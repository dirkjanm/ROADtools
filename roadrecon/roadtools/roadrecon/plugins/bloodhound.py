'''
Export ROADrecon data into BloodHound's neo4j database
Uses code from aclpwn under an MIT license

Copyright (c) 2020 Dirk-jan Mollema

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
import platform
import os
import json
import argparse
import sys
from roadtools.roadlib.metadef.database import ServicePrincipal, User, Group, DirectoryRole
import roadtools.roadlib.metadef.database as database
try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ClientError
    HAS_NEO_MODULE = True
except ModuleNotFoundError:
    try:
        from neo4j.v1 import GraphDatabase
        from neo4j.exceptions import ClientError
        HAS_NEO_MODULE = True
    except ModuleNotFoundError:
        HAS_NEO_MODULE = False

DESCRIPTION = '''
Export ROADrecon data into BloodHound's neo4j database.
Requires a custom version of the BloodHound interface to use, available at
https://github.com/dirkjanm/BloodHound-AzureAD
'''

BASE_LINK_QUERY = 'UNWIND $props AS prop MERGE (n:{0} {{objectid: prop.source}}) MERGE (m:{1} {{objectid: prop.target}}) MERGE (n)-[r:{2}]->(m)';

def add_edge(tx, aid, atype, bid, btype, linktype):
    q = BASE_LINK_QUERY.format(atype, btype, linktype)
    props = {'source':aid, 'target':bid}
    tx.run(q, props=props)

class BloodHoundPlugin():
    """
    Export data to BloodHounds neo4j database plugin
    """
    def __init__(self, session, dbhost, dbuser, dbpass):
        # SQLAlchemy session
        self.session = session
        # Neo4j driver
        self.driver = self.init_driver(dbhost, dbuser, dbpass)

    @staticmethod
    def init_driver(database, user, password):
        """
        Initialize neo4j driver
        """
        uri = "bolt://%s:7687" % database
        driver = GraphDatabase.driver(uri, auth=(user, password), encrypted=False)
        return driver

    @staticmethod
    def detect_db_config():
        """
        Detect bloodhound config, which is stored in appData.
        OS dependent according to https://electronjs.org/docs/api/app#appgetpathname
        """
        system = platform.system()
        if system == 'Windows':
            try:
                directory = os.environ['APPDATA']
            except KeyError:
                return (None, None)
            config = os.path.join(directory, 'BloodHound', 'config.json')
            try:
                with open(config, 'r') as configfile:
                    configdata = json.load(configfile)
            except IOError:
                return (None, None)

        if system == 'Linux':
            try:
                directory = os.environ['XDG_CONFIG_HOME']
            except KeyError:
                try:
                    directory = os.path.join(os.environ['HOME'], '.config')
                except KeyError:
                    return (None, None)
            config = os.path.join(directory, 'bloodhound', 'config.json')
            try:
                with open(config, 'r') as configfile:
                    configdata = json.load(configfile)
            except IOError:
                return (None, None)

        if system == 'Darwin':
            try:
                directory = os.path.join(os.environ['HOME'], 'Library', 'Application Support')
            except KeyError:
                return (None, None)
            config = os.path.join(directory, 'bloodhound', 'config.json')
            try:
                with open(config, 'r') as configfile:
                    configdata = json.load(configfile)
            except IOError:
                return (None, None)

        # If we are still here, we apparently found the config :)
        try:
            username = configdata['databaseInfo']['user']
        except KeyError:
            username = 'neo4j'
        try:
            password = configdata['databaseInfo']['password']
        except KeyError:
            password = None
        return username, password

    def main(self):
        """
        Main plugin logic. Simply connects to both databases and transforms the data
        """
        print('Connecting to neo4j')
        with self.driver.session() as neosession:
            print('Running queries')

            try:
                neosession.run('CREATE CONSTRAINT ON (c:AzureUser) ASSERT c.objectid IS UNIQUE')
                neosession.run('CREATE CONSTRAINT ON (c:AzureGroup) ASSERT c.objectid IS UNIQUE')
                neosession.run('CREATE CONSTRAINT ON (c:AzureRole) ASSERT c.objectid IS UNIQUE')
                neosession.run('CREATE CONSTRAINT ON (c:ServicePrincipal) ASSERT c.objectid IS UNIQUE')
            except ClientError as e:
                pass  # on neo4j 4, an error is raised when the constraint exists already

            for user in self.session.query(User):
                property_query = 'UNWIND $props AS prop MERGE (n:AzureUser {objectid: prop.sourceid}) SET n += prop.map'
                uprops = {
                    'name': user.userPrincipalName,
                    'displayname': user.displayName,
                    'enabled': user.accountEnabled,
                    'distinguishedname': user.onPremisesDistinguishedName,
                    'email': user.mail,
                }
                props = {'map': uprops, 'sourceid': user.objectId}
                if user.onPremisesSecurityIdentifier:
                    # uprops['onPremisesSecurityIdentifier'] = user.onPremisesSecurityIdentifier
                    props['onpremid'] = user.onPremisesSecurityIdentifier
                    property_query = 'UNWIND $props AS prop MERGE (n:AzureUser {objectid: prop.sourceid}) MERGE (m:User {objectid:prop.onpremid}) MERGE (m)-[r:SyncsTo {isacl:false}]->(n) SET n += prop.map'

                res = neosession.run(property_query, props=props)

            for sprinc in self.session.query(ServicePrincipal):
                property_query = 'UNWIND $props AS prop MERGE (n:ServicePrincipal {objectid: prop.sourceid}) SET n += prop.map'
                uprops = {
                    'name': sprinc.displayName,
                    'appid': sprinc.appId,
                    'publisher': sprinc.publisherName,
                    'displayname': sprinc.displayName,
                    'enabled': sprinc.accountEnabled,
                }
                props = {'map': uprops, 'sourceid': sprinc.objectId}
                res = neosession.run(property_query, props=props)
                for owneruser in sprinc.ownerUsers:
                    add_edge(neosession, owneruser.objectId, 'AzureUser', sprinc.objectId, 'ServicePrincipal', 'Owns')
                for ownersp in sprinc.ownerServicePrincipals:
                    add_edge(neosession, ownersp.objectId, 'ServicePrincipal', sprinc.objectId, 'ServicePrincipal', 'Owns')


            for group in self.session.query(Group):
                property_query = 'UNWIND $props AS prop MERGE (n:AzureGroup {objectid: prop.sourceid}) SET n += prop.map'
                uprops = {
                    'name': group.displayName,
                    'displayname': group.displayName,
                    'email': group.mail,
                }
                props = {'map': uprops, 'sourceid': group.objectId}
                if group.onPremisesSecurityIdentifier:
                    # uprops['onPremisesSecurityIdentifier'] = group.onPremisesSecurityIdentifier
                    props['onpremid'] = group.onPremisesSecurityIdentifier
                    property_query = 'UNWIND $props AS prop MERGE (n:AzureGroup {objectid: prop.sourceid}) MERGE (m:Group {objectid:prop.onpremid}) MERGE (m)-[r:SyncsTo {isacl:false}]->(n) SET n += prop.map'

                res = neosession.run(property_query, props=props)
                for memberuser in group.memberUsers:
                    add_edge(neosession, memberuser.objectId, 'AzureUser', group.objectId, 'AzureGroup', 'MemberOf')
                for membergroup in group.memberGroups:
                    add_edge(neosession, membergroup.objectId, 'AzureGroup', group.objectId, 'AzureGroup', 'MemberOf')
                for membersp in group.memberServicePrincipals:
                    add_edge(neosession, membersp.objectId, 'AzureGroup', group.objectId, 'ServicePrincipal', 'MemberOf')


            for role in self.session.query(DirectoryRole):
                property_query = 'UNWIND $props AS prop MERGE (n:AzureRole {objectid: prop.sourceid}) SET n += prop.map'
                uprops = {
                    'name': role.displayName,
                    'displayname': role.displayName,
                    'description': role.description,
                    'templateid': role.roleTemplateId
                }
                props = {'map': uprops, 'sourceid': role.objectId}
                res = neosession.run(property_query, props=props)
                for memberuser in role.memberUsers:
                    add_edge(neosession, memberuser.objectId, 'AzureUser', role.objectId, 'AzureRole', 'MemberOf')

                for memberuser in role.memberServicePrincipals:
                    add_edge(neosession, memberuser.objectId, 'ServicePrincipal', role.objectId, 'AzureRole', 'MemberOf')

        print('Done!')
        self.driver.close()

def add_args(parser):
    #DB parameters
    databasegroup = parser.add_argument_group("Database options (if unspecified they will be taken from your BloodHound config)")
    databasegroup.add_argument("--neodatabase", type=str, metavar="DATABASE HOST", default="localhost", help="The host neo4j is running on. Default: localhost")
    databasegroup.add_argument("-du", "--database-user", type=str, metavar="USERNAME", default="neo4j", help="Neo4j username to use")
    databasegroup.add_argument("-dp", "--database-password", type=str, metavar="PASSWORD", help="Neo4j password to use")


def main(args=None):
    if not HAS_NEO_MODULE:
        print('neo4j python module not found! Please install the module neo4j-driver first (pip install neo4j-driver)')
        sys.exit(1)
        return
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon policies to HTML plugin', formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('-d',
                            '--database',
                            action='store',
                            help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
                            default='roadrecon.db')
        add_args(parser)
        args = parser.parse_args()
    db_url = database.parse_db_argument(args.database)
    if args.database_password is None:
        args.database_user, args.database_password = BloodHoundPlugin.detect_db_config()
        if args.database_password is None:
            print('Error: Could not autodetect the Neo4j database credentials from your BloodHound config. Please specify them manually')
            return
    session = database.get_session(database.init(dburl=db_url))
    plugin = BloodHoundPlugin(session, args.neodatabase, args.database_user, args.database_password)
    plugin.main()

if __name__ == '__main__':
    main()
