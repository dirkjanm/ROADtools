import warnings
import json
import os
import asyncio
import time
import argparse
import sys
import traceback
import requests
import aiohttp
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker
from roadtools.roadlib.metadef.database import User, ServicePrincipal, Application, Group, Device, DirectoryRole, RoleAssignment,  ExtensionProperty, Contact, OAuth2PermissionGrant, Policy, RoleDefinition, AppRoleAssignment, TenantDetail
#from roadlib.metadef.database import Domain
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.metadef.database import ApplicationRef
import roadtools.roadlib.metadef.database as database
warnings.simplefilter('ignore')
token = None
expiretime = None
headers = {}
dburl = ''
urlcounter = 0

def mknext(url, prevurl):
    if url.startswith('https://'):
        # Absolute URL
        return url + '&api-version=1.61-internal'
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url + '&api-version=1.61-internal'
    return '/'.join(parts[:-1]) + '/' + url + '&api-version=1.61-internal'

async def dumphelper(url, method=requests.get):
    global urlcounter
    nexturl = url
    while nexturl:
        checktoken()
        try:
            urlcounter += 1
            async with method(nexturl, headers=headers) as req:
                if req.status != 200:
                    print('Error %d for URL %s' % (req.status, nexturl))
                    print(await req.text())
                try:
                    objects = await req.json()
                except json.decoder.JSONDecodeError:
                    # In case we break Azure
                    print(url)
                    print(req.content)
                    return
                try:
                    nexturl = mknext(objects['odata.nextLink'], url)
                except KeyError:
                    nexturl = None
                try:
                    for robject in objects['value']:
                        yield robject
                except KeyError:
                    # print(objects)
                    pass
        except Exception as exc:
            print(exc)
            return

def checktoken():
    global token, expiretime
    if time.time() > expiretime - 300:
        auth = Authentication()
        auth.client_id = token['_clientId']
        auth.tenant = token['tenantId']
        auth.tokendata = token
        if 'refreshToken' in token:
            token = auth.authenticate_with_refresh(token)
            headers['Authorization'] = '%s %s' % (token['tokenType'], token['accessToken'])
            expiretime = time.time() + token['expiresIn']
            print('Refreshed token')
            return True
        elif time.time() > expiretime:
            print('Access token is expired, but no access to refresh token! Dumping will fail')
            return False
    return True

async def dumpsingle(url, method):
    checktoken()
    try:
        async with method(url, headers=headers) as res:
            if res.status != 200:
                # This can happen
                if res.status == 404 and 'applicationRefs' in url:
                    return
                print('Error %d for URL %s' % (res.status, url))
                return
            objects = await res.json()
            return objects
    except Exception as exc:
        print(exc)
        return

def commit(engine, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['objectId']
        )
    elif 'sqlite' in dburl and ignore:
        statement = dbtype.__table__.insert(prefixes=['OR IGNORE'])
    else:
        statement = dbtype.__table__.insert()
    engine.execute(
        statement,
        cache
    )

class DataDumper(object):
    def __init__(self, tenantid, api_version, ahsession=None, engine=None, session=None):
        self.api_version = api_version
        self.tenantid = tenantid
        self.session = session
        self.engine = engine
        self.ahsession = ahsession

    async def dump_object(self, objecttype, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://graph.windows.net/%s/%s?api-version=1.61-internal' % (self.tenantid, objecttype)
        cache = []
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            if len(cache) > 1000:
                commit(self.engine, dbtype, cache)
                cache = []
        if len(cache) > 0:
            commit(self.engine, dbtype, cache)

    async def dump_l_to_db(self, url, method, mapping, linkname, childtbl, parent):
        i = 0
        async for obj in dumphelper(url, method=method):
            objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    childtbl, linkname = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s' % objclass)
                    continue
            child = self.session.query(childtbl).get(objectid)
            if not child:
                print('Non-existing child found: %s' % objectid)
                continue
            getattr(parent, linkname).append(child)
            i += 1
            if i > 1000:
               self.session.commit()
               i = 0

    async def dump_links(self, objecttype, linktype, parenttbl, mapping=None, linkname=None, childtbl=None, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl).all()
        jobs = []
        i = 0
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s/$links/%s?api-version=%s' % (self.tenantid, objecttype, parent.objectId, linktype, self.api_version)
            jobs.append(self.dump_l_to_db(url, method, mapping, linkname, childtbl, parent))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                i = 0
        await asyncio.gather(*jobs)
        self.session.commit()


    async def dump_mfa_to_db(self, url, method, parent):
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        parent.strongAuthenticationDetail = obj['strongAuthenticationDetail']

    async def dump_mfa(self, objecttype, parenttbl, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl).all()
        jobs = []
        i = 0
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s&$select=strongAuthenticationDetail,objectId' % (self.tenantid, objecttype, parent.objectId, self.api_version)
            jobs.append(self.dump_mfa_to_db(url, method, parent))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                self.session.commit()
                i = 0
        await asyncio.gather(*jobs)
        self.session.commit()

    async def dump_lo_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for multiple linked objects (returned as a list)
        """
        async for obj in dumphelper(url, method=method):
            # objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            # print(parent.objectId, obj)
            cache.append(obj)
            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                del cache[:]

    async def dump_so_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False):
        """
        Async db dumphelper for objects that are returned as single objects (direct values)
        """
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        cache.append(obj)
        if len(cache) > 1000:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            del cache[:]

    async def dump_linked_objects(self, objecttype, linktype, parenttbl, linkobjecttype, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s/%s?api-version=%s' % (self.tenantid, objecttype, parent.objectId, linktype, self.api_version)
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
        self.session.commit()


    async def dump_object_expansion(self, objecttype, dbtype, expandprop, linkname, childtbl, mapping=None, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://graph.windows.net/%s/%s?api-version=%s&$expand=%s' % (self.tenantid, objecttype, self.api_version, expandprop)
        i = 0
        async for obj in dumphelper(url, method=method):
            if len(obj[expandprop]) > 0:
                parent = self.session.query(dbtype).get(obj['objectId'])
                if not parent:
                    print('Non-existing parent found: %s' % obj['objectId'])
                    continue
                for epdata in obj[expandprop]:
                    objclass = epdata['odata.type']
                    if mapping is not None:
                        try:
                            childtbl, linkname = mapping[objclass]
                        except KeyError:
                            print('Unsupported member type: %s' % objclass)
                            continue
                    child = self.session.query(childtbl).get(epdata['objectId'])
                    if not child:
                        print('Non-existing child found: %s' % epdata['objectId'])
                        continue
                    getattr(parent, linkname).append(child)
                    i += 1
                    if i > 1000:
                        self.session.commit()
                        i = 0
        self.session.commit()

    async def dump_each(self, parenttbl, endpoint, dbtype, ignore_duplicates=False):
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s' % (self.tenantid, endpoint, parent.appId, self.api_version)
            jobs.append(self.dump_so_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache)
        self.session.commit()

    async def dump_custom_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/roleAssignments?api-version=%s&$filter=roleDefinitionId eq \'%s\'' % (self.tenantid, self.api_version, parent.objectId)
            async for obj in dumphelper(url, method=self.ahsession.get):
                cache.append(obj)
                if len(cache) > 1000:
                    commit(self.session, dbtype, cache)
                    cache = []
        if len(cache) > 0:
            commit(self.session, dbtype, cache)
        self.session.commit()

async def run(args, dburl):
    global token, expiretime, headers
    if 'tenantId' in token:
        tenantid = token['tenantId']
    elif args.tenant:
        tenantid = args.tenant
    else:
        tenantid = 'myorganization'
    expiretime = time.mktime(time.strptime(token['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
    headers = {
        'Authorization': '%s %s' % (token['tokenType'], token['accessToken'])
    }
    if not checktoken():
        return
    # Recreate DB
    engine = database.init(True, dburl=dburl)
    dumper = DataDumper(tenantid, '1.61-internal', engine=engine)
    async with aiohttp.ClientSession() as ahsession:
        print('Starting data gathering phase 1 of 2 (collecting objects)')
        dumper.ahsession = ahsession
        tasks = []
        tasks.append(dumper.dump_object('users', User))
        tasks.append(dumper.dump_object('tenantDetails', TenantDetail))
        tasks.append(dumper.dump_object('policies', Policy))
        tasks.append(dumper.dump_object('servicePrincipals', ServicePrincipal))
        tasks.append(dumper.dump_object('groups', Group))

        tasks.append(dumper.dump_object('applications', Application))
        tasks.append(dumper.dump_object('devices', Device))
        # tasks.append(dumper.dump_object('domains', Domain))
        tasks.append(dumper.dump_object('directoryRoles', DirectoryRole))
        tasks.append(dumper.dump_object('roleDefinitions', RoleDefinition))
        # tasks.append(dumper.dump_object('roleAssignments', RoleAssignment))
        tasks.append(dumper.dump_object('contacts', Contact))
        # tasks.append(dumper.dump_object('getAvailableExtensionProperties', ExtensionProperty, method=ahsession.post))
        tasks.append(dumper.dump_object('oauth2PermissionGrants', OAuth2PermissionGrant))
        await asyncio.gather(*tasks)

    Session = sessionmaker(bind=engine)
    dbsession = Session()
    # Mapping object, mapping type returned to Table and link name
    group_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
        'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
        'Microsoft.DirectoryServices.Contact': (Contact, 'memberContacts'),
        'Microsoft.DirectoryServices.Device': (Device, 'memberDevices'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
    }
    owner_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'ownerUsers'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'ownerServicePrincipals'),
    }
    tasks = []
    dumper.session = dbsession
    async with aiohttp.ClientSession() as ahsession:
        print('Starting data gathering phase 2 of 2 (collecting properties and relationships)')
        dumper.ahsession = ahsession
        tasks.append(dumper.dump_links('groups', 'members', Group, mapping=group_mapping))
        role_mapping = {
            'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
            'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
        }
        tasks.append(dumper.dump_links('directoryRoles', 'members', DirectoryRole, mapping=role_mapping))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignedTo', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignments', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion('servicePrincipals', ServicePrincipal, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_object_expansion('devices', Device, 'registeredOwners', 'owner', User))
        tasks.append(dumper.dump_object_expansion('applications', Application, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_custom_role_members(RoleAssignment))
        if args.mfa:
            tasks.append(dumper.dump_mfa('users', User, method=ahsession.get))
        tasks.append(dumper.dump_each(ServicePrincipal, 'applicationRefs', ApplicationRef))

        await asyncio.gather(*tasks)
    dbsession.close()

def getargs(gather_parser):
    gather_parser.add_argument('-d',
                               '--database',
                               action='store',
                               help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools. Default: roadrecon.db',
                               default='roadrecon.db')
    gather_parser.add_argument('-f',
                               '--tokenfile',
                               action='store',
                               help='File to read credentials from obtained by roadrecon auth',
                               default='.roadtools_auth')
    gather_parser.add_argument('--tokens-stdin',
                               action='store_true',
                               help='Read tokens from stdin instead of from disk')
    gather_parser.add_argument('--mfa',
                               action='store_true',
                               help='Dump MFA details (requires use of a privileged account)')
    gather_parser.add_argument('-t',
                               '--tenant',
                               action='store',
                               help='Tenant ID to gather, if this info is not stored in the token')

def main(args=None):
    global token, headers, dburl, urlcounter
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon - Gather Azure AD information', formatter_class=argparse.RawDescriptionHelpFormatter)
        getargs(parser)
        args = parser.parse_args()
        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)
    if args.tokens_stdin:
        token = json.loads(sys.stdin.read())
    else:
        with open(args.tokenfile, 'r') as infile:
            token = json.load(infile)
    if not ':/' in args.database:
        if args.database[0] != '/':
            dburl = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            dburl = 'sqlite:///' + args.database
    else:
        dburl = args.database

    headers['Authorization'] = '%s %s' % (token['tokenType'], token['accessToken'])

    seconds = time.perf_counter()
    try:
        asyncio.run(run(args, dburl))
    except AttributeError:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run(args, dburl))
    elapsed = time.perf_counter() - seconds
    print("ROADrecon gather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))


if __name__ == "__main__":
    main()
