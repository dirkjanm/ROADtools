import argparse
import asyncio
import json
import os
import sys
import time
import traceback
import warnings

import aiohttp
import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import Base, PIMprivilegedAccess, PIMgovernanceResource, \
PIMgovernanceAlert, PIMgovernanceRoleSetting, PIMgovernanceRoleAssignment, PIMgovernanceRoleDefinition, \
PIMgovernanceRoleAssignmentRequest, PIMgovernanceRoleSettingV2, lnk_pim_resource, \
lnk_pim_resource_rolealerts, \
User, Group, ServicePrincipal, lnk_pim_roleassignment_subjectuser, lnk_pim_roleassignment_subjectgroup, \
lnk_pim_roleassignment_subjectserviceprincipal, lnk_pim_resource_aadgroup
from roadtools.roadlib.auth import Authentication
from sqlalchemy import bindparam, func, text
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker
from datetime import datetime

warnings.simplefilter('ignore')
token = None
expiretime = None
headers = {}
dburl = ''
urlcounter = 0
groupcounter = 0
totalgroups = 0
devicecounter = 0
totaldevices = 0

tokencounter = 0
tokenfilltime = time.time()

MAX_GROUPS = 3000
MAX_REQ_PER_SEC = 600.0
GATHER_RESOURCE = 'https://api.azrbac.mspim.azure.com'

def mknext(url, prevurl):
    if url.startswith('https://'):
        # Absolute URL
        return url + ''
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url + ''
    return '/'.join(parts[:-1]) + '/' + url + ''

async def dumphelper(url, method):
    global urlcounter, tokencounter
    nexturl = url
    while nexturl:
        checktoken()
        await ratelimit()
        # print(nexturl)
        try:
            urlcounter += 1
            async with method(nexturl, headers=headers) as req:
                # Hold off when rate limit is reached
                if req.status == 429:
                    if tokencounter > 0:
                        tokencounter -= 10*MAX_REQ_PER_SEC
                        print('Sleeping because of rate-limit hit')
                    continue
                if req.status != 200:
                    # Ignore default users role not being found
                    if req.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                        return
                    print('Error %d for URL %s' % (req.status, nexturl))
                    # print(await req.text())
                    # print(req.headers)
                    print('')

                try:
                    objects = await req.json()
                except json.decoder.JSONDecodeError:
                    # In case we break Azure
                    print(url)
                    print(req.content)
                    print('')
                    return
                try:
                    nexturl = mknext(objects['@odata.nextLink'], url)
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

async def ratelimit():
    global tokencounter, tokenfilltime
    if tokencounter < MAX_REQ_PER_SEC:
        now = time.time()
        to_add = MAX_REQ_PER_SEC * (now - tokenfilltime)
        tokencounter = min(MAX_REQ_PER_SEC, tokencounter + to_add)
        tokenfilltime = now
    if tokencounter < 1:
        # print('Ratelimit reached')
        await asyncio.sleep(0.1)
        while True:
            now = time.time()
            to_add = MAX_REQ_PER_SEC * (now - tokenfilltime)
            tokencounter = min(MAX_REQ_PER_SEC, tokencounter + to_add)
            tokenfilltime = now
            if tokencounter > 1:
                break
            await asyncio.sleep(0.1)
        tokencounter -= 1
    else:
        tokencounter -= 1


def checktoken():
    global token, expiretime
    if time.time() > expiretime - 300:
        auth = Authentication()
        try:
            auth.client_id = token['_clientId']
        except KeyError:
            auth.client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        auth.tenant = token['tenantId']
        auth.tokendata = token
        auth.resource_uri = GATHER_RESOURCE
        if 'useragent' in token:
            auth.set_user_agent(token['useragent'])
        if 'refreshToken' in token:
            print("Access token expired - fetching new token using refresh token")
            token = auth.handle_autotoken(token, resource=GATHER_RESOURCE)
            headers['Authorization'] = '%s %s' % (token['tokenType'], token['accessToken'])
            expiretime = time.time() + token['expiresIn']
            return True
        elif time.time() > expiretime:
            print('Access token is expired, but no access to refresh token! Dumping will fail')
            return False
    return True

async def dumpsingle(url, method):
    global urlcounter, tokencounter
    checktoken()
    await ratelimit()
    try:
        urlcounter += 1
        async with method(url, headers=headers) as res:
            if res.status == 429:
                if tokencounter > 0:
                    tokencounter -= 10*MAX_REQ_PER_SEC
                    print('Sleeping because of rate-limit hit')
                obj = await dumpsingle(url, method)
                return obj
            if res.status != 200:
                # This can happen
                if res.status == 404 and 'applicationRefs' in url:
                    return
                # Ignore default users role not being found
                if res.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                    return
                print('Error %d for URL %s' % (res.status, url))
                return
            objects = await res.json()
            return objects
    except Exception as exc:
        print(exc)
        return

def commit(session, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['id']
        )
    elif 'sqlite' in dburl and ignore:
        statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
    else:
        statement = dbtype.__table__.insert()
    session.execute(
        statement,
        cache
    )

def commitlink(session, cachedict, ignore=False):
    global dburl
    for linktable, cache in cachedict.items():
        if 'postgresql' in dburl and ignore:
            insertst = pginsert(linktable)
            statement = insertst.on_conflict_do_nothing(
                index_elements=['id']
            )
        elif 'sqlite' in dburl and ignore:
            statement = linktable.insert().prefix_with('OR IGNORE')
        else:
            statement = linktable.insert()
        # print(cache)
        session.execute(
            statement,
            cache
        )

class DataDumper(object):
    def __init__(self, api_version, ahsession=None, engine=None, session=None):
        self.api_version = api_version
        self.session = session
        self.engine = engine
        self.ahsession = ahsession

    async def dump_lo_to_db(self, url, method, linkobjecttype, cache, ignore_duplicates=False, parent=None):
        """
        Async db dumphelper for multiple linked objects (returned as a list)
        """
        async for obj in dumphelper(url, method=method):
            # objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            # print(parent.objectId, obj)
            if parent:
                obj['parent'] = parent
            cache.append(obj)
            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                del cache[:]

    async def dump_linkednewobject_to_db(self, url, method, linkobjecttype, mapping, cache, linkcache, parentid, ignore_duplicates=False):
        """
        Async db dumphelper for multiple linked objects (returned as a list)
        """
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            try:
                linktable, leftcol, rightcol = mapping[linkobjecttype]
            except KeyError:
                print('Unsupported member type: %s ' % (str(linkobjecttype)))
                continue
            try:
                linkcache[linktable].append({leftcol: parentid, rightcol: obj['id']})
            except KeyError:
                linkcache[linktable] = [{leftcol: parentid, rightcol: obj['id']}]

            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                commitlink(self.session, linkcache)
                del cache[:]
                linkcache.clear()

    async def dump_linked_objects(self, objecttype, linktype, parenttbl, linkobjecttype, method=None, ignore_duplicates=False, parents=None):
        if method is None:
            method = self.ahsession.get
        if not parents:
            parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = f'https://api.azrbac.mspim.azure.com/api/{self.api_version}/{objecttype}/{parent.id}/{linktype}'
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_linked_newobjects(self, objecttype, linktype, parenttbl, linkobjecttype, mapping, method=None, ignore_duplicates=False, parents=None):
        if method is None:
            method = self.ahsession.get

        if not parents:
            parents = self.session.query(parenttbl).all()
        cache = []
        linkcache = {}
        jobs = []
        for parent in parents:
            url = f'https://api.azrbac.mspim.azure.com/api/{self.api_version}/{objecttype}/{parent.id}/{linktype}'
            jobs.append(self.dump_linkednewobject_to_db(url, method, linkobjecttype, mapping, cache, linkcache, parent.id, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            commitlink(self.session, linkcache)
        self.session.commit()

    async def dump_rolesettingsv2(self, privaccess, parents, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        linkobjecttype = PIMgovernanceRoleSettingV2
        cache = []
        jobs = []
        for parent in parents:
            url = f"https://api.azrbac.mspim.azure.com/api/{self.api_version}/privilegedAccess/{privaccess}/roleSettingsV2?$filter=(resource/id eq '{parent.id}')"
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_roleassignment_expansion(self, objecttype, dbtype, mapping, method=None):
        if method is None:
            method = self.ahsession.get
        url = f'https://api.azrbac.mspim.azure.com/api/{self.api_version}/{objecttype}?$expand=subject&$select=subject,id'
        i = 0
        async for obj in dumphelper(url, method=method):
            if obj['subject']:
                parent = self.session.get(dbtype, obj['id'])
                if not parent:
                    print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, 'subject', obj['id']))
                    continue
                epdata = obj['subject']
                objclass = epdata['type']
                try:
                    childtbl, linkname = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s' % objclass)
                    continue
                child = self.session.get(childtbl, epdata['id'])
                if not child:
                    print('Non-existing child during expansion %s %s: %s' % (dbtype.__table__, 'subject', epdata['id']))
                    continue
                getattr(parent, linkname).append(child)
                i += 1
                if i > 1000:
                    self.session.commit()
                    i = 0
        self.session.commit()


def split_list(input_list, chunk_size):
    return [input_list[i:i + chunk_size] for i in range(0, len(input_list), chunk_size)]

async def run(args):
    global token, expiretime, headers, totalgroups, totaldevices, dburl
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
    if args.user_agent:
        # Alias support, get temp auth object
        auth = Authentication()
        auth.set_user_agent(args.user_agent)
        headers['User-Agent'] = auth.user_agent
        # Store this in the token as well
        token['useragent'] = auth.user_agent

    if not checktoken():
        return
    # Recreate DB

    destroy_db = False

    engine = database.init(destroy_db, dburl=dburl)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    dbsession = Session()

    # Clear previous data

    dbsession.query(PIMprivilegedAccess).delete()
    dbsession.query(PIMgovernanceResource).delete()
    dbsession.query(PIMgovernanceRoleDefinition).delete()
    dbsession.query(PIMgovernanceRoleAssignment).delete()
    dbsession.query(PIMgovernanceRoleAssignmentRequest).delete()
    dbsession.query(PIMgovernanceRoleSetting).delete()
    dbsession.query(PIMgovernanceRoleSettingV2).delete()
    dbsession.query(PIMgovernanceAlert).delete()

    dumper = DataDumper('v2', engine=engine)
    # Manually add the supported PIM types
    dbsession.add(PIMprivilegedAccess(id='aadroles'))
    dbsession.add(PIMprivilegedAccess(id='aadgroups'))
    dbsession.add(PIMprivilegedAccess(id='azureResources'))
    dbsession.commit()
    async with aiohttp.ClientSession() as ahsession:
        print('Starting data gathering')
        dumper.ahsession = ahsession
        dumper.session = dbsession

        tasks = []
        # Mapping object, mapping type returned to Table and link name
        resource_link_mapping = {
            PIMgovernanceResource: (lnk_pim_resource, 'PIMprivilegedAccess', 'PIMgovernanceResource'),
            PIMgovernanceAlert: (lnk_pim_resource_rolealerts, 'PIMgovernanceResource', 'PIMgovernanceAlert')
        }
        subject_mapping = {
            'User': (User, 'subjectUser'),
            'ServicePrincipal': (ServicePrincipal, 'subjectServicePrincipal'),
            'Group': (Group, 'subjectGroup'),
        }

        # Fetch managed resources
        # for roles the only resource is the tenant
        # for groups these are the onboarded groups
        await dumper.dump_linked_newobjects('privilegedAccess', 'resources', PIMprivilegedAccess, PIMgovernanceResource, resource_link_mapping, ignore_duplicates=True)
        dbsession.commit()
        for privaccess in dbsession.query(PIMprivilegedAccess).all():
            children = privaccess.resources
            if len(children) == 0:
                continue
            if privaccess.id != 'azureResources':
                tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleDefinitions', PIMgovernanceResource, PIMgovernanceRoleDefinition, ignore_duplicates=True, parents=children))
                tasks.append(dumper.dump_rolesettingsv2(privaccess.id, children))
                tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleSettings', PIMgovernanceResource, PIMgovernanceRoleSetting, ignore_duplicates=False, parents=children))
            else:
                if args.skip_azure:
                    continue
                # These have a lot of duplicates so dump it only once
                tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleDefinitions', PIMgovernanceResource, PIMgovernanceRoleDefinition, ignore_duplicates=True, parents=[children[0]]))
                tasks.append(dumper.dump_rolesettingsv2(privaccess.id, [children[0]]))
                tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleSettings', PIMgovernanceResource, PIMgovernanceRoleSetting, ignore_duplicates=False, parents=[children[0]]))
            tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleAssignments', PIMgovernanceResource, PIMgovernanceRoleAssignment, ignore_duplicates=True, parents=children))
            tasks.append(dumper.dump_linked_objects(f'privilegedAccess/{privaccess.id}/resources', 'roleAssignmentRequests', PIMgovernanceResource, PIMgovernanceRoleAssignmentRequest, ignore_duplicates=False, parents=children))
            # This errors out for other resource types
            if privaccess.id == 'aadroles':
                tasks.append(dumper.dump_linked_newobjects(f'privilegedAccess/{privaccess.id}/resources', 'alerts', PIMgovernanceResource, PIMgovernanceAlert, resource_link_mapping, ignore_duplicates=False, parents=children))

        await asyncio.gather(*tasks)
        tasks = []

        for privaccess in dbsession.query(PIMprivilegedAccess).all():
            if privaccess.id == 'azureResources' and args.skip_azure:
                continue
            children = privaccess.resources
            for child in privaccess.resources:
                tasks.append(dumper.dump_roleassignment_expansion(f'privilegedAccess/{privaccess.id}/resources/{child.id}/roleAssignments', PIMgovernanceRoleAssignment, subject_mapping))

        await asyncio.gather(*tasks)


    dbsession.commit()

    privaccess = dbsession.get(PIMprivilegedAccess, 'aadgroups')
    linkcache = {}
    linktable = lnk_pim_resource_aadgroup
    leftcol = 'PIMgovernanceResource'
    rightcol = 'Group'
    for resource in privaccess.resources:
        try:
            linkcache[linktable].append({leftcol: resource.id, rightcol: resource.externalId})
        except KeyError:
            linkcache[linktable] = [{leftcol: resource.id, rightcol: resource.externalId}]

    commitlink(dbsession, linkcache)
    dbsession.commit()
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
    gather_parser.add_argument('--skip-azure',
                               action='store_true',
                               help='Skip Azure PIM collection since it is slooooow')
    gather_parser.add_argument('-t',
                               '--tenant',
                               action='store',
                               help='Tenant ID to gather, if this info is not stored in the token')
    gather_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. By default aiohttp default user agent is used, and python-requests is used for token renewal')
    gather_parser.add_argument('--autotoken',
                               action='store_true',
                               help='Use refresh token to request access token for the required API automatically')

def main(args=None):
    global token, headers, dburl, urlcounter
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon - Gather PIM information', formatter_class=argparse.RawDescriptionHelpFormatter)
        getargs(parser)
        args = parser.parse_args()
        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)
    if args.tokens_stdin:
        token = json.loads(sys.stdin.read())
    else:
        try:
            with open(args.tokenfile, 'r') as infile:
                token = json.load(infile)
        except FileNotFoundError:
            print('Token file %s not found. Please run "roadrecon auth" first' % args.tokenfile)
            sys.exit(1)
    if not ':/' in args.database:
        if args.database[0] != '/':
            dburl = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            dburl = 'sqlite:///' + args.database
    else:
        dburl = args.database
    try:
        _, tokendata = Authentication.parse_accesstoken(token['accessToken'])
    except KeyError:
        print('No access token found in tokenfile')
        return
    if tokendata['aud'] not in ('https://api.azrbac.mspim.azure.com/', 'https://api.azrbac.mspim.azure.com', 'https://management.azure.com/', '00000002-0000-0000-c000-000000000000'):
        if args.autotoken:
            auth = Authentication()
            token = auth.handle_autotoken(token, args=args, resource=GATHER_RESOURCE)
        else:
            print(f"Wrong token audience, got {tokendata['aud']} but expected https://api.azrbac.mspim.azure.com")
            print("Make sure to request a token with -r https://api.azrbac.mspim.azure.com")
            return

    headers['Authorization'] = f"Bearer {token['accessToken']}"

    seconds = time.perf_counter()
    asyncio.run(run(args))
    elapsed = time.perf_counter() - seconds
    print("ROADrecon pimgather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))

if __name__ == "__main__":
    main()
