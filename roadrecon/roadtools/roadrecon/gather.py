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
from sqlalchemy import func, bindparam
from roadtools.roadlib.metadef.database import User, ServicePrincipal, Application, Group, Device, DirectoryRole, RoleAssignment, ExtensionProperty, Contact, OAuth2PermissionGrant, Policy, RoleDefinition, AppRoleAssignment, TenantDetail, AuthorizationPolicy, DirectorySetting
from roadtools.roadlib.metadef.database import lnk_group_member_user, lnk_group_member_group, lnk_group_member_contact, lnk_group_member_device, lnk_group_member_serviceprincipal, lnk_device_owner, lnk_group_owner_user, lnk_group_owner_serviceprincipal
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
groupcounter = 0
totalgroups = 0
devicecounter = 0
totaldevices = 0

tokencounter = 0
tokenfilltime = time.time()

MAX_GROUPS = 3000
MAX_REQ_PER_SEC = 600.0

def mknext(url, prevurl):
    if url.startswith('https://'):
        # Absolute URL
        return url + '&api-version=1.61-internal'
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url + '&api-version=1.61-internal'
    return '/'.join(parts[:-1]) + '/' + url + '&api-version=1.61-internal'

async def dumphelper(url, method=requests.get):
    global urlcounter, tokencounter
    nexturl = url
    while nexturl:
        checktoken()
        await ratelimit()
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
        await ratelimit()
    else:
        tokencounter -= 1


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

def commitlink(engine, cachedict, ignore=False):
    global dburl
    for linktable, cache in cachedict.items():
        if 'postgresql' in dburl and ignore:
            insertst = pginsert(linktable)
            statement = insertst.on_conflict_do_nothing(
                index_elements=['objectId']
            )
        elif 'sqlite' in dburl and ignore:
            statement = linktable.insert(prefixes=['OR IGNORE'])
        else:
            statement = linktable.insert()
        # print(cache)
        engine.execute(
            statement,
            cache
        )

def commitmfa(engine, dbtype, cache):
    statement = dbtype.__table__.update().where(dbtype.objectId == bindparam('userid'))
    engine.execute(
        statement,
        cache
    )

async def queue_processor(queue):
    while True:
        task = await queue.get()
        # task is already a coroutine, so we wait for it to finish
        await task
        queue.task_done()

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
                del cache[:]
        if len(cache) > 0:
            commit(self.engine, dbtype, cache)

    async def dump_l_to_db(self, url, method, mapping, linkname, childtbl, parent):
        global groupcounter, totalgroups, devicecounter, totaldevices
        i = 0
        async for obj in dumphelper(url, method=method):
            objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    childtbl, linkname = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s for parent %s' % (objclass, parent.__table__))
                    continue
            child = self.session.query(childtbl).get(objectid)
            if not child:
                try:
                    parentname = parent.displayName
                except AttributeError:
                    parentname = parent.objectId
                print('Non-existing child found on %s %s: %s' % (parent.__table__, parentname, objectid))
                continue
            getattr(parent, linkname).append(child)
            i += 1
            if i > 1000:
                self.session.commit()
                i = 0
        if str(parent.__table__) == 'Groups':
            groupcounter += 1
            print('Done processing {0}/{1} groups'.format(int(groupcounter/2), totalgroups), end='\r')

    async def dump_l_to_linktable(self, url, method, mapping, parentid, objecttype):
        global groupcounter, totalgroups, devicecounter, totaldevices
        i = 0
        cache = {}
        async for obj in dumphelper(url, method=method):
            objectid, objclass = obj['url'].split('/')[-2:]
            # If only one type exists, we don't need to use the mapping
            if mapping is not None:
                try:
                    linktable, leftcol, rightcol = mapping[objclass]
                except KeyError:
                    print('Unsupported member type: %s for parent %s' % (objclass, objecttype))
                    continue
            try:
                cache[linktable].append({leftcol: parentid, rightcol: objectid})
            except KeyError:
                cache[linktable] = [{leftcol: parentid, rightcol: objectid}]
            i += 1
            if i > 1000:
                commitlink(self.session, cache)
                cache = {}
                i = 0
        commitlink(self.session, cache)
        if str(objecttype) == 'groups':
            groupcounter += 1
            print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(groupcounter/2), totalgroups, devicecounter, totaldevices), end='\r')
        if str(objecttype) == 'devices':
            devicecounter += 1
            print('Done processing {0}/{1} groups {2}/{3} devices'.format(int(groupcounter/2), totalgroups, devicecounter, totaldevices), end='\r')

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

    async def dump_links_with_queue(self, queue, objecttype, linktype, parenttbl, mapping=None, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        for parentid, in parents:
            url = 'https://graph.windows.net/%s/%s/%s/$links/%s?api-version=%s' % (self.tenantid, objecttype, parentid, linktype, self.api_version)
            # Chunk it to avoid huge memory usage
            await queue.put(self.dump_l_to_linktable(url, method, mapping, parentid, objecttype))
        await queue.join()
        self.session.commit()

    async def dump_mfa_to_db(self, url, method, parentid, cache):
        obj = await dumpsingle(url, method=method)
        if not obj:
            return
        cache.append({'userid':parentid,'strongAuthenticationDetail':obj['strongAuthenticationDetail']})

    async def dump_mfa(self, objecttype, parenttbl, method=None):
        if method is None:
            method = self.ahsession.get
        parents = self.session.query(parenttbl.objectId).all()
        jobs = []
        cache = []
        i = 0
        for parentid, in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s&$select=strongAuthenticationDetail,objectId' % (self.tenantid, objecttype, parentid, self.api_version)
            jobs.append(self.dump_mfa_to_db(url, method, parentid, cache))
            i += 1
            # Chunk it to avoid huge memory usage
            if i > 1000:
                await asyncio.gather(*jobs)
                del jobs[:]
                commitmfa(self.session, parenttbl, cache)
                del cache[:]
                i = 0
        await asyncio.gather(*jobs)
        commitmfa(self.session, parenttbl, cache)
        del cache[:]

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
                    print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, expandprop, obj['objectId']))
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
                        print('Non-existing child during expansion %s %s: %s' % (dbtype.__table__, expandprop, epdata['objectId']))
                        continue
                    getattr(parent, linkname).append(child)
                    i += 1
                    if i > 1000:
                        self.session.commit()
                        i = 0
        self.session.commit()

    async def dump_keycredentials(self, objecttype, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        cache = []
        url = 'https://graph.windows.net/%s/%s?api-version=1.61-internal&$select=keyCredentials,objectId' % (self.tenantid, objecttype)
        async for obj in dumphelper(url, method=method):
            cache.append({'userid':obj['objectId'], 'keyCredentials':obj['keyCredentials']})
            if len(cache) > 1000:
                commitmfa(self.session, dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            commitmfa(self.session, dbtype, cache)
        del cache[:]

    async def dump_apps_from_list(self, parents, endpoint, dbtype, ignore_duplicates=True):
        cache = []
        jobs = []
        for parentid in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s' % (self.tenantid, endpoint, parentid, self.api_version)
            jobs.append(self.dump_so_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_each(self, parenttbl, endpoint, dbtype, ignore_duplicates=True):
        parents = self.session.query(parenttbl).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/%s/%s?api-version=%s' % (self.tenantid, endpoint, parent.appId, self.api_version)
            jobs.append(self.dump_so_to_db(url, self.ahsession.get, dbtype, cache, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=ignore_duplicates)
        self.session.commit()

    async def dump_custom_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/roleAssignments?api-version=%s&$filter=roleDefinitionId eq \'%s\'' % (self.tenantid, self.api_version, parent.objectId)
            jobs.append(self.dump_lo_to_db(url, self.ahsession.get, dbtype, cache))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache)
        self.session.commit()

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
    if not checktoken():
        return
    # Recreate DB

    if args.skip_first_phase:
        destroy_db = False
    else:
        destroy_db = True

    engine = database.init(destroy_db, dburl=dburl)
    dumper = DataDumper(tenantid, '1.61-internal', engine=engine)
    if not args.skip_first_phase:
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
            tasks.append(dumper.dump_object('authorizationPolicy', AuthorizationPolicy))
            tasks.append(dumper.dump_object('settings', DirectorySetting))
            await asyncio.gather(*tasks)

    Session = sessionmaker(bind=engine)
    dbsession = Session()

    if args.skip_first_phase:
        # Delete existing links to make sure we start with clean data
        for table in database.Base.metadata.tables.keys():
            if table.startswith('lnk_'):
                dbsession.execute("DELETE FROM {0}".format(table))
        dbsession.query(ApplicationRef).delete()
        dbsession.query(RoleAssignment).delete()
        dbsession.commit()

    # Mapping object, mapping type returned to Table and link name
    group_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
        'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
        'Microsoft.DirectoryServices.Contact': (Contact, 'memberContacts'),
        'Microsoft.DirectoryServices.Device': (Device, 'memberDevices'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
    }
    group_owner_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'ownerUsers'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'ownerServicePrincipals'),
    }
    owner_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'ownerUsers'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'ownerServicePrincipals'),
    }
    role_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
        'Microsoft.DirectoryServices.ServicePrincipal': (ServicePrincipal, 'memberServicePrincipals'),
        'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
    }
    # Direct link mapping
    group_link_mapping = {
        'Microsoft.DirectoryServices.User': (lnk_group_member_user, 'Group', 'User'),
        'Microsoft.DirectoryServices.Group': (lnk_group_member_group, 'Group', 'childGroup'),
        'Microsoft.DirectoryServices.Contact': (lnk_group_member_contact, 'Group', 'Contact'),
        'Microsoft.DirectoryServices.Device': (lnk_group_member_device, 'Group', 'Device'),
        'Microsoft.DirectoryServices.ServicePrincipal': (lnk_group_member_serviceprincipal, 'Group', 'ServicePrincipal'),
    }
    group_owner_link_mapping = {
        'Microsoft.DirectoryServices.User': (lnk_group_owner_user, 'Group', 'User'),
        'Microsoft.DirectoryServices.ServicePrincipal': (lnk_group_owner_serviceprincipal, 'Group', 'ServicePrincipal'),
    }
    device_link_mapping = {
        'Microsoft.DirectoryServices.User': (lnk_device_owner, 'Device', 'User'),
    }

    tasks = []
    dumper.session = dbsession
    totalgroups = dbsession.query(func.count(Group.objectId)).scalar()
    totaldevices = dbsession.query(func.count(Device.objectId)).scalar()
    if totalgroups > MAX_GROUPS:
        print('Gathered {0} groups, switching to 3-phase approach for efficiency'.format(totalgroups))
    async with aiohttp.ClientSession() as ahsession:
        if totalgroups > MAX_GROUPS:
            print('Starting data gathering phase 2 of 3 (collecting properties and relationships)')
        else:
            print('Starting data gathering phase 2 of 2 (collecting properties and relationships)')
        dumper.ahsession = ahsession
        # If we have a lot of groups, dump them separately
        if totalgroups <= MAX_GROUPS:
            tasks.append(dumper.dump_links('groups', 'members', Group, mapping=group_mapping))
            tasks.append(dumper.dump_links('groups', 'owners', Group, mapping=group_owner_mapping))
            tasks.append(dumper.dump_object_expansion('devices', Device, 'registeredOwners', 'owner', User))
        tasks.append(dumper.dump_links('directoryRoles', 'members', DirectoryRole, mapping=role_mapping))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignedTo', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignments', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion('servicePrincipals', ServicePrincipal, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_object_expansion('applications', Application, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_custom_role_members(RoleAssignment))
        if args.mfa:
            tasks.append(dumper.dump_mfa('users', User, method=ahsession.get))
        tasks.append(dumper.dump_each(ServicePrincipal, 'applicationRefs', ApplicationRef))
        tasks.append(dumper.dump_keycredentials('servicePrincipals', ServicePrincipal))
        tasks.append(dumper.dump_keycredentials('applications', Application))
        await asyncio.gather(*tasks)
    dbsession.commit()

    tasks = []
    if totalgroups > MAX_GROUPS:
        print('Starting data gathering phase 3 of 3 (collecting group memberships and device owners)')
        async with aiohttp.ClientSession() as ahsession:
            dumper.ahsession = ahsession
            queue = asyncio.Queue(maxsize=100)
            # Start the workers
            workers = []
            for i in range(100):
                workers.append(asyncio.ensure_future(queue_processor(queue)))

            tasks.append(dumper.dump_links_with_queue(queue, 'devices', 'registeredOwners', Device, mapping=device_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'members', Group, mapping=group_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'owners', Group, mapping=group_owner_link_mapping))

            await asyncio.gather(*tasks)
            await queue.join()
            for worker_task in workers:
                worker_task.cancel()

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
    gather_parser.add_argument('--skip-first-phase',
                               action='store_true',
                               help='Skip the first phase (assumes this has been previously completed)')
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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(args))
    elapsed = time.perf_counter() - seconds
    print("ROADrecon gather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))


if __name__ == "__main__":
    main()
