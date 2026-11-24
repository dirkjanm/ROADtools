import argparse
import asyncio
import json
import os
import sys
import time
import traceback
import warnings

import aiohttp
import requests
import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import Base, lnk_ig_cg_resource, lnk_ig_ap, \
lnk_ig_ap_resource_request, lnk_ig_ap_rr, lnk_ig_ap_rr_scope, \
lnk_ig_ap_assignment_request, \
lnk_ig_ap_assignment_resource_role, lnk_ig_ap_rrs_scope, lnk_ig_ap_rrs_role, \
lnk_ig_ap_assignment_target, lnk_ig_ap_assignment_request_target, lnk_ig_ap_assignment_request_requestor, \
lnk_ig_ap_assignment_policy_inscope_user, lnk_ig_ap_assignment_policy_inscope_serviceprincipal, lnk_ig_ap_assignment_policy_inscope_group, \
IGaccessPackageCatalog, IGaccessPackageResource, \
IGaccessPackageResourceRequest, IGaccessPackageResourceRole, IGaccessPackageResourceRoleScope, \
IGaccessPackage, IGaccessPackageAssignmentPolicy, IGaccessPackageAssignment, \
IGaccessPackageAssignmentRequest, IGaccessPackageAssignmentResourceRole, \
IGaccessPackageResourceScope, IGaccessPackageSubject, User, Group, ServicePrincipal
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
GATHER_RESOURCE = 'https://elm.iga.azure.com/'

def mknext(url, prevurl):
    if url.startswith('https://'):
        # Absolute URL
        return url + ''
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url + ''
    return '/'.join(parts[:-1]) + '/' + url + ''

async def dumphelper(url, method=requests.get):
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

    async def dump_object(self, objecttype, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://elm.iga.azure.com/api/%s/%s' % (self.api_version, objecttype)
        cache = []
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            if len(cache) > 1000:
                commit(self.session, dbtype, cache, ignore=True)
                del cache[:]
        if len(cache) > 0:
            commit(self.session, dbtype, cache, ignore=True)

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
            print(obj)
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
            url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}/{parent.id}/{linktype}'
            jobs.append(self.dump_lo_to_db(url, method, linkobjecttype, cache, ignore_duplicates=ignore_duplicates, parent=provider))
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
            url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}/{parent.id}/{linktype}'
            jobs.append(self.dump_linkednewobject_to_db(url, method, linkobjecttype, mapping, cache, linkcache, parent.id, ignore_duplicates=ignore_duplicates))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            commitlink(self.session, linkcache)
        self.session.commit()

    async def dump_ap_resourcescopes(self, objecttype, dbtype, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}?$expand=accessPackageResourceRoleScopes($expand=accessPackageResourceRole($expand=accessPackageResource),accessPackageResourceScope)'
        i = 0
        linkcache = {}
        multiobjectcache = {}
        async for obj in dumphelper(url, method=method):
            if obj['accessPackageResourceRoleScopes']:
                parent = self.session.get(dbtype, obj['id'])
                if not parent:
                    print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, 'subject', obj['id']))
                    continue
                for epdata in obj['accessPackageResourceRoleScopes']:
                    # add object
                    childtbl = IGaccessPackageResourceRoleScope
                    try:
                        multiobjectcache[childtbl].append(epdata)
                    except KeyError:
                        multiobjectcache[childtbl] = [epdata]
                    # add link
                    try:
                        linkcache[lnk_ig_ap_rr_scope].append({'IGaccessPackage': obj['id'], 'IGaccessPackageResourceRoleScope': epdata['id']})
                    except KeyError:
                        linkcache[lnk_ig_ap_rr_scope] = [{'IGaccessPackage': obj['id'], 'IGaccessPackageResourceRoleScope': epdata['id']}]
                    # Second layer 1 - resource role
                    aprrdata = epdata['accessPackageResourceRole']
                    # add object
                    childtbl = IGaccessPackageResourceRole
                    try:
                        multiobjectcache[childtbl].append(aprrdata)
                    except KeyError:
                        multiobjectcache[childtbl] = [aprrdata]
                    # add link
                    try:
                        linkcache[lnk_ig_ap_rrs_role].append({'IGaccessPackageResourceRoleScope': epdata['id'], 'IGaccessPackageResourceRole': aprrdata['id']})
                    except KeyError:
                        linkcache[lnk_ig_ap_rrs_role] = [{'IGaccessPackageResourceRoleScope': epdata['id'], 'IGaccessPackageResourceRole': aprrdata['id']}]
                    # Third layer - the resource
                    rdata = aprrdata['accessPackageResource']
                    # add link
                    try:
                        linkcache[lnk_ig_ap_rr].append({'IGaccessPackageResource': rdata['id'], 'IGaccessPackageResourceRole': aprrdata['id']})
                    except KeyError:
                        linkcache[lnk_ig_ap_rr] = [{'IGaccessPackageResource': rdata['id'], 'IGaccessPackageResourceRole': aprrdata['id']}]

                    # Second layer 2 - resource scope
                    aprsdata = epdata['accessPackageResourceScope']
                    # add object
                    childtbl = IGaccessPackageResourceScope
                    try:
                        multiobjectcache[childtbl].append(aprsdata)
                    except KeyError:
                        multiobjectcache[childtbl] = [aprsdata]
                    # add link
                    try:
                        linkcache[lnk_ig_ap_rrs_scope].append({'IGaccessPackageResourceRoleScope': epdata['id'], 'IGaccessPackageResourceScope': aprsdata['id']})
                    except KeyError:
                        linkcache[lnk_ig_ap_rrs_scope] = [{'IGaccessPackageResourceRoleScope': epdata['id'], 'IGaccessPackageResourceScope': aprsdata['id']}]
        if len(multiobjectcache) > 0:
            for linkobjecttype, cache in multiobjectcache.items():
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            commitlink(self.session, linkcache)
        self.session.commit()

    async def dump_object_expansion_links(self, objecttype, dbtype, expandprop, linkname, childtbl, mapping=None, method=None):
        if method is None:
            method = self.ahsession.get
        url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}?$expand={expandprop}&$select={expandprop},id'
        i = 0
        async for obj in dumphelper(url, method=method):
            if len(obj[expandprop]) > 0:
                parent = self.session.get(dbtype, obj['id'])
                if not parent:
                    print('Non-existing parent found during expansion %s %s: %s' % (dbtype.__table__, expandprop, obj['id']))
                    continue
                for epdata in obj[expandprop]:
                    if mapping is not None:
                        objclass = epdata['odata.type']
                        try:
                            childtbl, linkname = mapping[objclass]
                        except KeyError:
                            print('Unsupported member type: %s' % objclass)
                            continue
                    child = self.session.get(childtbl, epdata['id'])
                    if not child:
                        print('Non-existing child during expansion %s %s: %s' % (dbtype.__table__, expandprop, epdata['id']))
                        continue
                    getattr(parent, linkname).append(child)
                    i += 1
                    if i > 1000:
                        self.session.commit()
                        i = 0
        self.session.commit()

    async def dump_object_expansion_newobject(self, objecttype, expandprop, linkobjecttype, mapping, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}?$expand={expandprop}&$select={expandprop},id'
        i = 0
        cache = []
        linkcache = {}
        async for obj in dumphelper(url, method=method):
            if obj[expandprop]:
                epdata = obj[expandprop]
                cache.append(epdata)
                try:
                    linktable, leftcol, rightcol = mapping[linkobjecttype]
                except KeyError:
                    print('Unsupported member type: %s ' % (str(linkobjecttype)))
                    continue
                try:
                    linkcache[linktable].append({leftcol: obj['id'], rightcol: epdata['id']})
                except KeyError:
                    linkcache[linktable] = [{leftcol: obj['id'], rightcol: epdata['id']}]
            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                commitlink(self.session, linkcache)
                del cache[:]
                linkcache.clear()
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            commitlink(self.session, linkcache)
        self.session.commit()

    async def dump_accesspackagerequesttarget(self, objecttype, expandprop, linkobjecttype, mapping, method=None, ignore_duplicates=False):
        if method is None:
            method = self.ahsession.get
        url = f'https://elm.iga.azure.com/api/{self.api_version}/{objecttype}?$expand=accessPackageAssignment($expand=target)&$select=id'
        i = 0
        cache = []
        linkcache = {}
        async for obj in dumphelper(url, method=method):
            if obj['accessPackageAssignment'] and obj['accessPackageAssignment'][expandprop]:
                # Its in a subproperty, great
                epdata = obj['accessPackageAssignment'][expandprop]
                cache.append(epdata)
                try:
                    linktable, leftcol, rightcol = mapping[linkobjecttype]
                except KeyError:
                    print('Unsupported member type: %s ' % (str(linkobjecttype)))
                    continue
                try:
                    linkcache[linktable].append({leftcol: obj['id'], rightcol: epdata['id']})
                except KeyError:
                    linkcache[linktable] = [{leftcol: obj['id'], rightcol: epdata['id']}]
            if len(cache) > 1000:
                commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
                commitlink(self.session, linkcache)
                del cache[:]
                linkcache.clear()
        if len(cache) > 0:
            commit(self.session, linkobjecttype, cache, ignore=ignore_duplicates)
            commitlink(self.session, linkcache)
        self.session.commit()

async def run(args):
    global token, expiretime, headers, dburl
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

    dbsession.query(IGaccessPackageCatalog).delete()
    dbsession.query(IGaccessPackageResource).delete()
    dbsession.query(IGaccessPackageResourceRequest).delete()
    dbsession.query(IGaccessPackageResourceRole).delete()
    dbsession.query(IGaccessPackageResourceRoleScope).delete()
    dbsession.query(IGaccessPackageResourceScope).delete()
    dbsession.query(IGaccessPackage).delete()
    dbsession.query(IGaccessPackageAssignmentPolicy).delete()
    dbsession.query(IGaccessPackageAssignment).delete()
    dbsession.query(IGaccessPackageAssignmentRequest).delete()
    dbsession.query(IGaccessPackageAssignmentResourceRole).delete()
    dbsession.query(IGaccessPackageSubject).delete()
    # Delete existing links to make sure we start with clean data
    for table in database.Base.metadata.tables.keys():
        if table.startswith('lnk_ig_'):
            dbsession.execute(text("DELETE FROM {0}".format(table)))

    dumper = DataDumper('v1', engine=engine)
    print('Phase 1 - gather data')
    async with aiohttp.ClientSession() as ahsession:
        print('Starting data gathering')
        dumper.ahsession = ahsession
        dumper.session = dbsession

        tasks = []

        # Mapping object, mapping type returned to Table and link name
        resource_link_mapping = {
            IGaccessPackageResource: (lnk_ig_cg_resource, 'IGaccessPackageCatalog', 'IGaccessPackageResource'),
        }

        tasks = []
        tasks.append(dumper.dump_object('accessPackageCatalogs', IGaccessPackageCatalog))
        tasks.append(dumper.dump_object('accessPackages', IGaccessPackage))
        tasks.append(dumper.dump_object('accessPackageAssignmentPolicies', IGaccessPackageAssignmentPolicy))
        tasks.append(dumper.dump_object('accessPackageAssignments', IGaccessPackageAssignment))
        tasks.append(dumper.dump_object('accessPackageAssignmentRequests', IGaccessPackageAssignmentRequest))

        await asyncio.gather(*tasks)
        dbsession.commit()

        tasks = []
        tasks.append(dumper.dump_linked_newobjects('accessPackageCatalogs', 'accessPackageResources', IGaccessPackageCatalog, IGaccessPackageResource, resource_link_mapping, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion_links('accessPackages', IGaccessPackage, 'accessPackageAssignmentPolicies', 'assignmentPolicies', IGaccessPackageAssignmentPolicy))
        # tasks.append(dumper.dump_object_expansion_links('accessPackages', IGaccessPackage, 'accessPackageAssignments', 'assignments', IGaccessPackageAssignmentPolicy))
        # tasks.append(dumper.dump_object_expansion_links('accessPackages', IGaccessPackage, 'accessPackageAssignmentRequests', 'assignmentRequests', IGaccessPackageAssignmentRequest))
        tasks.append(dumper.dump_object_expansion_links('accessPackageCatalogs', IGaccessPackageCatalog, 'accessPackages', 'accessPackages', IGaccessPackage))

        # Flush cache to make sure all objects exist
        await asyncio.gather(*tasks)
        dbsession.commit()
        tasks = []
        ass_subject_link_mapping = {
            IGaccessPackageSubject: (lnk_ig_ap_assignment_target, 'IGaccessPackageAssignment', 'IGaccessPackageSubject'),
        }

        tasks.append(dumper.dump_ap_resourcescopes('accessPackages', IGaccessPackage, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion_newobject('accessPackageAssignments', 'target', IGaccessPackageSubject, ass_subject_link_mapping, ignore_duplicates=True))
        ass_req_subject_link_mapping = {
            IGaccessPackageSubject: (lnk_ig_ap_assignment_request_requestor, 'IGaccessPackageAssignmentRequest', 'IGaccessPackageSubject'),
        }
        tasks.append(dumper.dump_object_expansion_newobject('accessPackageAssignmentRequests', 'requestor', IGaccessPackageSubject, ass_req_subject_link_mapping, ignore_duplicates=True))
        ass_req_subject_link_mapping_target = {
            IGaccessPackageSubject: (lnk_ig_ap_assignment_request_target, 'IGaccessPackageAssignmentRequest', 'IGaccessPackageSubject'),
        }
        tasks.append(dumper.dump_accesspackagerequesttarget('accessPackageAssignmentRequests', 'target', IGaccessPackageSubject, ass_req_subject_link_mapping_target, ignore_duplicates=True))

        await asyncio.gather(*tasks)
        dbsession.commit()

    print('Phase 2 - calculate access package scopes')
    linktable_mapping = {
        '#Microsoft.IGAELM.EC.FrontEnd.ExternalModel.groupMembers': (lnk_ig_ap_assignment_policy_inscope_group, 'IGaccessPackageAssignmentPolicy', 'Group'),
        '#Microsoft.IGAELM.EC.FrontEnd.ExternalModel.singleUser': (lnk_ig_ap_assignment_policy_inscope_user, 'IGaccessPackageAssignmentPolicy', 'User'),
        '#Microsoft.IGAELM.EC.FrontEnd.ExternalModel.singleServicePrincipal': (lnk_ig_ap_assignment_policy_inscope_serviceprincipal, 'IGaccessPackageAssignmentPolicy', 'ServicePrincipal'),
    }
    linkcache = {}
    for appolicy in dbsession.query(IGaccessPackageAssignmentPolicy).all():
        if appolicy.allowedTargetScope == 'specificDirectoryUsers':
            for target in appolicy.specificAllowedTargets:
                linkobjecttype = target['@odata.type']
                try:
                    linktable, leftcol, rightcol = linktable_mapping[linkobjecttype]
                except KeyError:
                    print('Unsupported member type: %s ' % (str(linkobjecttype)))
                    continue
                try:
                    linkcache[linktable].append({leftcol: appolicy.id, rightcol: target['objectId']})
                except KeyError:
                    linkcache[linktable] = [{leftcol: appolicy.id, rightcol: target['objectId']}]
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
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon - Gather Identity Governance information', formatter_class=argparse.RawDescriptionHelpFormatter)
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
    if tokendata['aud'] not in ('https://elm.iga.azure.com/', 'https://elm.iga.azure.com', 'https://management.azure.com/', '00000002-0000-0000-c000-000000000000'):
        if args.autotoken:
            auth = Authentication()
            token = auth.handle_autotoken(token, args=args, resource=GATHER_RESOURCE)
        else:
            print(f"Wrong token audience, got {tokendata['aud']} but expected https://elm.iga.azure.com")
            print("Make sure to request a token with -r https://elm.iga.azure.com")
            return

    headers['Authorization'] = f"Bearer {token['accessToken']}"

    seconds = time.perf_counter()
    asyncio.run(run(args))
    elapsed = time.perf_counter() - seconds
    print("ROADrecon iggather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))


if __name__ == "__main__":
    main()
