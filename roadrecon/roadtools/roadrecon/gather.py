import argparse
import asyncio
import json
import os
import sys
import time
import warnings
import re
from multidict import CIMultiDict

import aiohttp
from sqlalchemy import bindparam, func, text
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.auth import Authentication
from roadtools.roadrecon.plugins import policyanalysis
from roadtools.roadlib.metadef.database import (
    AdministrativeUnit, AgentIdentityMetadata, Application, ApplicationRef,
    AppRoleAssignment, AuthorizationPolicy, Contact, Device, DirectoryRole,
    DirectorySetting, EligibleRoleAssignment, ExtensionProperty,
    FederatedIdentityCredential, Group, OAuth2PermissionGrant, Policy,
    RoleAssignment, RoleDefinition, ServicePrincipal, TenantDetail, User,
    lnk_au_member_device, lnk_au_member_group, lnk_au_member_user,
    lnk_device_owner, lnk_group_member_contact, lnk_group_member_device,
    lnk_group_member_group, lnk_group_member_serviceprincipal,
    lnk_group_member_user, lnk_group_owner_serviceprincipal,
    lnk_group_owner_user)

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
GATHER_RESOURCE = 'https://graph.windows.net'

class BatchResponse(aiohttp.ClientResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._unpacked_body = None

    async def read(self):
        """Unpack the multipart batch on the first read and cache it."""
        if self._unpacked_body is None:
            # Use MultipartReader to parse the response
            reader = aiohttp.MultipartReader.from_response(self)
            part = await reader.next()

            if part and part.headers.get('Content-Type') == 'application/http':
                inner_raw = await part.read()

                # Split into Status Line, Headers, and Body
                # The first empty line (\r\n\r\n) separates headers from body
                header_block, self._unpacked_body = inner_raw.split(b'\r\n\r\n', 1)

                # Split headers into lines
                header_lines = header_block.decode('utf-8').split('\r\n')
                status_line = header_lines.pop(0) # e.g. "HTTP/1.1 200 OK"

                # Update Status Code
                match = re.search(r'HTTP/\d\.\d\s+(\d{3})', status_line)
                if match:
                    self.status = int(match.group(1))

                # Parse Headers into a MultiDict
                new_headers = CIMultiDict()
                for line in header_lines:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        new_headers.add(k.strip(), v.strip())

                self._headers = new_headers
            else:
                self._unpacked_body = await super().read()
            await reader.release()
            await self.release()
        return self._unpacked_body

    async def json(self, **kwargs):
        return json.loads(await self.read())

    async def text(self, encoding='utf-8'):
        return (await self.read()).decode(encoding)

class BatchSession(aiohttp.ClientSession):
    def __init__(self, *args, **kwargs):
        # Tell the session to use our transparent response class
        kwargs['response_class'] = BatchResponse
        super().__init__(*args, **kwargs)

    def get(self, url, **kwargs):
        # Customize headers or URL
        urlparts = url.split('/')
        reqheaders = kwargs.get('headers', {})
        reqheaders['Content-Type'] = 'multipart/mixed; boundary=batch_request_boundary'
        body = f'''--batch_request_boundary
Content-Type: application/http
Content-Transfer-Encoding: binary

GET {url} HTTP/1.1

--batch_request_boundary--'''
        kwargs['headers'] = reqheaders
        kwargs['data'] = body
        batchurl = f'https://graph.windows.net/{urlparts[3]}/$batch?api-version=1.61-internal'
        # Send POST request instead to $batch endpoint
        return self.post(batchurl, **kwargs)

def mknext(url, prevurl):
    if url.startswith('https://'):
        # Absolute URL
        return url + '&api-version=1.61-internal'
    parts = prevurl.split('/')
    if 'directoryObjects' in url:
        return '/'.join(parts[:4]) + '/' + url + '&api-version=1.61-internal'
    return '/'.join(parts[:-1]) + '/' + url + '&api-version=1.61-internal'

async def dumphelper(url, method):
    global urlcounter, tokencounter
    nexturl = url
    while nexturl:
        checktoken()
        await ratelimit()
        try:
            urlcounter += 1
            async with method(nexturl, headers=headers) as req:
                await req.read()
                # Hold off when rate limit is reached
                if req.status == 429:
                    if tokencounter > 0:
                        tokencounter -= 10*MAX_REQ_PER_SEC
                        print('Sleeping because of rate-limit hit')
                    continue
                if req.status > 299:
                    # Ignore default users role not being found
                    if req.status == 404 and 'a0b1b346-4d3e-4e8b-98f8-753987be4970' in url:
                        return
                    print('Error %d for URL %s' % (req.status, nexturl))
                    if req.status == 403:
                        # Handle access denied cases in AAD graph
                        try:
                            message = await req.json()
                            try:
                                errmessage = message['odata.error']['message']['value']
                                if 'Access blocked to AAD Graph API' in errmessage:
                                    print('Access to AAD Graph API blocked. Try requesting a token with a different client ID, then re-run roadrecon gather')
                            except KeyError:
                                pass
                        except:
                            pass
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
            auth.client_id = '1b730954-1685-4b74-9bfd-dac224a7b894'
        auth.tenant = token['tenantId']
        auth.tokendata = token
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
            await res.read()
            if res.status == 429:
                if tokencounter > 0:
                    tokencounter -= 10*MAX_REQ_PER_SEC
                    print('Sleeping because of rate-limit hit')
                obj = await dumpsingle(url, method)
                return obj
            if res.status > 299:
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

def enginecommit(engine, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['objectId']
        )
    elif 'sqlite' in dburl and ignore:
        statement = dbtype.__table__.insert().prefix_with('OR IGNORE')
    else:
        statement = dbtype.__table__.insert()
    with engine.begin() as conn:
        conn.execute(
            statement,
            cache
        )

def commit(session, dbtype, cache, ignore=False):
    global dburl
    if 'postgresql' in dburl and ignore:
        insertst = pginsert(dbtype.__table__)
        statement = insertst.on_conflict_do_nothing(
            index_elements=['objectId']
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
                index_elements=['objectId']
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

def commitmfa(session, dbtype, cache):
    statement = dbtype.__table__.update().where(dbtype.objectId == bindparam('userid'))
    session.execute(
        statement,
        cache
    )


def _parse_metadata_value(val):
    if val is None:
        return None
    if isinstance(val, (list, dict)):
        return val
    if isinstance(val, str):
        stripped = val.strip()
        if (stripped.startswith('[') and stripped.endswith(']')) or (stripped.startswith('{') and stripped.endswith('}')):
            try:
                return json.loads(stripped)
            except Exception:
                pass
        if ',' in stripped:
            return [s.strip() for s in stripped.split(',') if s.strip()]
        return [stripped] if stripped else []
    return [str(val)]


def extract_agent_metadata_from_sp(sp_raw: dict, collection_source: str = "msgraph_beta") -> dict | None:
    if not isinstance(sp_raw, dict):
        return None
    object_id = sp_raw.get('objectId') or sp_raw.get('id')
    if not object_id:
        return None
    app_id = sp_raw.get('appId')
    display_name = sp_raw.get('displayName') or sp_raw.get('appDisplayName') or ''
    sp_type = sp_raw.get('servicePrincipalType') or ''
    tags = sp_raw.get('tags') or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    notes = sp_raw.get('notes') or sp_raw.get('appData') or ''
    sp_names = sp_raw.get('servicePrincipalNames') or []
    if not isinstance(sp_names, list):
        sp_names = []
    verified_pub = sp_raw.get('verifiedPublisher') or {}
    pub_name = sp_raw.get('publisherName') or (verified_pub.get('displayName') if isinstance(verified_pub, dict) else '') or ''

    app_metadata = sp_raw.get('appMetadata') or {}
    meta_entries = {}
    if isinstance(app_metadata, dict):
        data_list = app_metadata.get('data')
        if isinstance(data_list, list):
            for entry in data_list:
                if isinstance(entry, dict) and entry.get('key'):
                    meta_entries[str(entry['key']).lower()] = entry.get('value')
        else:
            for k, v in app_metadata.items():
                meta_entries[str(k).lower()] = v

    combined_tags_lower = ' '.join(str(t).lower() for t in tags)
    combined_spn_lower = ' '.join(str(s).lower() for s in sp_names)
    dn_lower = display_name.lower()
    sp_type_lower = sp_type.lower()
    notes_lower = str(notes).lower()
    meta_keys_str = ' '.join(f"{k}:{v}" for k, v in meta_entries.items()).lower()
    haystack = ' '.join([dn_lower, sp_type_lower, combined_tags_lower, combined_spn_lower, notes_lower, meta_keys_str])

    agent_category = None
    if 'agent365' in haystack or 'agent 365' in haystack:
        agent_category = 'Agent365'
    elif sp_type_lower in ('agentidentity', 'agentid', 'entraagentid', 'aiagent') or 'entraagent' in haystack or 'agentidentity' in haystack:
        agent_category = 'EntraAgentId'
    elif 'copilotstudio' in haystack or 'copilot studio' in haystack or 'pva_' in haystack or 'power virtual agents' in haystack:
        agent_category = 'CopilotStudio'
    elif 'declarativeagent' in haystack or 'declarative agent' in haystack or 'm365copilot' in haystack or 'm365 copilot' in haystack or 'microsoft 365 copilot' in haystack:
        agent_category = 'M365DeclarativeAgent'
    elif 'azureai' in haystack or 'azure ai' in haystack or 'foundry' in haystack or 'aifoundry' in haystack:
        agent_category = 'AzureAIAgent'
    elif any(kw in haystack for kw in ('autonomous agent', 'ai agent', 'mcp', 'agentblueprintid', 'agentid', 'copilot agent')):
        agent_category = 'CustomAIAgent'

    if not agent_category:
        return None

    exec_mode_raw = (
        meta_entries.get('executionmode')
        or meta_entries.get('agentexecutionmode')
        or meta_entries.get('mode')
        or sp_raw.get('executionMode')
        or ''
    )
    exec_lower = str(exec_mode_raw).lower()
    if 'autonomous' in exec_lower or 'autonomous' in haystack or 'background' in exec_lower or 'daemon' in exec_lower:
        if 'interactive' in exec_lower or 'hybrid' in exec_lower or 'delegated' in exec_lower:
            execution_mode = 'Hybrid'
        else:
            execution_mode = 'Autonomous'
    elif 'hybrid' in exec_lower or 'hybrid' in combined_tags_lower:
        execution_mode = 'Hybrid'
    elif 'interactive' in exec_lower or 'interactive' in haystack or 'declarative' in haystack or agent_category == 'M365DeclarativeAgent':
        execution_mode = 'Interactive'
    else:
        execution_mode = 'Unknown'

    blueprint_id = (
        meta_entries.get('agentblueprintid')
        or meta_entries.get('blueprintid')
        or sp_raw.get('blueprintId')
        or sp_raw.get('applicationTemplateId')
    )

    sponsors_raw = (
        meta_entries.get('sponsoruserids')
        or meta_entries.get('sponsors')
        or meta_entries.get('sponsoruserid')
        or sp_raw.get('sponsorUserIds')
    )
    sponsor_user_ids = _parse_metadata_value(sponsors_raw) or []

    scopes_raw = (
        meta_entries.get('m365scopes')
        or meta_entries.get('scopes')
        or meta_entries.get('copilotscopes')
        or sp_raw.get('m365Scopes')
    )
    m365_scopes = _parse_metadata_value(scopes_raw) or []

    mcp_raw = (
        meta_entries.get('mcptools')
        or meta_entries.get('mcpservers')
        or meta_entries.get('tools')
        or sp_raw.get('mcpTools')
    )
    mcp_tools = _parse_metadata_value(mcp_raw) or []

    raw_metadata = {
        'servicePrincipalType': sp_type,
        'tags': tags,
        'appMetadata': app_metadata,
        'verifiedPublisher': verified_pub,
        'publisherName': pub_name,
    }

    return {
        'objectId': object_id,
        'appId': app_id,
        'agentCategory': agent_category,
        'executionMode': execution_mode,
        'blueprintId': str(blueprint_id) if blueprint_id else None,
        'sponsorUserIds': sponsor_user_ids,
        'm365Scopes': m365_scopes,
        'mcpTools': mcp_tools,
        'collectionSource': sp_raw.get('collectionSource') or collection_source,
        'rawMetadata': raw_metadata,
    }


def store_federated_credentials_batch(dbsession, app_object_id: str, app_id: str, fics_list: list):
    if not fics_list:
        return 0
    count = 0
    for fic in fics_list:
        if not isinstance(fic, dict):
            continue
        fic_id = fic.get('id') or f"{app_object_id}:{fic.get('name', count)}"
        record = FederatedIdentityCredential(
            id=fic_id,
            applicationObjectId=app_object_id,
            appId=app_id,
            name=fic.get('name'),
            issuer=fic.get('issuer'),
            subject=fic.get('subject'),
            description=fic.get('description'),
            audiences=fic.get('audiences') if isinstance(fic.get('audiences'), list) else ([fic['audiences']] if fic.get('audiences') else []),
            claimsMatchingExpression=fic.get('claimsMatchingExpression'),
        )
        dbsession.merge(record)
        count += 1
    dbsession.flush()
    return count


def store_agent_metadata(dbsession, meta_dict: dict):
    if not meta_dict or not meta_dict.get('objectId'):
        return None
    record = AgentIdentityMetadata(
        objectId=meta_dict['objectId'],
        appId=meta_dict.get('appId'),
        agentCategory=meta_dict.get('agentCategory'),
        executionMode=meta_dict.get('executionMode', 'Unknown'),
        blueprintId=meta_dict.get('blueprintId'),
        sponsorUserIds=meta_dict.get('sponsorUserIds') or [],
        m365Scopes=meta_dict.get('m365Scopes') or [],
        mcpTools=meta_dict.get('mcpTools') or [],
        collectionSource=meta_dict.get('collectionSource', 'heuristic'),
        rawMetadata=meta_dict.get('rawMetadata') or {},
    )
    merged = dbsession.merge(record)
    dbsession.flush()
    return merged

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

    @property
    def dbsession(self):
        return self.session

    @dbsession.setter
    def dbsession(self, value):
        self.session = value

    async def dump_object(self, objecttype, dbtype, method=None):
        if method is None:
            method = self.ahsession.get
        url = 'https://graph.windows.net/%s/%s?api-version=1.61-internal' % (self.tenantid, objecttype)
        cache = []
        async for obj in dumphelper(url, method=method):
            cache.append(obj)
            if len(cache) > 1000:
                enginecommit(self.engine, dbtype, cache)
                del cache[:]
        if len(cache) > 0:
            enginecommit(self.engine, dbtype, cache)

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
            child = self.session.get(childtbl, objectid)
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
                parent = self.session.get(dbtype, obj['objectId'])
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
                    child = self.session.get(childtbl, epdata['objectId'])
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

    async def dump_eligible_role_members(self, dbtype):
        parents = self.session.query(RoleDefinition).all()
        cache = []
        jobs = []
        for parent in parents:
            url = 'https://graph.windows.net/%s/eligibleRoleAssignments?api-version=%s&$filter=roleDefinitionId eq \'%s\'' % (self.tenantid, self.api_version, parent.objectId)
            jobs.append(self.dump_lo_to_db(url, self.ahsession.get, dbtype, cache))
        await asyncio.gather(*jobs)
        if len(cache) > 0:
            commit(self.session, dbtype, cache)
        self.session.commit()

    async def _fetch_msgraph_paged(self, url, msgraph_headers):
        next_url = url
        while next_url:
            try:
                async with self.ahsession.get(next_url, headers=msgraph_headers) as resp:
                    await resp.read()
                    if resp.status > 299:
                        return
                    payload = await resp.json()
            except Exception:
                return
            for item in payload.get('value', []):
                yield item
            next_url = payload.get('@odata.nextLink') or payload.get('odata.nextLink')

    async def dump_federated_credentials(self, msgraph_headers):
        if not msgraph_headers or not self.ahsession or not self.session:
            return 0
        url = 'https://graph.microsoft.com/beta/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials'
        total = 0
        async for app_obj in self._fetch_msgraph_paged(url, msgraph_headers):
            app_object_id = app_obj.get('id') or app_obj.get('objectId')
            app_id = app_obj.get('appId')
            fics = app_obj.get('federatedIdentityCredentials') or []
            if app_object_id and fics:
                total += store_federated_credentials_batch(self.session, app_object_id, app_id, fics)
        self.session.commit()
        return total

    async def dump_agent_metadata(self, msgraph_headers):
        if not msgraph_headers or not self.ahsession or not self.session:
            return 0
        url = 'https://graph.microsoft.com/beta/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,tags,appMetadata,verifiedPublisher'
        total = 0
        async for sp_obj in self._fetch_msgraph_paged(url, msgraph_headers):
            meta = extract_agent_metadata_from_sp(sp_obj, collection_source="msgraph_beta")
            if meta:
                store_agent_metadata(self.session, meta)
                total += 1
        self.session.commit()
        return total

    async def dump_nhi_msgraph(self, msgraph_headers=None):
        if not self.session:
            return
        # Phase 1: heuristic extraction over collected ServicePrincipal records
        existing_sps = self.session.query(ServicePrincipal).all()
        for sp in existing_sps:
            existing_meta = self.session.get(AgentIdentityMetadata, sp.objectId)
            if existing_meta and existing_meta.collectionSource == 'msgraph_beta':
                continue
            sp_dict = sp.as_dict()
            meta = extract_agent_metadata_from_sp(sp_dict, collection_source="heuristic")
            if meta:
                store_agent_metadata(self.session, meta)
        self.session.commit()

        # Phase 2: MS Graph beta enrichment if msgraph_headers available
        if msgraph_headers and self.ahsession:
            try:
                await self.dump_federated_credentials(msgraph_headers)
                await self.dump_agent_metadata(msgraph_headers)
            except Exception as exc:
                print(f"Warning: MS Graph NHI beta collection encountered an error: {exc}")

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
    if args.evade:
        if args.user_agent is None:
            args.user_agent = 'Microsoft ADO.NET Data Services'
        aiostrategy = BatchSession
    else:
        aiostrategy = aiohttp.ClientSession

    if args.user_agent:
        # Alias support, get temp auth object
        auth = Authentication()
        auth.set_user_agent(args.user_agent)
        headers['User-Agent'] = auth.user_agent
        # Store this in the token as well
        token['useragent'] = auth.user_agent

    # Handle proxy
    verify_cert = True
    proxyurl = None
    # if args.proxy:
    #     proxyurl = f'{args.proxy_type}://{args.proxy}'
    #     if not args.secure:
    #         verify_cert = False
    # # Disable TLS cert validation
    # if args.insecure:
    #     verify_cert = False

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
        async with aiostrategy(proxy=proxyurl, connector=aiohttp.TCPConnector(ssl=verify_cert)) as ahsession:
            print('Starting data gathering phase 1 of 2 (collecting objects)')
            dumper.ahsession = ahsession
            tasks = []
            tasks.append(dumper.dump_object('users', User))
            tasks.append(dumper.dump_object('tenantDetails', TenantDetail))
            tasks.append(dumper.dump_object('policies', Policy))
            tasks.append(dumper.dump_object('servicePrincipals', ServicePrincipal))
            tasks.append(dumper.dump_object('groups', Group))
            tasks.append(dumper.dump_object('administrativeUnits', AdministrativeUnit))

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
                dbsession.execute(text("DELETE FROM {0}".format(table)))
        dbsession.query(ApplicationRef).delete()
        dbsession.query(RoleAssignment).delete()
        dbsession.query(EligibleRoleAssignment).delete()
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
    au_mapping = {
        'Microsoft.DirectoryServices.User': (User, 'memberUsers'),
        'Microsoft.DirectoryServices.Group': (Group, 'memberGroups'),
        'Microsoft.DirectoryServices.Device': (Device, 'memberDevices'),
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
    au_link_mapping = {
        'Microsoft.DirectoryServices.User': (lnk_au_member_user, 'AdministrativeUnit', 'User'),
        'Microsoft.DirectoryServices.Group': (lnk_au_member_group, 'AdministrativeUnit', 'Group'),
        'Microsoft.DirectoryServices.Device': (lnk_au_member_device, 'AdministrativeUnit', 'Device'),
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
    # pylint: disable=not-callable
    totalgroups = dbsession.query(func.count(Group.objectId)).scalar()
    totaldevices = dbsession.query(func.count(Device.objectId)).scalar()
    if totalgroups > MAX_GROUPS:
        print('Gathered {0} groups, switching to 3-phase approach for efficiency'.format(totalgroups))
    async with aiostrategy(proxy=proxyurl, connector=aiohttp.TCPConnector(ssl=verify_cert)) as ahsession:
        if totalgroups > MAX_GROUPS:
            print('Starting data gathering phase 2 of 3 (collecting properties and relationships)')
        else:
            print('Starting data gathering phase 2 of 2 (collecting properties and relationships)')
        dumper.ahsession = ahsession
        # If we have a lot of groups, dump them separately
        if totalgroups <= MAX_GROUPS:
            tasks.append(dumper.dump_links('groups', 'members', Group, mapping=group_mapping))
            tasks.append(dumper.dump_links('groups', 'owners', Group, mapping=group_owner_mapping))
            tasks.append(dumper.dump_links('administrativeUnits', 'members', AdministrativeUnit, mapping=au_mapping))
            tasks.append(dumper.dump_object_expansion('devices', Device, 'registeredOwners', 'owner', User))
        tasks.append(dumper.dump_links('directoryRoles', 'members', DirectoryRole, mapping=role_mapping))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignedTo', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_linked_objects('servicePrincipals', 'appRoleAssignments', ServicePrincipal, AppRoleAssignment, ignore_duplicates=True))
        tasks.append(dumper.dump_object_expansion('servicePrincipals', ServicePrincipal, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_object_expansion('applications', Application, 'owners', 'owner', User, mapping=owner_mapping))
        tasks.append(dumper.dump_custom_role_members(RoleAssignment))
        tasks.append(dumper.dump_eligible_role_members(EligibleRoleAssignment))
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
        async with aiostrategy(proxy=proxyurl, connector=aiohttp.TCPConnector(ssl=verify_cert)) as ahsession:
            dumper.ahsession = ahsession
            queue = asyncio.Queue(maxsize=100)
            # Start the workers
            workers = []
            for i in range(100):
                workers.append(asyncio.ensure_future(queue_processor(queue)))

            tasks.append(dumper.dump_links_with_queue(queue, 'devices', 'registeredOwners', Device, mapping=device_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'members', Group, mapping=group_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'groups', 'owners', Group, mapping=group_owner_link_mapping))
            tasks.append(dumper.dump_links_with_queue(queue, 'administrativeUnits', 'members', AdministrativeUnit, mapping=au_link_mapping))

            await asyncio.gather(*tasks)
            await queue.join()
            for worker_task in workers:
                worker_task.cancel()

    dbsession.commit()

    if not getattr(args, 'skip_nhi', False):
        msgraph_headers = None
        if isinstance(token, dict):
            try:
                _, tokendata = Authentication.parse_accesstoken(token.get('accessToken', ''))
            except Exception:
                tokendata = {}
            if tokendata.get('aud') in ('https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000'):
                msgraph_headers = {'Authorization': f"{token.get('tokenType', 'Bearer')} {token['accessToken']}"}
            elif 'refreshToken' in token and getattr(args, 'autotoken', False):
                try:
                    ms_auth = Authentication()
                    ms_auth.client_id = token.get('_clientId', '1b730954-1685-4b74-9bfd-dac224a7b894')
                    ms_auth.tenant = tenantid
                    ms_token = ms_auth.handle_autotoken(dict(token), args=args, resource='https://graph.microsoft.com')
                    if ms_token and 'accessToken' in ms_token:
                        msgraph_headers = {'Authorization': f"{ms_token.get('tokenType', 'Bearer')} {ms_token['accessToken']}"}
                except Exception as exc:
                    print(f"Skipping MS Graph beta token exchange for NHI collection: {exc}")
        async with aiostrategy(proxy=proxyurl, connector=aiohttp.TCPConnector(ssl=verify_cert)) as ahsession:
            dumper.ahsession = ahsession
            await dumper.dump_nhi_msgraph(msgraph_headers=msgraph_headers)

    # Auto analyze CA policies
    print('Data gathering complete - Performing data pre-analysis: calculating CA policy scopes')
    policyanalysis.dburl = dburl
    plugin = policyanalysis.PoliciesPlugin(dbsession)
    plugin.main()

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
    gather_parser.add_argument('-ua', '--user-agent', action='store',
                                help='Custom user agent to use. By default aiohttp default user agent is used, and python-requests is used for token renewal')
    gather_parser.add_argument('--autotoken',
                               action='store_true',
                               help='Use refresh token to request access token for the required API automatically')
    gather_parser.add_argument('--skip-azure',
                               action='store_true',
                               help='Skip Azure PIM collection since it is slooooow')
    gather_parser.add_argument('--skip-nhi',
                               action='store_true',
                               help='Skip Non-Human Identity (NHI), Federated Credentials, and Agent 365 metadata collection')
    gather_parser.add_argument('--evade',
                               action='store_true',
                               help='Evade common AAD Graph enumeration detections')
    # gather_parser.add_argument('-p', '--proxy', action='store', help="Proxy requests through a proxy (format: proxyip:port). Ignores TLS validation if specified, unless --secure is used.")
    # gather_parser.add_argument('-pt', '--proxy-type', action='store', default="http", help="Proxy type to use. Supported: http / https. Default: http")
    # gather_parser.add_argument('-s', '--secure', action='store_true', help="Enforce certificate validation even if using a proxy")
    # gather_parser.add_argument('-i', '--insecure', action='store_true', help="Do not validate certificates (insecure)")


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
    try:
        _, tokendata = Authentication.parse_accesstoken(token['accessToken'])
    except KeyError:
        print('No access token found in tokenfile')
        return
    if tokendata['aud'] not in ('https://graph.windows.net', 'https://graph.windows.net/', '00000002-0000-0000-c000-000000000000'):
        if args.autotoken:
            auth = Authentication()
            token = auth.handle_autotoken(token, args=args, resource=GATHER_RESOURCE)
        else:
            print(f"Wrong token audience, got {tokendata['aud']} but expected https://graph.windows.net")
            print("Make sure to request a token with -r https://graph.windows.net")
            return

    headers['Authorization'] = f"Bearer {token['accessToken']}"

    seconds = time.perf_counter()
    asyncio.run(run(args))
    elapsed = time.perf_counter() - seconds
    print("ROADrecon gather executed in {0:0.2f} seconds and issued {1} HTTP requests.".format(elapsed, urlcounter))


if __name__ == "__main__":
    main()
