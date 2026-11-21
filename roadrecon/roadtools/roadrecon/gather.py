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
from datetime import datetime, timezone
from urllib.parse import urlparse
from sqlalchemy import bindparam, func, inspect as sa_inspect, text
from sqlalchemy.dialects.postgresql import insert as pginsert
from sqlalchemy.orm import sessionmaker

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.auth import Authentication
from roadtools.roadrecon.plugins import policyanalysis
from roadtools.roadlib.metadef.database import (
    AdministrativeUnit, AgentIdentityMetadata, Application, ApplicationRef,
    AppRoleAssignment, AuthorizationPolicy, Contact, Device, DirectoryRole,
    DirectorySetting, EligibleRoleAssignment, ExtensionProperty,
    FederatedIdentityCredential, Group, NhiCollectionState, OAuth2PermissionGrant, Policy,
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
            if not self.content_type.startswith('multipart/'):
                # Not a $batch reply (e.g. MS Graph via --evade): pass through untouched
                self._unpacked_body = await super().read()
                return self._unpacked_body
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
        # Copy so the shared headers dict is never mutated
        kwargs['headers'] = dict(kwargs.get('headers') or {})
        if urlparse(url).hostname == 'graph.microsoft.com':
            # MS Graph has no $batch-in-AAD-Graph-format; send as a plain GET
            return super().get(url, **kwargs)
        urlparts = url.split('/')
        reqheaders = kwargs['headers']
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

    def _norm(val):
        return re.sub(r'[^a-z0-9]', '', str(val).lower())

    # Only structured fields are trusted: tags, servicePrincipalType, appMetadata keys.
    # Display name / notes / SPNs are free text and never classify an SP as an agent.
    tag_set = {_norm(t) for t in tags}
    signals = tag_set | {_norm(sp_type)} | {_norm(k) for k in meta_entries}

    # Real MS Graph beta shape (observed live): agent identities carry @odata.type
    # '#microsoft.graph.agentIdentity' and servicePrincipalType 'ServiceIdentity' plus
    # agentIdentityBlueprintId/agentAppId; blueprint principals carry
    # '#microsoft.graph.agentIdentityBlueprintPrincipal'. servicePrincipalType alone is not enough.
    odata_type = str(sp_raw.get('@odata.type') or '').lower()
    is_blueprint_principal = odata_type == '#microsoft.graph.agentidentityblueprintprincipal'
    is_agent_identity = odata_type == '#microsoft.graph.agentidentity' or (
        _norm(sp_type) == 'serviceidentity' and bool(sp_raw.get('agentIdentityBlueprintId') or sp_raw.get('agentAppId')))

    agent_category = None
    if 'agent365' in signals:
        agent_category = 'Agent365'
    elif is_agent_identity or is_blueprint_principal or _norm(sp_type) in ('agentidentity', 'agentid', 'entraagentid', 'aiagent') or 'entraagentid' in tag_set:
        agent_category = 'EntraAgentId'
    elif signals & {'copilotstudio', 'powervirtualagents', 'pva'}:
        agent_category = 'CopilotStudio'
    elif signals & {'declarativeagent', 'm365declarativeagent', 'm365copilot', 'microsoft365copilot'}:
        agent_category = 'M365DeclarativeAgent'
    elif signals & {'azureaiagent', 'azureaifoundry', 'aifoundry', 'aifoundryagent'}:
        agent_category = 'AzureAIAgent'
    elif signals & {'autonomousagent', 'aiagent', 'copilotagent', 'agentblueprintid', 'agentid', 'mcptools', 'mcpservers'}:
        agent_category = 'CustomAIAgent'

    if not agent_category:
        return None

    # Execution mode: explicit field, or a tag exactly equal to a mode name. Never free text.
    exec_lower = str(
        meta_entries.get('executionmode')
        or meta_entries.get('agentexecutionmode')
        or sp_raw.get('executionMode')
        or ''
    ).lower()
    if not exec_lower:
        exec_lower = next((str(t).strip().lower() for t in tags
                           if str(t).strip().lower() in ('autonomous', 'interactive', 'hybrid')), '')
    if 'hybrid' in exec_lower or ('autonomous' in exec_lower and 'interactive' in exec_lower):
        execution_mode = 'Hybrid'
    elif 'autonomous' in exec_lower or 'background' in exec_lower or 'daemon' in exec_lower:
        execution_mode = 'Autonomous'
    elif 'interactive' in exec_lower or 'delegated' in exec_lower:
        execution_mode = 'Interactive'
    else:
        execution_mode = 'Unknown'

    blueprint_id = (
        sp_raw.get('agentIdentityBlueprintId')
        or meta_entries.get('agentblueprintid')
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
        '@odata.type': sp_raw.get('@odata.type'),
        'agentAppId': sp_raw.get('agentAppId'),
        'isBlueprint': is_blueprint_principal,
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
    if meta_dict.get('collectionSource') == 'msgraph_beta':
        # Sponsors come from a separate /sponsors relationship fetch, not from the
        # servicePrincipal payload. Keep the last known values across the merge so a
        # transient lookup failure cannot silently turn a sponsored agent into an orphan.
        existing = dbsession.get(AgentIdentityMetadata, record.objectId)
        if existing is not None and existing.collectionSource == 'msgraph_beta':
            record.sponsorUserIds = existing.sponsorUserIds
    merged = dbsession.merge(record)
    dbsession.flush()
    return merged

NHI_SOURCES = ('federatedCredentials', 'agentMetadata')
NHI_MAX_ATTEMPTS = 3
NHI_MAX_RETRY_DELAY = 60
NHI_RETRY_STATUSES = (429, 500, 502, 503, 504)
NHI_MAX_PAGES = 10000
MSGRAPH_HOST = 'graph.microsoft.com'
MSGRAPH_AUDIENCES = ('https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000')


class NhiFetchError(Exception):
    """MS Graph NHI fetch failed (HTTP error, exception or partial pagination)."""


def record_nhi_state(dbsession, source, status, detail=None, count=None):
    """Upsert one NhiCollectionStates row. No-op if the table does not exist (legacy DB)."""
    if not sa_inspect(dbsession.get_bind()).has_table(NhiCollectionState.__tablename__):
        return
    dbsession.merge(NhiCollectionState(
        source=source, status=status, detail=detail, itemCount=count,
        collectedAt=datetime.now(timezone.utc).isoformat()))
    dbsession.commit()


def mark_nhi_skipped(dbsession, detail):
    for source in NHI_SOURCES:
        record_nhi_state(dbsession, source, 'skipped', detail, 0)


def acquire_msgraph_headers(tok, args, tenantid, user_agent=None):
    """Auth headers for MS Graph, or None. --skip-nhi wins over --nhi/--autotoken.
    user_agent (the one used for AAD Graph, incl. --evade/--user-agent) is added if given."""
    hdrs = _acquire_msgraph_auth(tok, args, tenantid)
    if hdrs and user_agent:
        hdrs['User-Agent'] = user_agent
    return hdrs


def _acquire_msgraph_auth(tok, args, tenantid):
    if getattr(args, 'skip_nhi', False) or not isinstance(tok, dict):
        return None
    try:
        _, tokendata = Authentication.parse_accesstoken(tok.get('accessToken', ''))
    except Exception:
        tokendata = None
    if (tokendata or {}).get('aud') in MSGRAPH_AUDIENCES:
        return {'Authorization': f"{tok.get('tokenType', 'Bearer')} {tok['accessToken']}"}
    if 'refreshToken' in tok and (getattr(args, 'autotoken', False) or getattr(args, 'nhi', False)):
        try:
            ms_auth = Authentication()
            ms_auth.client_id = tok.get('_clientId', '1b730954-1685-4b74-9bfd-dac224a7b894')
            ms_auth.tenant = tenantid
            ms_token = ms_auth.handle_autotoken(dict(tok), args=args, resource='https://graph.microsoft.com')
            if ms_token and 'accessToken' in ms_token:
                return {'Authorization': f"{ms_token.get('tokenType', 'Bearer')} {ms_token['accessToken']}"}
        except Exception as exc:
            print(f"MS Graph token exchange for NHI collection failed: {exc}")
    return None


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
        """Yield items across all pages. Raises NhiFetchError on any failure so
        callers can never mistake partial data for a complete collection."""
        next_url = url
        visited = set()
        while next_url:
            if next_url in visited:
                raise NhiFetchError(f"repeating nextLink {next_url.split('?')[0]}")
            if len(visited) >= NHI_MAX_PAGES:
                raise NhiFetchError(f"page cap {NHI_MAX_PAGES} exceeded")
            visited.add(next_url)
            status = None
            for attempt in range(1, NHI_MAX_ATTEMPTS + 1):
                try:
                    async with self.ahsession.get(next_url, headers=dict(msgraph_headers)) as resp:
                        await resp.read()
                        status = resp.status
                        if status <= 299:
                            payload = await resp.json()
                            break
                        retry_after = (getattr(resp, 'headers', None) or {}).get('Retry-After')
                except Exception as exc:
                    # Strip query strings so an error message can never carry a
                    # signed nextLink (or other URL credential) into the DB/UI.
                    raise NhiFetchError(f"{type(exc).__name__}: {str(exc).split('?')[0]}") from exc
                if status not in NHI_RETRY_STATUSES or attempt == NHI_MAX_ATTEMPTS:
                    raise NhiFetchError(f"HTTP {status} for {next_url.split('?')[0]}")
                try:
                    delay = min(float(retry_after), NHI_MAX_RETRY_DELAY)
                except (TypeError, ValueError):
                    delay = min(2 ** attempt, NHI_MAX_RETRY_DELAY)
                await asyncio.sleep(delay)
            for item in payload.get('value', []):
                yield item
            next_url = payload.get('@odata.nextLink') or payload.get('odata.nextLink')
            if next_url:
                parts = urlparse(next_url)
                if parts.scheme != 'https' or parts.hostname != MSGRAPH_HOST:
                    raise NhiFetchError(f"refusing nextLink outside https://{MSGRAPH_HOST}: {next_url.split('?')[0]}")

    def _safe_record(self, source, status, detail, count):
        """record_nhi_state that survives a poisoned session; never raises."""
        for _ in range(2):
            try:
                record_nhi_state(self.session, source, status, detail, count)
                return
            except Exception as exc:
                self.session.rollback()
                last = exc
        print(f"NHI: could not record state for {source}: {last}")

    async def _collect_source(self, source, url, msgraph_headers, handle_item, prune):
        """Fetch one MS Graph source, record its NhiCollectionState. Never raises
        (fetch or DB errors), so one source cannot hide the other. handle_item
        returns the keys stored, or None when the item was skipped."""
        seen = set()
        skipped = 0
        try:
            async for item in self._fetch_msgraph_paged(url, msgraph_headers):
                keys = handle_item(item)
                if keys is None:
                    skipped += 1
                else:
                    seen.update(keys)
            prune(seen)
        except Exception as exc:
            try:
                self.session.commit()  # keep what was collected; never prune on partial data
            except Exception:
                self.session.rollback()  # DB error poisoned the session
            self._safe_record(source, 'failed', f"{type(exc).__name__}: {str(exc).split('?')[0]}"[:500], len(seen))
            return len(seen)
        detail = f"{skipped} skipped: parent object not in local DB" if skipped else None
        self._safe_record(source, 'collected', detail, len(seen))
        return len(seen)

    async def dump_federated_credentials(self, msgraph_headers):
        if not msgraph_headers or not self.ahsession or not self.session:
            return 0
        url = 'https://graph.microsoft.com/beta/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials'
        seen_ids = set()
        known_apps = {r[0] for r in self.session.query(Application.objectId).all()}

        def handle(app_obj):
            keys = []
            app_object_id = app_obj.get('id') or app_obj.get('objectId')
            fics = app_obj.get('federatedIdentityCredentials') or []
            if app_object_id and fics and app_object_id not in known_apps:
                return None  # FK parent missing locally (stale/partial gather)
            if app_object_id and fics:
                store_federated_credentials_batch(self.session, app_object_id, app_obj.get('appId'), fics)
                for n, fic in enumerate(f for f in fics if isinstance(f, dict)):
                    keys.append(fic.get('id') or f"{app_object_id}:{fic.get('name', n)}")
            seen_ids.update(keys)
            return keys

        def prune(_seen):
            stale = [r[0] for r in self.session.query(FederatedIdentityCredential.id).all() if r[0] not in seen_ids]
            for i in range(0, len(stale), 500):
                self.session.query(FederatedIdentityCredential).filter(
                    FederatedIdentityCredential.id.in_(stale[i:i + 500])).delete(synchronize_session=False)
            self.session.commit()

        return await self._collect_source('federatedCredentials', url, msgraph_headers, handle, prune)

    async def dump_agent_metadata(self, msgraph_headers):
        if not msgraph_headers or not self.ahsession or not self.session:
            return 0
        # No $select: it is not verified that beta supports selecting appMetadata, and an
        # unknown property would 400 the whole source. Default properties are returned.
        url = 'https://graph.microsoft.com/beta/servicePrincipals'

        known_sps = {r[0] for r in self.session.query(ServicePrincipal.objectId).all()}

        sponsor_targets = []

        def handle(sp_obj):
            meta = extract_agent_metadata_from_sp(sp_obj, collection_source="msgraph_beta")
            if meta and meta['objectId'] not in known_sps:
                return None  # FK parent missing locally
            if meta:
                store_agent_metadata(self.session, meta)
                if str((meta.get('rawMetadata') or {}).get('@odata.type') or '').lower() == '#microsoft.graph.agentidentity':
                    sponsor_targets.append(meta['objectId'])
                return [meta['objectId']]
            return []

        def prune(seen):
            stale = [r[0] for r in self.session.query(AgentIdentityMetadata.objectId).filter(
                AgentIdentityMetadata.collectionSource == 'msgraph_beta').all() if r[0] not in seen]
            for i in range(0, len(stale), 500):
                self.session.query(AgentIdentityMetadata).filter(
                    AgentIdentityMetadata.objectId.in_(stale[i:i + 500])).delete(synchronize_session=False)
            self.session.commit()

        count = await self._collect_source('agentMetadata', url, msgraph_headers, handle, prune)
        await self._collect_sponsors(sponsor_targets, msgraph_headers)
        return count

    async def _collect_sponsors(self, agent_ids, msgraph_headers):
        """Sponsors are the /sponsors relationship of an agent identity, not a property.
        A failure for one agent is recorded on its row and in the source detail; it never fails the source."""
        # ponytail: sequential, one GET per agent identity; parallelise if tenants have thousands of agents
        failed = 0
        for agent_id in agent_ids:
            url = f'https://graph.microsoft.com/beta/servicePrincipals/{agent_id}/sponsors?$select=id'
            row = self.session.get(AgentIdentityMetadata, agent_id)
            if row is None:
                continue
            try:
                ids = [u['id'] async for u in self._fetch_msgraph_paged(url, msgraph_headers) if isinstance(u, dict) and u.get('id')]
                row.sponsorUserIds = ids
            except Exception as exc:
                failed += 1
                # A transient lookup failure is not evidence that the agent has no
                # sponsor. Keep any sponsors already stored: clearing them would
                # fabricate an orphan finding and escalate write findings to Critical.
                row.rawMetadata = dict(row.rawMetadata or {}, sponsorsError=f"{type(exc).__name__}: {str(exc).split('?')[0]}"[:300])
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            failed = failed or len(agent_ids)
        if failed:
            marker = self.session.get(NhiCollectionState, 'agentMetadata')
            if marker is not None and marker.status == 'collected':
                detail = f"sponsors unavailable for {failed} of {len(agent_ids)} agent identities"
                self._safe_record('agentMetadata', 'collected', (marker.detail + '; ' + detail) if marker.detail else detail, marker.itemCount)

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
            elif existing_meta is not None:
                # Stale heuristic row from an older/looser classifier
                self.session.delete(existing_meta)
        self.session.commit()

        # Phase 2: MS Graph beta collection
        if not msgraph_headers or not self.ahsession:
            print('NHI: no MS Graph token available - federated credentials and Agent 365 metadata '
                  'collection skipped (heuristic agent detection only). Use --nhi/--autotoken with a '
                  'refresh token, or supply a graph.microsoft.com token.')
            mark_nhi_skipped(self.session, 'no MS Graph token available')
            return
        # Each source records its own state and swallows its own failures
        await self.dump_federated_credentials(msgraph_headers)
        await self.dump_agent_metadata(msgraph_headers)

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

    if getattr(args, 'skip_nhi', False):
        print('NHI: collection skipped (--skip-nhi)')
        mark_nhi_skipped(dbsession, 'skipped via --skip-nhi')
    else:
        msgraph_headers = acquire_msgraph_headers(token, args, tenantid, user_agent=headers.get('User-Agent'))
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
    gather_parser.add_argument('--nhi',
                               action='store_true',
                               help='Force the MS Graph token exchange for NHI collection when a refresh token is available, even without --autotoken. --skip-nhi takes precedence if both are given')
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
