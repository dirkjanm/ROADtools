import argparse
import asyncio
from types import SimpleNamespace

import aiohttp
import pytest

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import (
    AgentIdentityMetadata,
    Application,
    FederatedIdentityCredential,
    NhiCollectionState,
    ServicePrincipal,
)
from roadtools.roadrecon import gather
from roadtools.roadrecon.gather import DataDumper, extract_agent_metadata_from_sp

AUTH = {"Authorization": "Bearer fake"}


class FakeResponse:
    def __init__(self, status, payload=None, headers=None):
        self.status = status
        self._payload = payload or {}
        self.headers = headers or {}

    async def read(self):
        return b""

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """routes: substring -> list of FakeResponse|Exception (last one repeats)."""

    def __init__(self, routes):
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls = []
        self.headers_seen = []

    def get(self, url, headers=None):
        self.calls.append(url)
        self.headers_seen.append(headers)
        for key, queue in self.routes.items():
            if key in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(item, Exception):
                    raise item
                return item
        return FakeResponse(404)


def app_page(next_link=None, fic_id="fic-1", app_id="app-1"):
    page = {"value": [{"id": app_id, "appId": "g-" + app_id, "federatedIdentityCredentials": [
        {"id": fic_id, "name": fic_id, "issuer": "i", "subject": "s"}]}]}
    if next_link:
        page["@odata.nextLink"] = next_link
    return page


def sp_page(*ids):
    return {"value": [{"id": i, "appId": "g-" + i, "displayName": "x",
                       "servicePrincipalType": "AgentIdentity", "tags": ["Agent365"]} for i in ids]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = database.init(create=True, dburl=f"sqlite:///{tmp_path / 't.db'}")
    session = database.get_session(engine)

    async def no_sleep(_s):
        return None

    sleeps = []

    async def rec_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(gather.asyncio, "sleep", rec_sleep)
    yield SimpleNamespace(engine=engine, session=session, sleeps=sleeps)
    session.close()


def seed(env, apps=(), sps=()):
    env.session.add_all([Application(objectId=a) for a in apps] + [ServicePrincipal(objectId=x) for x in sps])
    env.session.commit()


def run(env, routes, headers=AUTH):
    fake = FakeSession(routes)
    d = DataDumper("t", "1.61-internal", ahsession=fake, engine=env.engine, session=env.session)
    asyncio.run(d.dump_nhi_msgraph(msgraph_headers=headers))
    return fake


def state(env, source):
    env.session.expire_all()
    return env.session.get(NhiCollectionState, source)


# ---- Finding 1: collection state -------------------------------------------------

def test_full_success_marks_collected_with_counts(env):
    seed(env, apps=('app-1', 'app-2'), sps=('sp-1',))
    run(env, {
        "/beta/applications": [FakeResponse(200, app_page(next_link="https://graph.microsoft.com/beta/applications?$skiptoken=2")),
                               FakeResponse(200, app_page(fic_id="fic-2", app_id="app-2"))],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page("sp-1"))],
    })
    f, a = state(env, "federatedCredentials"), state(env, "agentMetadata")
    assert (f.status, f.itemCount) == ("collected", 2)
    assert (a.status, a.itemCount) == ("collected", 1)
    assert f.collectedAt


def test_http_failure_isolated_per_source(env):
    seed(env, sps=('sp-1',))
    run(env, {
        "/beta/applications": [FakeResponse(403)],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page("sp-1"))],
    })
    f, a = state(env, "federatedCredentials"), state(env, "agentMetadata")
    assert f.status == "failed" and "403" in f.detail
    assert a.status == "collected" and a.itemCount == 1


def test_exception_marks_failed_and_other_source_still_runs(env):
    seed(env, sps=('sp-1',))
    run(env, {
        "/beta/applications": [RuntimeError("boom-net")],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page("sp-1"))],
    })
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and "boom-net" in f.detail
    assert state(env, "agentMetadata").status == "collected"


def test_partial_pagination_is_failed_not_collected(env):
    seed(env, apps=('app-1',))
    env.session.add(FederatedIdentityCredential(id="old", applicationObjectId="app-1"))
    env.session.commit()
    run(env, {
        "/beta/applications": [FakeResponse(200, app_page(next_link="https://graph.microsoft.com/beta/applications?$skiptoken=2")),
                               FakeResponse(500)],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page())],
    })
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and "500" in f.detail
    # no stale cleanup on partial data
    assert env.session.get(FederatedIdentityCredential, "old") is not None


def test_no_token_marks_skipped_and_prints(env, capsys):
    run(env, {}, headers=None)
    out = capsys.readouterr().out
    assert "MS Graph" in out and "skipped" in out.lower()
    for src in ("federatedCredentials", "agentMetadata"):
        assert state(env, src).status == "skipped"


def test_mark_nhi_skipped_for_skip_flag(env):
    gather.mark_nhi_skipped(env.session, "--skip-nhi")
    for src in ("federatedCredentials", "agentMetadata"):
        s = state(env, src)
        assert s.status == "skipped" and "--skip-nhi" in s.detail


def test_state_not_written_when_table_missing(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    ServicePrincipal.__table__.create(engine)
    s = sessionmaker(bind=engine)()
    gather.mark_nhi_skipped(s, "x")  # must not raise
    s.close()


# ---- Finding 3: retry + stale ----------------------------------------------------

def test_429_retries_honoring_retry_after_then_succeeds(env):
    seed(env, apps=('app-1',))
    run(env, {
        "/beta/applications": [FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, app_page())],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page())],
    })
    assert 7 in env.sleeps
    assert state(env, "federatedCredentials").status == "collected"


def test_retry_attempts_are_capped(env):
    fake = run(env, {
        "/beta/applications": [FakeResponse(503)],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page())],
    })
    assert sum("/beta/applications" in c for c in fake.calls) == 3
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and "503" in f.detail


def test_stale_rows_removed_only_on_success(env):
    seed(env, apps=('app-1',), sps=('sp-1', 'sp-old'))
    env.session.add_all([
        FederatedIdentityCredential(id="stale", applicationObjectId="app-1"),
        AgentIdentityMetadata(objectId="sp-old", agentCategory="Agent365", collectionSource="msgraph_beta"),
        AgentIdentityMetadata(objectId="sp-heur", agentCategory="Agent365", collectionSource="heuristic"),
    ])
    env.session.commit()
    run(env, {
        "/beta/applications": [FakeResponse(200, app_page())],
        "/beta/servicePrincipals": [FakeResponse(200, sp_page("sp-1"))],
    })
    s = env.session
    assert s.get(FederatedIdentityCredential, "stale") is None
    assert s.get(FederatedIdentityCredential, "fic-1") is not None
    assert s.get(AgentIdentityMetadata, "sp-old") is None
    assert s.get(AgentIdentityMetadata, "sp-1").collectionSource == "msgraph_beta"
    assert s.get(AgentIdentityMetadata, "sp-heur") is not None


def test_stale_rows_kept_when_source_fails(env):
    seed(env, apps=('app-1',), sps=('sp-old',))
    env.session.add(AgentIdentityMetadata(objectId="sp-old", agentCategory="Agent365", collectionSource="msgraph_beta"))
    env.session.commit()
    run(env, {"/beta/applications": [FakeResponse(200, app_page())],
              "/beta/servicePrincipals": [FakeResponse(403)]})
    assert env.session.get(AgentIdentityMetadata, "sp-old") is not None
    assert state(env, "agentMetadata").status == "failed"


# ---- Finding 2: --evade BatchSession --------------------------------------------

def test_batchsession_bypasses_batch_rewrite_for_msgraph(monkeypatch):
    seen = {}

    def fake_get(self, url, **kw):
        seen["get"] = (url, kw)
        return "plain-get"

    def fake_post(self, url, **kw):
        seen["post"] = (url, kw)
        return "batch-post"

    monkeypatch.setattr(aiohttp.ClientSession, "get", fake_get)
    monkeypatch.setattr(aiohttp.ClientSession, "post", fake_post)
    shared = {"Authorization": "Bearer x"}

    async def go():
        async with gather.BatchSession() as s:
            r1 = s.get("https://graph.microsoft.com/beta/applications?$top=5", headers=shared)
            snap = dict(shared)
            r2 = s.get("https://graph.windows.net/tenant/users?api-version=1.61-internal", headers=shared)
            return r1, r2, snap

    r1, r2, snap = asyncio.run(go())
    assert r1 == "plain-get"
    assert seen["get"][0].startswith("https://graph.microsoft.com/beta/applications")
    assert "Content-Type" not in seen["get"][1]["headers"]
    assert r2 == "batch-post"
    assert "$batch" in seen["post"][0]
    # shared headers never mutated, in either path
    assert shared == {"Authorization": "Bearer x"} == snap
    assert seen["post"][1]["headers"]["Content-Type"].startswith("multipart/mixed")


def test_batchresponse_passes_through_non_multipart_json():
    from aiohttp import web
    from aiohttp.test_utils import TestServer

    async def go():
        app = web.Application()

        async def h(_r):
            return web.json_response({"value": [1]})

        app.router.add_post("/x", h)
        async with TestServer(app) as srv:
            async with gather.BatchSession() as s:
                async with s.post(str(srv.make_url("/x"))) as resp:
                    return await resp.json()

    assert asyncio.run(go()) == {"value": [1]}


# ---- N1: DB errors with FK enforcement -------------------------------------------

@pytest.fixture
def env_fk(tmp_path, monkeypatch):
    from sqlalchemy import event
    engine = database.init(create=True, dburl=f"sqlite:///{tmp_path / 'fk.db'}")

    @event.listens_for(engine, "connect")
    def _fk(conn, _rec):
        conn.execute("PRAGMA foreign_keys=ON")

    engine.dispose()
    session = database.get_session(engine)

    async def rec_sleep(_s):
        return None

    monkeypatch.setattr(gather.asyncio, "sleep", rec_sleep)
    yield SimpleNamespace(engine=engine, session=session, sleeps=[])
    session.close()


def test_fk_on_orphans_skipped_not_fatal(env_fk):
    env = env_fk
    seed(env, apps=("app-2",))
    env.session.add(NhiCollectionState(source="federatedCredentials", status="collected", itemCount=99))
    env.session.commit()
    page = {"value": app_page()["value"] + app_page(fic_id="fic-2", app_id="app-2")["value"]}
    run(env, {"/beta/applications": [FakeResponse(200, page)],
              "/beta/servicePrincipals": [FakeResponse(200, sp_page("ghost-sp"))]})
    f, a = state(env, "federatedCredentials"), state(env, "agentMetadata")
    assert (f.status, f.itemCount) == ("collected", 1)
    assert "1 skipped" in f.detail
    assert env.session.get(FederatedIdentityCredential, "fic-2") is not None
    assert env.session.get(FederatedIdentityCredential, "fic-1") is None
    assert (a.status, a.itemCount) == ("collected", 0) and "1 skipped" in a.detail


def test_db_error_in_handler_marks_failed_and_replaces_stale_marker(env_fk, monkeypatch):
    env = env_fk
    seed(env, apps=("app-1",), sps=("sp-1",))
    env.session.add(NhiCollectionState(source="federatedCredentials", status="collected", itemCount=99))
    env.session.commit()

    def bad_store(session, app_object_id, app_id, fics):
        session.add(FederatedIdentityCredential(id="x", applicationObjectId="no-such-app"))
        session.flush()  # IntegrityError under FK enforcement

    monkeypatch.setattr(gather, "store_federated_credentials_batch", bad_store)
    run(env, {"/beta/applications": [FakeResponse(200, app_page())],
              "/beta/servicePrincipals": [FakeResponse(200, sp_page("sp-1"))]})  # must not raise
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and f.detail
    assert state(env, "agentMetadata").status == "collected"


# ---- N4: user agent ----------------------------------------------------------------

def test_acquire_msgraph_headers_carries_user_agent(fake_auth):
    h = gather.acquire_msgraph_headers(TOK, _parse("--nhi"), "t", user_agent="UA-test")
    assert h == {"Authorization": "Bearer g", "User-Agent": "UA-test"}
    assert gather.acquire_msgraph_headers(TOK, _parse("--nhi"), "t") == {"Authorization": "Bearer g"}


def test_user_agent_sent_on_every_msgraph_request(env):
    seed(env, apps=("app-1",))
    fake = run(env, {"/beta/applications": [FakeResponse(200, app_page())],
                     "/beta/servicePrincipals": [FakeResponse(200, sp_page())]},
               headers={**AUTH, "User-Agent": "UA-test"})
    assert fake.headers_seen and all(h["User-Agent"] == "UA-test" for h in fake.headers_seen)


# ---- N8: nextLink validation / loop guard -----------------------------------------

@pytest.mark.parametrize("link", [
    "https://evil.example.com/beta/applications?$skiptoken=2",
    "http://graph.microsoft.com/beta/applications?$skiptoken=2",
    "https://graph.microsoft.com.evil.com/beta/applications",
])
def test_foreign_nextlink_rejected_and_token_not_sent(env, link):
    fake = run(env, {"/beta/applications": [FakeResponse(200, app_page(next_link=link))],
                     "/beta/servicePrincipals": [FakeResponse(200, sp_page())]})
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and "nextLink" in f.detail
    assert not any("evil" in c or c.startswith("http://") for c in fake.calls)


def test_repeating_nextlink_terminates(env):
    loop = "https://graph.microsoft.com/beta/applications?$skiptoken=1"
    run(env, {"/beta/applications": [FakeResponse(200, app_page(next_link=loop))],
              "/beta/servicePrincipals": [FakeResponse(200, sp_page())]})
    f = state(env, "federatedCredentials")
    assert f.status == "failed" and "repeat" in f.detail.lower()


def test_page_cap_enforced(env, monkeypatch):
    monkeypatch.setattr(gather, "NHI_MAX_PAGES", 3)
    pages = [FakeResponse(200, app_page(next_link=f"https://graph.microsoft.com/beta/applications?$skiptoken={i}"))
             for i in range(10)]
    fake = run(env, {"/beta/applications": pages, "/beta/servicePrincipals": [FakeResponse(200, sp_page())]})
    assert sum("/beta/applications" in c for c in fake.calls) <= 3
    assert state(env, "federatedCredentials").status == "failed"


# ---- BatchResponse multipart regression ---------------------------------------------

def test_batchresponse_parses_multipart_batch_reply():
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    inner = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
             b'{"value": [{"objectId": "u1"}]}')
    body = (b"--bnd\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n"
            + inner + b"\r\n--bnd--\r\n")

    async def go():
        app = web.Application()

        async def h(_r):
            return web.Response(body=body, headers={"Content-Type": "multipart/mixed; boundary=bnd"})

        app.router.add_post("/b", h)
        async with TestServer(app) as srv:
            async with gather.BatchSession() as s:
                async with s.post(str(srv.make_url("/b"))) as resp:
                    return await resp.json(), resp.status

    data, status = asyncio.run(go())
    assert data == {"value": [{"objectId": "u1"}]} and status == 200


# ---- Finding 4: heuristics -------------------------------------------------------

@pytest.mark.parametrize("name", [
    "Azure AI Search", "McPherson Expense", "Salesforce MCP Connector",
    "Agentid Tool", "PVA_helper", "Foundry Cloud Sync", "Autonomous Agent Reports",
    "Microsoft 365 Copilot Usage Report", "Copilot Studio Exporter",
])
def test_generic_names_do_not_classify_as_agents(name):
    sp = {"id": "sp", "displayName": name, "servicePrincipalType": "Application",
          "tags": ["WindowsAzureActiveDirectoryIntegratedApp"], "notes": "ai agent mcp foundry"}
    assert extract_agent_metadata_from_sp(sp) is None


@pytest.mark.parametrize("sp,category", [
    ({"servicePrincipalType": "AgentIdentity"}, "EntraAgentId"),
    ({"tags": ["Agent365"]}, "Agent365"),
    ({"tags": ["CopilotStudio"]}, "CopilotStudio"),
    ({"tags": ["DeclarativeAgent"]}, "M365DeclarativeAgent"),
    ({"appMetadata": {"data": [{"key": "AgentBlueprintId", "value": "b"}]}}, "CustomAIAgent"),
])
def test_explicit_signals_classify(sp, category):
    sp = {"id": "sp", "displayName": "Whatever", **sp}
    assert extract_agent_metadata_from_sp(sp)["agentCategory"] == category


def test_execution_mode_only_from_explicit_fields():
    base = {"id": "sp", "servicePrincipalType": "AgentIdentity"}
    # display-name / notes substrings are ignored
    m = extract_agent_metadata_from_sp({**base, "displayName": "Autonomous Interactive Hybrid", "notes": "autonomous"})
    assert m["executionMode"] == "Unknown"
    # tag must equal the mode exactly
    assert extract_agent_metadata_from_sp({**base, "tags": ["NotAutonomousAtAll"]})["executionMode"] == "Unknown"
    assert extract_agent_metadata_from_sp({**base, "tags": ["Autonomous"]})["executionMode"] == "Autonomous"
    assert extract_agent_metadata_from_sp({**base, "tags": ["hybrid"]})["executionMode"] == "Hybrid"
    assert extract_agent_metadata_from_sp({**base, "executionMode": "Interactive"})["executionMode"] == "Interactive"
    md = {"appMetadata": {"data": [{"key": "ExecutionMode", "value": "Autonomous"}]}}
    assert extract_agent_metadata_from_sp({**base, **md})["executionMode"] == "Autonomous"


# ---- Finding 5: --nhi flag -------------------------------------------------------

def _parse(*argv):
    p = argparse.ArgumentParser()
    gather.getargs(p)
    return p.parse_args(list(argv))


def test_nhi_flag_parses_and_help_mentions_skip_wins():
    assert _parse("--nhi").nhi is True
    assert _parse().nhi is False
    p = argparse.ArgumentParser()
    gather.getargs(p)
    nhi_help = next(a.help for a in p._actions if "--nhi" in a.option_strings)
    assert "--skip-nhi" in nhi_help


@pytest.fixture
def fake_auth(monkeypatch):
    calls = []

    class A:
        @staticmethod
        def parse_accesstoken(_t):
            return None, {}

        def handle_autotoken(self, tok, args=None, resource=None):
            calls.append(resource)
            return {"accessToken": "g", "tokenType": "Bearer"}

    monkeypatch.setattr(gather, "Authentication", A)
    return calls


TOK = {"accessToken": "x", "tokenType": "Bearer", "refreshToken": "r"}


def test_nhi_flag_forces_exchange_without_autotoken(fake_auth):
    h = gather.acquire_msgraph_headers(TOK, _parse("--nhi"), "t")
    assert h == {"Authorization": "Bearer g"} and fake_auth == ["https://graph.microsoft.com"]


def test_skip_nhi_wins_over_nhi(fake_auth):
    assert gather.acquire_msgraph_headers(TOK, _parse("--nhi", "--skip-nhi"), "t") is None
    assert fake_auth == []


def test_no_flags_no_exchange(fake_auth):
    assert gather.acquire_msgraph_headers(TOK, _parse(), "t") is None
    assert fake_auth == []
    assert gather.acquire_msgraph_headers(TOK, _parse("--autotoken"), "t") is not None


# ---- Live-Graph shapes (observed 2026-11-20; sanitized, no tenant data) ---------------

LIVE_AGENT = {
    "@odata.type": "#microsoft.graph.agentIdentity", "id": "ag-1", "appId": "ag-app-1",
    "displayName": "agent one", "servicePrincipalType": "ServiceIdentity", "tags": [],
    "agentAppId": "ag-app-1", "agentIdentityBlueprintId": "bp-1", "accountEnabled": True,
}
LIVE_BLUEPRINT_PRINCIPAL = {
    "@odata.type": "#microsoft.graph.agentIdentityBlueprintPrincipal", "id": "bp-sp-1",
    "appId": "bp-app-1", "displayName": "blueprint one", "servicePrincipalType": "Application", "tags": [],
}


def test_live_agent_identity_is_classified_with_blueprint_id():
    m = extract_agent_metadata_from_sp(LIVE_AGENT)
    assert m["agentCategory"] == "EntraAgentId"
    assert m["blueprintId"] == "bp-1"
    assert m["executionMode"] == "Unknown"
    assert m["rawMetadata"]["@odata.type"] == "#microsoft.graph.agentIdentity"
    assert m["rawMetadata"]["agentAppId"] == "ag-app-1"


def test_live_blueprint_principal_is_classified_and_marked():
    m = extract_agent_metadata_from_sp(LIVE_BLUEPRINT_PRINCIPAL)
    assert m["agentCategory"] == "EntraAgentId"
    assert m["rawMetadata"]["isBlueprint"] is True


@pytest.mark.parametrize("sp", [
    {"id": "x", "servicePrincipalType": "ServiceIdentity", "tags": []},          # type alone is not enough
    {"id": "x", "servicePrincipalType": "Application", "tags": [], "displayName": "agent identity blueprint"},
    {"id": "x", "servicePrincipalType": "ManagedIdentity", "tags": []},
    {"id": "x", "@odata.type": "#microsoft.graph.servicePrincipal", "tags": []},
])
def test_non_agent_live_shapes_do_not_classify(sp):
    assert extract_agent_metadata_from_sp(sp) is None


def test_sponsors_fetched_for_agent_identities_only(env):
    seed(env, sps=("ag-1", "bp-sp-1"))
    fake = run(env, {
        "/sponsors": [FakeResponse(200, {"value": [{"id": "u-1"}, {"id": "u-2"}]})],
        "/beta/servicePrincipals": [FakeResponse(200, {"value": [LIVE_AGENT, LIVE_BLUEPRINT_PRINCIPAL]})],
    })
    env.session.expire_all()
    agent = env.session.get(AgentIdentityMetadata, "ag-1")
    assert agent.sponsorUserIds == ["u-1", "u-2"]
    assert env.session.get(AgentIdentityMetadata, "bp-sp-1") is not None
    sponsor_calls = [c for c in fake.calls if "/sponsors" in c]
    assert len(sponsor_calls) == 1 and "/ag-1/" in sponsor_calls[0]
    a = state(env, "agentMetadata")
    assert a.status == "collected" and a.detail is None


def test_sponsor_fetch_failure_is_recorded_not_fatal(env):
    seed(env, sps=("ag-1",))
    run(env, {
        "/sponsors": [FakeResponse(403)],
        "/beta/servicePrincipals": [FakeResponse(200, {"value": [LIVE_AGENT]})],
    })
    env.session.expire_all()
    agent = env.session.get(AgentIdentityMetadata, "ag-1")
    assert agent is not None and agent.sponsorUserIds == []
    assert "403" in agent.rawMetadata["sponsorsError"]
    a = state(env, "agentMetadata")
    assert a.status == "collected" and "sponsors unavailable" in a.detail
