import types

import pytest
from sqlalchemy import text

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import (
    AgentIdentityMetadata,
    Application,
    AppRoleAssignment,
    DirectoryRole,
    FederatedIdentityCredential,
    NhiCollectionState,
    OAuth2PermissionGrant,
    ServicePrincipal,
    User,
)
from roadtools.roadrecon.nhi_analyzer import analyze_nhi_posture, evaluate_fic_risk

GH = "https://token.actions.githubusercontent.com"
CUTOFF_PIN = "repo:o/r:ref:refs/heads/main"


@pytest.fixture
def dbenv(tmp_path):
    url = f"sqlite:///{tmp_path / 'nhi.db'}"
    engine = database.init(create=True, dburl=url)
    session = database.get_session(engine)
    yield session, url
    session.close()


def _graph(session):
    session.add(ServicePrincipal(
        objectId="sp-graph", appId="00000003-0000-0000-c000-000000000000",
        displayName="Microsoft Graph", servicePrincipalType="Application",
        microsoftFirstParty=True,
        appRoles=[
            {"id": "r-mail", "value": "Mail.Read"},
            {"id": "r-user", "value": "User.Read.All"},
            {"id": "r-rm", "value": "RoleManagement.ReadWrite.Directory"},
        ],
    ))


def _app_sp(session, n, **kw):
    session.add(ServicePrincipal(
        objectId=f"sp-{n}", appId=f"app-guid-{n}", displayName=f"App {n}",
        servicePrincipalType="Application", **kw))
    session.add(Application(objectId=f"app-{n}", appId=f"app-guid-{n}", displayName=f"App {n}"))


def _fic(session, n, **kw):
    base = dict(id=f"fic-{n}", applicationObjectId=f"app-{n}", appId=f"app-guid-{n}",
                name="f", issuer=GH, subject=CUTOFF_PIN)
    base.update(kw)
    session.add(FederatedIdentityCredential(**base))


def _marker(session, source, status, detail=None):
    session.add(NhiCollectionState(source=source, status=status, detail=detail, itemCount=0))


# ---- 1. evidence semantics -------------------------------------------------

def test_no_marker_no_rows_is_uncollected_never_false_zero(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    session.commit()
    s = analyze_nhi_posture(session)
    summ = s["summary"]
    assert summ["collectionStatus"] == "derived_from_legacy_db"
    assert summ["federatedCredentialsCollected"] is False
    assert summ["agentMetadataCollected"] is False
    assert summ["totalFederatedCredentials"] is None
    assert s["federatedCredentials"] == []
    assert s["workloads"][0]["federatedCredentialsCount"] is None
    assert summ["federatedCredentialsTablePresent"] is True


def test_marker_collected_with_zero_rows_is_true_zero(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _marker(session, "federatedCredentials", "collected")
    session.commit()
    s = analyze_nhi_posture(session)
    assert s["summary"]["collectionStatus"] == "collected"
    assert s["summary"]["totalFederatedCredentials"] == 0
    assert s["workloads"][0]["federatedCredentialsCount"] == 0


def test_marker_failed_ignores_partial_rows_and_exposes_detail(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    _marker(session, "federatedCredentials", "failed", "HTTP 403")
    _marker(session, "agentMetadata", "skipped", "--skip-nhi")
    session.commit()
    s = analyze_nhi_posture(session)
    summ = s["summary"]
    assert summ["collectionStatus"] == "derived_from_legacy_db"
    assert summ["totalFederatedCredentials"] is None
    assert summ["federatedCredentialsCollectionDetail"] == "HTTP 403"
    assert summ["agentMetadataCollectionDetail"] == "--skip-nhi"
    assert summ["agentMetadataCollected"] is False
    assert s["federatedCredentials"] == []
    assert any("federatedCredentials" in g for g in summ["dataGaps"])


def test_no_marker_rows_present_infers_collected(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    session.commit()
    s = analyze_nhi_posture(session)
    assert s["summary"]["collectionStatus"] == "collected"
    assert s["summary"]["totalFederatedCredentials"] == 1


def test_marker_table_missing_falls_back_to_row_inference(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    session.commit()
    session.execute(text("DROP TABLE NhiCollectionStates"))
    session.commit()
    s = analyze_nhi_posture(session)
    assert s["summary"]["federatedCredentialsCollected"] is True


def test_max_expiry_none_when_only_expired(dbenv):
    session, _ = dbenv
    _app_sp(session, 1, passwordCredentials=[
        {"keyId": "k", "startDate": "2020-01-01T00:00:00Z", "endDate": "2021-01-01T00:00:00Z"}])
    session.commit()
    w = analyze_nhi_posture(session)["workloads"][0]
    assert w["maxExpiryDays"] is None
    assert w["expiredCredentialsCount"] == 1


# ---- 2/3. tier0 and ownerless ---------------------------------------------

def test_delegated_scopes_are_not_tier0_but_count_for_m365(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    session.add(OAuth2PermissionGrant(
        objectId="g1", clientId="sp-1", resourceId="sp-graph",
        consentType="AllPrincipals", scope="Directory.ReadWrite.All Mail.Read"))
    session.commit()
    r = analyze_nhi_posture(session)
    assert r["summary"]["tier0PrivilegedNhIs"] == 0
    w = r["workloads"][0]
    assert w["tier0Roles"] == []
    assert "Directory.ReadWrite.All" in w["m365Scopes"] or "Mail.Read" in w["m365Scopes"]
    assert "Mail.Read" in w["m365Scopes"]
    assert not [f for f in r["findings"] if f["category"] == "WorkloadTier0Privilege"]


def test_ownerless_excludes_managed_identities(dbenv):
    session, _ = dbenv
    session.add(ServicePrincipal(
        objectId="sp-mi", appId="mi-guid", displayName="mi", servicePrincipalType="ManagedIdentity",
        managedIdentityResourceId="/subscriptions/s/resourcegroups/r/providers/Microsoft.Compute/virtualMachines/vm"))
    _app_sp(session, 1)
    session.commit()
    r = analyze_nhi_posture(session)
    assert r["summary"]["ownerlessNhIs"] == 1
    assert r["summary"]["totalManagedIdentities"] == 1


# ---- 4/5. FIC risk ----------------------------------------------------------

def _eval(**kw):
    base = {"id": "x", "issuer": GH, "subject": CUTOFF_PIN, "name": "n"}
    base.update(kw)
    return evaluate_fic_risk(base, "A")


def test_fic_claims_expression_string_open_is_critical():
    r = _eval(subject=None, claimsMatchingExpression="claims['sub'] matches '*'")
    assert r["riskLevel"] == "Critical"
    r = _eval(subject=None, claimsMatchingExpression="*")
    assert r["riskLevel"] == "Critical"


def test_fic_claims_expression_dict_open_is_critical_partial_is_high():
    r = _eval(subject=None, claimsMatchingExpression={"value": "claims['sub'] matches '*'", "languageVersion": 1})
    assert r["riskLevel"] == "Critical"
    r = _eval(subject=None, claimsMatchingExpression={
        "value": "claims['sub'] matches 'repo:o/r:ref:refs/heads/*'", "languageVersion": 1})
    assert r["riskLevel"] == "High"


def test_fic_expression_without_subject_constraint_is_critical():
    r = _eval(subject=None, claimsMatchingExpression={
        "value": "claims['repository_id'] eq '123'", "languageVersion": 1})
    assert r["riskLevel"] == "Critical"


def test_fic_literal_asterisk_subject_is_medium_with_reason():
    r = _eval(subject="repo:o/r:*")
    assert r["riskLevel"] == "Medium"
    assert any("literal asterisk" in x for x in r["riskReasons"])


def test_fic_unrecognised_https_issuer_is_medium_known_is_low():
    r = _eval(issuer="https://idp.evil.example/", subject="abc")
    assert r["riskLevel"] == "Medium"
    assert any("unrecognised issuer" in x for x in r["riskReasons"])
    for iss in ("https://oidc.eks.eu-west-1.amazonaws.com/id/ABC", "https://gitlab.com",
                "https://app.terraform.io", "https://accounts.google.com",
                "https://vstoken.dev.azure.com/tid", "https://container.googleapis.com/v1/x",
                "https://eastus.oic.prod-aks.azure.com/t/i/"):
        assert _eval(issuer=iss, subject="abc")["riskLevel"] == "Low", iss


def test_medium_fic_emits_finding(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1, issuer="https://idp.evil.example/", subject="abc")
    session.commit()
    r = analyze_nhi_posture(session)
    assert any(f["category"] == "FederatedCredentialTrust" and f["severity"] == "Medium"
               for f in r["findings"])


# ---- 6/7. typing and summary ------------------------------------------------

def test_first_party_with_secret_is_not_skipped_and_typed(dbenv):
    session, _ = dbenv
    session.add(ServicePrincipal(
        objectId="sp-fp", appId="fp-guid", displayName="MS thing", servicePrincipalType="Application",
        microsoftFirstParty=True,
        passwordCredentials=[{"keyId": "k", "startDate": "2030-01-01T00:00:00Z", "endDate": "2031-01-01T00:00:00Z"}]))
    _app_sp(session, 1)
    session.commit()
    ws = {w["objectId"]: w for w in analyze_nhi_posture(session)["workloads"]}
    assert ws["sp-fp"]["nhiType"] == "FirstPartyMicrosoft"
    assert ws["sp-fp"]["nhiCategory"] == "WorkloadApp"
    assert ws["sp-1"]["nhiType"] == "SingleTenantWorkloadApp"
    assert ws["sp-1"]["nhiCategory"] == "WorkloadApp"


def test_summary_severity_breakdown_and_top_findings(dbenv):
    session, _ = dbenv
    _graph(session)
    for n in range(1, 8):
        _app_sp(session, n)
        session.add(AppRoleAssignment(objectId=f"ar{n}", principalId=f"sp-{n}", resourceId="sp-graph", id="r-rm"))
    session.commit()
    summ = analyze_nhi_posture(session)["summary"]
    assert set(summ["severityBreakdown"]) == {"Critical", "High", "Medium", "Low", "Informational"}
    assert summ["severityBreakdown"]["Critical"] == 7
    assert len(summ["topFindings"]) == 5


def test_workload_role_buckets_and_agent_sponsor_names(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    dr = DirectoryRole(objectId="dr1", displayName="Global Administrator")
    session.add(dr)
    session.flush()
    sp1 = session.get(ServicePrincipal, "sp-1")
    sp1.memberOfRole.append(dr)
    _app_sp(session, 2)
    session.add(User(objectId="u1", userPrincipalName="boss@x.com", displayName="Boss"))
    session.add(AgentIdentityMetadata(objectId="sp-2", appId="app-guid-2", agentCategory="CustomAIAgent",
                                      executionMode="Interactive", sponsorUserIds=["u1"],
                                      collectionSource="msgraph_beta"))
    session.commit()
    r = analyze_nhi_posture(session)
    w = r["workloads"][0]
    assert w["directoryRoles"] == ["Global Administrator"]
    assert w["pimRoles"] == [] and w["azureRoles"] == []
    assert "Global Administrator" in w["privilegedRoles"]
    a = r["agents"][0]
    assert a["sponsorNames"] == ["boss@x.com"]
    assert a["ownerNames"] == []
    assert a["sponsorUserIds"] == ["u1"]


# ---- 10. execution mode -----------------------------------------------------

@pytest.mark.parametrize("role,expected", [("r-user", "Unknown"), ("r-mail", "Autonomous")])
def test_unknown_mode_only_autonomous_for_m365_or_tier0_roles(dbenv, role, expected):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1)
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Unknown", collectionSource="msgraph_beta"))
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id=role))
    session.commit()
    assert analyze_nhi_posture(session)["agents"][0]["executionMode"] == expected


# ---- 9. data gaps -----------------------------------------------------------

def test_missing_pim_tables_recorded_as_data_gap(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    session.commit()
    session.execute(text("DROP TABLE lnk_pim_roleassignment_subjectserviceprincipal"))
    session.commit()
    gaps = analyze_nhi_posture(session)["summary"]["dataGaps"]
    assert any(g.startswith("pimRoles unavailable") for g in gaps)


def test_tier0_app_roles_have_no_leading_space_entry():
    from roadtools.roadrecon.nhi_analyzer import TIER0_APP_ROLES
    assert all(r == r.strip() for r in TIER0_APP_ROLES)


# ---- 8. server cache --------------------------------------------------------

def test_server_cache_runs_analysis_once_per_db_state(dbenv, monkeypatch):
    import roadtools.roadrecon.server as server_mod
    session, _ = dbenv
    _app_sp(session, 1)
    session.commit()
    calls = []

    def counting(sess):
        calls.append(1)
        return analyze_nhi_posture(sess)

    monkeypatch.setattr(server_mod, "analyze_nhi_posture", counting)
    monkeypatch.setattr(server_mod, "db", types.SimpleNamespace(session=session))
    server_mod._nhi_report_cache.clear()
    server_mod.app.config["TESTING"] = True
    with server_mod.app.test_client() as c:
        for path in ("/api/nhi/summary", "/api/nhi/agents", "/api/nhi/workloads",
                     "/api/nhi/federatedcredentials", "/api/nhi/findings",
                     "/api/serviceprincipals/sp-1/nhi"):
            assert c.get(path).status_code == 200
        assert len(calls) == 1
        body = c.get("/api/nhi/summary").get_json()
        assert "severityBreakdown" in body and "topFindings" in body
        _app_sp(session, 2)
        session.commit()
        assert len(c.get("/api/nhi/workloads").get_json()) == 2
        assert len(calls) == 2
    server_mod._nhi_report_cache.clear()


# ---- review round 2 ---------------------------------------------------------

GL = "https://gitlab.com"


def _expr(value, issuer=GL):
    return _eval(issuer=issuer, subject=None,
                 claimsMatchingExpression={"value": value, "languageVersion": 1})


def _rank(level):
    return ["Low", "Medium", "High", "Critical"].index(level)


@pytest.mark.parametrize("value", [
    "claims['sub'] matches 'x' or true",
    "claims['sub'] eq 'a' or TRUE",
    "claims['sub'] != 'x'",
    "claims['sub'] ne 'x'",
    "not claims['sub'] eq 'x'",
    "claims['sub'] startswith ''",
    "claims['sub'] contains ''",
    "claims['sub'] endswith ''",
    "claims['sub'] startswith('')",
    "claims['sub']matches'*'",
    "claims['sub']   MATCHES   '**'",
    "claims[\"sub\"] matches \"*\"",
    "claims['sub'] matches '?*'",
    "claims['sub'] eq 'x' or 'a' eq 'a'",
])
def test_fic_open_expression_variants_are_critical(value):
    assert _expr(value)["riskLevel"] == "Critical", value


@pytest.mark.parametrize("value", [
    "claims['sub'] eq 'a' or claims['iss'] eq 'x'",
    "claims['sub'] eq 'a' OR claims['repository_id'] eq '1'",
    "claims['repository_id'] eq '1' or claims['sub'] eq 'a'",
])
def test_fic_or_combining_sub_with_other_clause_is_at_least_high(value):
    r = _expr(value)
    assert _rank(r["riskLevel"]) >= _rank("High"), value


@pytest.mark.parametrize("value", [
    "claims['sub'] eq 'a' xor claims['x'] eq 'b'",
    "claims['sub'] ~~ 'a'",
    "claims['sub'] eq 'a' and lower(claims['x']) eq 'b'",
])
def test_fic_unparseable_expression_is_at_least_medium_with_reason(value):
    r = _expr(value)
    assert _rank(r["riskLevel"]) >= _rank("Medium"), value
    assert any("unparseable expression, cannot confirm subject restriction" in x
               for x in r["riskReasons"]), value


def test_fic_well_formed_pinned_expression_stays_low():
    r = _expr("claims['sub'] eq 'a' and claims['project_id'] eq '9'")
    assert r["riskLevel"] == "Low"
    r = _expr("claims['sub']  eq  'a'  AND  claims['project_id'] eq '9'")
    assert r["riskLevel"] == "Low"


def test_fic_issuer_with_userinfo_is_unrecognised():
    r = _eval(issuer="https://evil.example@token.actions.githubusercontent.com", subject="abc")
    assert r["riskLevel"] == "Medium"
    assert any("unrecognised issuer" in x for x in r["riskReasons"])
    r = _eval(issuer="https://token.actions.githubusercontent.com@evil.example", subject="abc")
    assert r["riskLevel"] == "Medium"


# -- heuristic agent promotion (N3) / execution mode --

def _graph_copilot(session):
    session.add(ServicePrincipal(
        objectId="sp-copilot", appId="copilot-res", displayName="Copilot API",
        servicePrincipalType="Application", microsoftFirstParty=True,
        appRoles=[{"id": "r-cop", "value": "Copilot.Read.All"},
                  {"id": "r-ai", "value": "AiEnterpriseInteraction.Read.All"}]))


def test_delegated_copilot_grant_alone_does_not_promote_to_agent(dbenv):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1)
    session.add(OAuth2PermissionGrant(objectId="g", clientId="sp-1", resourceId="sp-graph",
                                      consentType="AllPrincipals", scope="Copilot.Read.All"))
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id="r-user"))
    session.commit()
    r = analyze_nhi_posture(session)
    assert r["agents"] == []
    assert [w["objectId"] for w in r["workloads"]] == ["sp-1"]


def test_app_role_copilot_promotes_autonomous_and_labelled_heuristic(dbenv):
    session, _ = dbenv
    _graph_copilot(session)
    _app_sp(session, 1)
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-copilot", id="r-cop"))
    session.commit()
    a = analyze_nhi_posture(session)["agents"][0]
    assert a["executionMode"] == "Autonomous"
    assert any("heuristic" in x.lower() for x in a["riskReasons"])


def test_heuristic_agent_delegated_write_scope_is_not_write_blast_radius(dbenv):
    session, _ = dbenv
    _graph_copilot(session)
    _app_sp(session, 1)
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-copilot", id="r-cop"))
    session.add(OAuth2PermissionGrant(objectId="g", clientId="sp-1", resourceId="sp-copilot",
                                      consentType="AllPrincipals", scope="Mail.ReadWrite"))
    session.commit()
    r = analyze_nhi_posture(session)
    agent = r["agents"][0]
    assert agent["executionMode"] == "Autonomous"
    # delegated scope stays informational, never a write-blast-radius finding
    assert "Mail.ReadWrite" in agent["m365Scopes"]
    assert not [f for f in r["findings"] if f["category"] == "AgentM365BlastRadius"]


def test_unknown_mode_tier0_role_is_autonomous(dbenv):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1)
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Unknown", collectionSource="msgraph_beta"))
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id="r-rm"))
    session.commit()
    assert analyze_nhi_posture(session)["agents"][0]["executionMode"] == "Autonomous"


def test_unknown_mode_delegated_m365_stays_unknown(dbenv):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1)
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Unknown", collectionSource="msgraph_beta"))
    session.add(OAuth2PermissionGrant(objectId="g", clientId="sp-1", resourceId="sp-graph",
                                      consentType="AllPrincipals", scope="Mail.Read"))
    session.commit()
    assert analyze_nhi_posture(session)["agents"][0]["executionMode"] == "Unknown"


# -- sponsors (N6) --

def _agent(session, n=1, sponsors=None):
    _app_sp(session, n)
    session.add(AgentIdentityMetadata(objectId=f"sp-{n}", appId=f"app-guid-{n}", agentCategory="CustomAIAgent",
                                      executionMode="Interactive", sponsorUserIds=sponsors or [],
                                      collectionSource="msgraph_beta"))


def test_placeholder_sponsor_does_not_count_as_owner(dbenv):
    session, _ = dbenv
    _agent(session, sponsors=["none"])
    session.commit()
    r = analyze_nhi_posture(session)
    a = r["agents"][0]
    assert a["ownersCount"] == 0 and a["sponsorsCount"] == 0
    assert a["unresolvedSponsors"] == ["none"]
    assert any(f["category"] == "AgentGovernance" for f in r["findings"])
    assert r["summary"]["ownerlessNhIs"] == 1


def test_resolvable_sponsor_counts_by_oid_or_upn(dbenv):
    session, _ = dbenv
    session.add(User(objectId="u1", userPrincipalName="boss@x.com", displayName="Boss"))
    _agent(session, 1, sponsors=["u1"])
    _agent(session, 2, sponsors=["boss@x.com"])
    session.commit()
    r = analyze_nhi_posture(session)
    for a in r["agents"]:
        assert a["ownersCount"] == 1 and a["sponsorsCount"] == 1 and a["unresolvedSponsors"] == []
        assert a["sponsorNames"] == ["boss@x.com"]
    assert not [f for f in r["findings"] if f["category"] == "AgentGovernance"]


def test_mixed_sponsors_only_resolved_count(dbenv):
    session, _ = dbenv
    session.add(User(objectId="u1", userPrincipalName="boss@x.com", displayName="Boss"))
    _agent(session, sponsors=["none", "u1", "ghost"])
    session.commit()
    a = analyze_nhi_posture(session)["agents"][0]
    assert a["sponsorsCount"] == 1 and a["ownersCount"] == 1
    assert a["unresolvedSponsors"] == ["none", "ghost"]


def test_sponsor_who_is_also_owner_counted_once(dbenv):
    session, _ = dbenv
    u = User(objectId="u1", userPrincipalName="boss@x.com", displayName="Boss")
    session.add(u)
    _agent(session, sponsors=["u1"])
    session.flush()
    sp1 = session.get(ServicePrincipal, "sp-1")
    sp1.ownerUsers.append(u)
    session.commit()
    a = analyze_nhi_posture(session)["agents"][0]
    assert a["ownersCount"] == 1


# -- delegated-only M365 must not drive workload findings (M3) --

def test_delegated_only_m365_with_secret_no_secret_finding_no_ownerless_bump(dbenv):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1, passwordCredentials=[
        {"keyId": "k", "startDate": "2026-10-01T00:00:00Z", "endDate": "2027-03-01T00:00:00Z"}])
    session.add(OAuth2PermissionGrant(objectId="g", clientId="sp-1", resourceId="sp-graph",
                                      consentType="AllPrincipals", scope="Mail.Read"))
    session.commit()
    r = analyze_nhi_posture(session)
    w = r["workloads"][0]
    assert "Mail.Read" in w["m365Scopes"]
    assert not [f for f in r["findings"] if f["id"].startswith("NHI-WORKLOAD-SECRET")]
    assert w["riskLevel"] == "Low"


def test_app_role_m365_with_secret_still_flagged(dbenv):
    session, _ = dbenv
    _graph(session)
    _app_sp(session, 1, passwordCredentials=[
        {"keyId": "k", "startDate": "2026-10-01T00:00:00Z", "endDate": "2027-03-01T00:00:00Z"}])
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id="r-mail"))
    session.commit()
    r = analyze_nhi_posture(session)
    assert [f for f in r["findings"] if f["id"].startswith("NHI-WORKLOAD-SECRET")]
    assert r["workloads"][0]["riskLevel"] == "High"


# -- owner relationship failures (data gaps) --

def test_missing_owner_link_table_records_data_gap_not_crash(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    session.commit()
    session.execute(text("DROP TABLE lnk_serviceprincipal_owner_user"))
    session.execute(text("DROP TABLE lnk_application_owner_user"))
    session.commit()
    r = analyze_nhi_posture(session)
    assert len(r["workloads"]) == 1
    assert any(g.startswith("owners unavailable") for g in r["summary"]["dataGaps"])


def test_summary_exposes_per_source_collection_status(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _marker(session, "federatedCredentials", "failed", "x")
    _marker(session, "agentMetadata", "collected")
    session.commit()
    s = analyze_nhi_posture(session)["summary"]
    assert s["federatedCredentialsCollectionStatus"] == "failed"
    assert s["agentMetadataCollectionStatus"] == "collected"
    assert s["collectionStatus"] == "derived_from_legacy_db"


# -- server routes (N2 and narrow exceptions) --

def _server(session, monkeypatch):
    import roadtools.roadrecon.server as server_mod
    monkeypatch.setattr(server_mod, "db", types.SimpleNamespace(session=session))
    server_mod._nhi_report_cache.clear()
    server_mod.app.config["TESTING"] = True
    return server_mod


def test_app_fic_route_hides_rows_when_source_not_collected(dbenv, monkeypatch):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    _marker(session, "federatedCredentials", "failed", "HTTP 403")
    session.commit()
    server_mod = _server(session, monkeypatch)
    with server_mod.app.test_client() as c:
        assert c.get("/api/applications/app-1/federatedcredentials").get_json() == []
        assert c.get("/api/nhi/summary").get_json()["federatedCredentialsCollected"] is False


def test_app_fic_route_returns_rows_when_collected(dbenv, monkeypatch):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    _marker(session, "federatedCredentials", "collected")
    session.commit()
    server_mod = _server(session, monkeypatch)
    with server_mod.app.test_client() as c:
        body = c.get("/api/applications/app-1/federatedcredentials").get_json()
        assert len(body) == 1 and body[0]["id"] == "fic-1"


def test_schema_getters_log_and_rollback_on_db_error_not_swallow_other_errors(dbenv, monkeypatch, caplog):
    from sqlalchemy.exc import OperationalError
    server_mod = _server(dbenv[0], monkeypatch)

    class Boom:
        @property
        def agentMetadata(self):
            raise OperationalError("select", {}, Exception("no such table"))

        @property
        def federatedIdentityCredentials(self):
            raise OperationalError("select", {}, Exception("no such table"))

    caplog.set_level("WARNING")
    assert server_mod.ServicePrincipalSchema().get_agent_metadata(Boom()) is None
    assert server_mod.ApplicationSchema().get_federated_credentials(Boom()) == []
    assert len(caplog.records) >= 2

    class Bug:
        @property
        def agentMetadata(self):
            raise ValueError("programming bug")

    with pytest.raises(ValueError):
        server_mod.ServicePrincipalSchema().get_agent_metadata(Bug())


# ---- round-4 fixes ------------------------------------------------------------

OWNER_TABLES = ("lnk_serviceprincipal_owner_user", "lnk_serviceprincipal_owner_serviceprincipal",
                "lnk_application_owner_user", "lnk_application_owner_serviceprincipal")


def _drop_owner_tables(session):
    for t in OWNER_TABLES:
        session.execute(text(f"DROP TABLE {t}"))
    session.commit()


def test_owner_tables_missing_owners_unknown_not_ownerless_and_fast(dbenv):
    from sqlalchemy import event
    session, _ = dbenv
    for n in range(300):
        _app_sp(session, n)
    _agent(session, 1000)
    session.commit()
    _drop_owner_tables(session)
    counter = []
    event.listen(session.get_bind(), "before_cursor_execute", lambda *a, **k: counter.append(1))
    r = analyze_nhi_posture(session)
    assert len(counter) < 200, len(counter)  # was ~5100 before the fix
    assert len(r["workloads"]) == 300
    assert all(w["ownersCount"] is None for w in r["workloads"])
    assert r["agents"][0]["ownersCount"] is None
    assert r["summary"]["ownerlessNhIs"] == 0
    assert not [f for f in r["findings"] if f["category"] == "AgentGovernance"]
    assert not any("No assigned application or service principal owner" in x
                   for w in r["workloads"] for x in w["riskReasons"])
    assert len([g for g in r["summary"]["dataGaps"] if g.startswith("owners unavailable")]) == 1


def test_owner_tables_missing_resolved_sponsor_still_counts(dbenv):
    session, _ = dbenv
    session.add(User(objectId="u1", userPrincipalName="boss@x.com", displayName="Boss"))
    _agent(session, 1, sponsors=["u1"])
    session.commit()
    _drop_owner_tables(session)
    a = analyze_nhi_posture(session)["agents"][0]
    assert a["ownersCount"] == 1


def test_github_leading_wildcard_sub_is_critical_pinned_org_is_high():
    for pat in ("*:ref:refs/heads/main", "repo:*", "*r*", "repo:*/x:ref:refs/heads/main"):
        r = _expr(f"claims['sub'] matches '{pat}'", issuer=GH)
        assert r["riskLevel"] == "Critical", pat
    r = _expr("claims['sub'] matches 'repo:myorg/*'", issuer=GH)
    assert r["riskLevel"] == "High"


def _graph_agent_autonomous(session, delegated=None):
    _graph(session)
    session.add(ServicePrincipal(objectId="sp-1", appId="app-guid-1", displayName="Ag",
                                 servicePrincipalType="Application"))
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Autonomous", sponsorUserIds=[],
                                      collectionSource="msgraph_beta"))
    if delegated:
        session.add(OAuth2PermissionGrant(objectId="g", clientId="sp-1", resourceId="sp-graph",
                                          consentType="AllPrincipals", scope=delegated))
    session.commit()


def test_agent_delegated_only_write_scope_no_m365write_finding(dbenv):
    session, _ = dbenv
    _graph_agent_autonomous(session, delegated="Mail.ReadWrite")
    r = analyze_nhi_posture(session)
    assert not [f for f in r["findings"] if f["category"] == "AgentM365BlastRadius"]
    assert "Mail.ReadWrite" in r["agents"][0]["m365Scopes"]


def test_agent_app_role_write_scope_still_m365write_finding(dbenv):
    session, _ = dbenv
    session.add(ServicePrincipal(objectId="sp-graph", appId="g", displayName="Graph",
                                 appRoles=[{"id": "r-send", "value": "Mail.Send"}]))
    session.add(ServicePrincipal(objectId="sp-1", appId="app-guid-1", displayName="Ag"))
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Autonomous", sponsorUserIds=[],
                                      collectionSource="msgraph_beta"))
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id="r-send"))
    session.commit()
    f = [f for f in analyze_nhi_posture(session)["findings"] if f["category"] == "AgentM365BlastRadius"]
    assert len(f) == 1 and f[0]["severity"] == "Critical"


def test_sponsor_upn_matches_case_insensitively_objectid_exact(dbenv):
    session, _ = dbenv
    session.add(User(objectId="abc-1", userPrincipalName="Boss@X.com", displayName="Boss"))
    _agent(session, 1, sponsors=["boss@x.COM"])
    _agent(session, 2, sponsors=["ABC-1"])
    session.commit()
    by = {a["objectId"]: a for a in analyze_nhi_posture(session)["agents"]}
    assert by["sp-1"]["sponsorsCount"] == 1
    assert by["sp-2"]["sponsorsCount"] == 0


def test_collected_marker_without_table_is_uncollected_with_gap(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    _marker(session, "federatedCredentials", "collected")
    session.commit()
    session.execute(text("DROP TABLE FederatedIdentityCredentials"))
    session.commit()
    s = analyze_nhi_posture(session)["summary"]
    assert s["federatedCredentialsCollected"] is False
    assert s["totalFederatedCredentials"] is None
    assert any(g.startswith("federatedCredentials not collected") for g in s["dataGaps"])


def test_k8s_default_namespace_in_sub_eq_expression_is_high():
    r = _expr("claims['sub'] eq 'system:serviceaccount:default:x'", issuer="https://x.oic.prod-aks.azure.com/t/")
    assert any("default" in x and "namespace" in x for x in r["riskReasons"])
    assert _rank(r["riskLevel"]) >= _rank("High")


def test_parenthesised_wildcard_expression_is_critical():
    for v in ("(claims['sub'] matches '*')", "((claims['sub'] matches '*'))"):
        assert _expr(v)["riskLevel"] == "Critical", v


def test_app_schema_fics_gated_on_collection_state(dbenv, monkeypatch):
    session, _ = dbenv
    _app_sp(session, 1)
    _fic(session, 1)
    _marker(session, "federatedCredentials", "failed", "x")
    session.commit()
    server_mod = _server(session, monkeypatch)
    app_row = session.get(Application, "app-1")
    assert server_mod.ApplicationSchema().get_federated_credentials(app_row) == []
    with server_mod.app.test_client() as c:
        assert c.get("/api/applications/app-1").get_json()["federatedIdentityCredentials"] == []
    state = session.query(NhiCollectionState).one()
    state.status = "collected"
    session.commit()
    assert len(server_mod.ApplicationSchema().get_federated_credentials(app_row)) == 1


def test_agent_metadata_not_collected_adds_gap_and_orphan_caveat(dbenv):
    session, _ = dbenv
    session.add(ServicePrincipal(objectId="sp-graph", appId="g", displayName="Graph",
                                 appRoles=[{"id": "c1", "value": "Copilot.Read.All"}]))
    session.add(ServicePrincipal(objectId="sp-1", appId="app-guid-1", displayName="Ag"))
    session.add(AppRoleAssignment(objectId="ar", principalId="sp-1", resourceId="sp-graph", id="c1"))
    session.commit()
    r = analyze_nhi_posture(session)
    assert r["agents"], "heuristic agent expected"
    assert ("agent sponsor data unavailable: agentMetadata not collected; "
            "ownerless/orphan counts for agents are an upper bound") in r["summary"]["dataGaps"]
    orphan = [f for f in r["findings"] if f["category"] == "AgentGovernance"]
    assert orphan and all("upper bound" in f["detail"] for f in orphan)
    assert any("heuristically" in x for x in r["agents"][0]["riskReasons"])


def test_agent_meta_row_with_heuristic_source_gets_heuristic_reason(dbenv):
    session, _ = dbenv
    _app_sp(session, 1)
    session.add(AgentIdentityMetadata(objectId="sp-1", appId="app-guid-1", agentCategory="CustomAIAgent",
                                      executionMode="Interactive", sponsorUserIds=[],
                                      collectionSource="heuristic"))
    _marker(session, "agentMetadata", "collected")
    session.commit()
    a = analyze_nhi_posture(session)["agents"][0]
    assert any("heuristically" in x for x in a["riskReasons"])


def test_sp_nhi_route_emits_agent_metadata_collection_fields(dbenv, monkeypatch):
    session, _ = dbenv
    _app_sp(session, 1)
    _marker(session, "agentMetadata", "failed", "HTTP 403")
    session.commit()
    server_mod = _server(session, monkeypatch)
    with server_mod.app.test_client() as c:
        b = c.get("/api/serviceprincipals/sp-1/nhi").get_json()
    assert b["appId"] == "app-guid-1" and b["displayName"] == "App 1"
    assert b["agentMetadataCollected"] is False
    assert b["agentMetadataCollectionDetail"] == "HTTP 403"
