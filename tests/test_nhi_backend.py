import pytest
import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import (
    Application,
    ServicePrincipal,
    FederatedIdentityCredential,
    AgentIdentityMetadata,
)


def test_nhi_models_persist_and_relate(tmp_path):
    db_file = tmp_path / "test_nhi.db"
    engine = database.init(create=True, dburl=f"sqlite:///{db_file}")
    session = database.get_session(engine)

    app = Application(
        objectId="app-obj-1",
        appId="11111111-2222-3333-4444-555555555555",
        displayName="Contoso Agent 365 Builder",
    )
    fic = FederatedIdentityCredential(
        id="fic-1",
        applicationObjectId="app-obj-1",
        appId="11111111-2222-3333-4444-555555555555",
        name="github-deploy",
        issuer="https://token.actions.githubusercontent.com",
        subject="repo:contoso/agent365:*",
        description="GitHub Actions wildcard",
        audiences=["api://AzureADTokenExchange"],
        claimsMatchingExpression=None,
    )
    sp = ServicePrincipal(
        objectId="sp-obj-1",
        appId="11111111-2222-3333-4444-555555555555",
        displayName="Contoso Agent 365 Builder",
        servicePrincipalType="Application",
    )
    meta = AgentIdentityMetadata(
        objectId="sp-obj-1",
        appId="11111111-2222-3333-4444-555555555555",
        agentCategory="Agent365",
        executionMode="Autonomous",
        blueprintId="bp-agent365-01",
        sponsorUserIds=["user-1"],
        m365Scopes=["Mail.ReadWrite", "Files.ReadWrite.All"],
        mcpTools=["sharepoint-connector"],
        collectionSource="msgraph_beta",
        rawMetadata={"agentVersion": "2.0"},
    )

    session.add_all([app, fic, sp, meta])
    session.commit()

    loaded_app = session.query(Application).filter_by(objectId="app-obj-1").one()
    assert len(loaded_app.federatedIdentityCredentials) == 1
    assert loaded_app.federatedIdentityCredentials[0].issuer == "https://token.actions.githubusercontent.com"
    fic_dict = loaded_app.federatedIdentityCredentials[0].as_dict()
    assert fic_dict["id"] == "fic-1"
    assert fic_dict["applicationObjectId"] == "app-obj-1"
    assert fic_dict["audiences"] == ["api://AzureADTokenExchange"]

    loaded_sp = session.query(ServicePrincipal).filter_by(objectId="sp-obj-1").one()
    assert loaded_sp.agentMetadata is not None
    assert loaded_sp.agentMetadata.agentCategory == "Agent365"
    assert loaded_sp.agentMetadata.executionMode == "Autonomous"
    meta_dict = loaded_sp.agentMetadata.as_dict()
    assert meta_dict["blueprintId"] == "bp-agent365-01"
    assert meta_dict["m365Scopes"] == ["Mail.ReadWrite", "Files.ReadWrite.All"]
    assert meta_dict["mcpTools"] == ["sharepoint-connector"]
    session.close()


def test_extract_agent_metadata_from_sp_identifies_agent365_and_copilot():
    from roadtools.roadrecon.gather import extract_agent_metadata_from_sp

    sp_raw = {
        "id": "sp-agent-1",
        "appId": "aaaa1111-bbbb-2222-cccc-333333333333",
        "displayName": "Sales Order Autonomous Agent 365",
        "servicePrincipalType": "AgentIdentity",
        "tags": ["Agent365", "CopilotStudio", "AutonomousAgent"],
        "verifiedPublisher": {"displayName": "Microsoft Corporation"},
        "appMetadata": {
            "data": [
                {"key": "AgentBlueprintId", "value": "bp-99"},
                {"key": "ExecutionMode", "value": "Autonomous"},
                {"key": "SponsorUserIds", "value": "user-1,user-2"},
                {"key": "M365Scopes", "value": "Mail.ReadWrite,Files.Read.All"},
                {"key": "McpTools", "value": '["erp-connector", "crm-tool"]'},
            ]
        },
    }
    meta = extract_agent_metadata_from_sp(sp_raw)
    assert meta is not None
    assert meta["objectId"] == "sp-agent-1"
    assert meta["agentCategory"] in ("Agent365", "EntraAgentId")
    assert meta["executionMode"] == "Autonomous"
    assert meta["blueprintId"] == "bp-99"
    assert meta["sponsorUserIds"] == ["user-1", "user-2"]
    assert "Mail.ReadWrite" in meta["m365Scopes"]
    assert meta["mcpTools"] == ["erp-connector", "crm-tool"]

    # Non-agent regular service principal returns None
    normal_sp = {
        "id": "sp-normal-1",
        "appId": "bbbb1111-bbbb-2222-cccc-333333333333",
        "displayName": "Standard Payroll Portal",
        "servicePrincipalType": "Application",
        "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
    }
    assert extract_agent_metadata_from_sp(normal_sp) is None


def test_store_federated_credentials_and_agent_metadata_and_dumper(tmp_path):
    import asyncio
    from roadtools.roadrecon.gather import (
        DataDumper,
        store_agent_metadata,
        store_federated_credentials_batch,
    )

    db_file = tmp_path / "test_gather_fic.db"
    engine = database.init(create=True, dburl=f"sqlite:///{db_file}")
    session = database.get_session(engine)
    session.add(Application(objectId="app-1", appId="app-guid-1", displayName="DeployApp"))
    session.add(
        ServicePrincipal(
            objectId="sp-1",
            appId="app-guid-1",
            displayName="M365 Declarative Copilot Assistant",
            servicePrincipalType="Application",
            tags=["M365Copilot", "DeclarativeAgent"],
        )
    )
    session.commit()

    fics_payload = [
        {
            "id": "fic-guid-1",
            "name": "k8s-prod",
            "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E",
            "subject": "system:serviceaccount:prod:agent-runner",
            "description": "EKS workload identity",
            "audiences": ["api://AzureADTokenExchange"],
        }
    ]
    store_federated_credentials_batch(session, "app-1", "app-guid-1", fics_payload)
    session.commit()

    saved = session.query(FederatedIdentityCredential).filter_by(id="fic-guid-1").one()
    assert saved.applicationObjectId == "app-1"
    assert saved.subject == "system:serviceaccount:prod:agent-runner"

    # Test DataDumper.dump_nhi_msgraph heuristic + mocked MS Graph beta responses
    class FakeResponse:
        def __init__(self, status, payload):
            self.status = status
            self._payload = payload

        async def read(self):
            return b""

        async def json(self):
            return self._payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        def get(self, url, headers=None):
            if "/beta/applications" in url:
                return FakeResponse(
                    200,
                    {
                        "value": [
                            {
                                "id": "app-1",
                                "appId": "app-guid-1",
                                "displayName": "DeployApp",
                                "federatedIdentityCredentials": [
                                    {
                                        "id": "fic-guid-2",
                                        "name": "gh-actions",
                                        "issuer": "https://token.actions.githubusercontent.com",
                                        "subject": "repo:contoso/app:ref:refs/heads/main",
                                        "audiences": ["api://AzureADTokenExchange"],
                                    }
                                ],
                            }
                        ]
                    },
                )
            if "/beta/servicePrincipals" in url:
                return FakeResponse(
                    200,
                    {
                        "value": [
                            {
                                "id": "sp-1",
                                "appId": "app-guid-1",
                                "displayName": "M365 Declarative Copilot Assistant",
                                "servicePrincipalType": "AgentIdentity",
                                "tags": ["Agent365", "Autonomous"],
                            }
                        ]
                    },
                )
            return FakeResponse(404, {})

    dumper = DataDumper("tenant-1", "1.61-internal", ahsession=FakeSession(), engine=engine, session=session)
    # First run without msgraph_headers -> heuristic only
    asyncio.run(dumper.dump_nhi_msgraph(msgraph_headers=None))
    heuristic_meta = session.get(AgentIdentityMetadata, "sp-1")
    assert heuristic_meta is not None
    assert heuristic_meta.collectionSource == "heuristic"
    assert heuristic_meta.agentCategory == "M365DeclarativeAgent"

    # Second run with msgraph_headers -> upgrades to msgraph_beta and stores fic-guid-2
    asyncio.run(dumper.dump_nhi_msgraph(msgraph_headers={"Authorization": "Bearer fake"}))
    beta_meta = session.get(AgentIdentityMetadata, "sp-1")
    assert beta_meta.collectionSource == "msgraph_beta"
    assert beta_meta.agentCategory == "Agent365"
    assert session.get(FederatedIdentityCredential, "fic-guid-2") is not None
    session.close()


def test_evaluate_fic_risk_checks_wildcards_github_k8s_and_pinned():
    from roadtools.roadrecon.nhi_analyzer import evaluate_fic_risk

    # 1. Critical wildcard subject
    crit_fic = {
        "id": "fic-crit",
        "applicationObjectId": "app-1",
        "appId": "guid-1",
        "name": "wildcard-subj",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:contoso/app:*",
        "audiences": ["api://AzureADTokenExchange"],
    }
    res_crit = evaluate_fic_risk(crit_fic, "AppOne")
    assert res_crit["riskLevel"] == "Critical"
    assert res_crit["severityWeight"] == 4

    # 2. Critical HTTP issuer
    http_fic = {
        "id": "fic-http",
        "applicationObjectId": "app-1",
        "appId": "guid-1",
        "name": "http-issuer",
        "issuer": "http://insecure.issuer.local",
        "subject": "system:serviceaccount:prod:runner",
    }
    res_http = evaluate_fic_risk(http_fic, "AppOne")
    assert res_http["riskLevel"] == "Critical"
    assert res_http["severityWeight"] == 4

    # 3. High GitHub Actions pull_request trigger
    gh_pr_fic = {
        "id": "fic-gh-pr",
        "applicationObjectId": "app-1",
        "appId": "guid-1",
        "name": "gh-pr",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:contoso/app:pull_request",
    }
    res_gh_pr = evaluate_fic_risk(gh_pr_fic, "AppOne")
    assert res_gh_pr["riskLevel"] == "High"
    assert res_gh_pr["severityWeight"] == 3

    # 4. High Kubernetes default namespace
    k8s_def_fic = {
        "id": "fic-k8s-def",
        "applicationObjectId": "app-1",
        "appId": "guid-1",
        "name": "k8s-default",
        "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/123",
        "subject": "system:serviceaccount:default:my-sa",
    }
    res_k8s = evaluate_fic_risk(k8s_def_fic, "AppOne")
    assert res_k8s["riskLevel"] == "High"
    assert res_k8s["severityWeight"] == 3

    # 5. Low pinned OIDC subject
    low_fic = {
        "id": "fic-low",
        "applicationObjectId": "app-1",
        "appId": "guid-1",
        "name": "gh-prod",
        "issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:contoso/app:ref:refs/heads/main",
    }
    res_low = evaluate_fic_risk(low_fic, "AppOne")
    assert res_low["riskLevel"] == "Low"
    assert res_low["severityWeight"] == 1


def test_analyze_nhi_posture_and_flask_endpoints_and_legacy_db(tmp_path):
    from sqlalchemy import text
    from flask_sqlalchemy import SQLAlchemy
    import roadtools.roadrecon.server as server_mod
    from roadtools.roadrecon.nhi_analyzer import analyze_nhi_posture
    from roadtools.roadlib.metadef.database import (
        AppRoleAssignment,
        DirectoryRole,
        OAuth2PermissionGrant,
    )

    db_file = tmp_path / "test_analyzer.db"
    db_url = f"sqlite:///{db_file}"
    engine = database.init(create=True, dburl=db_url)
    session = database.get_session(engine)

    msgraph_sp = ServicePrincipal(
        objectId="sp-msgraph",
        appId="00000003-0000-0000-c000-000000000000",
        displayName="Microsoft Graph",
        servicePrincipalType="Application",
        microsoftFirstParty=True,
        appRoles=[
            {"id": "role-mail-rw", "value": "Mail.ReadWrite", "displayName": "Read and write mail in all mailboxes"},
            {"id": "role-rolemgmt", "value": "RoleManagement.ReadWrite.Directory", "displayName": "Read and write all directory RBAC settings"},
        ],
    )
    agent_sp = ServicePrincipal(
        objectId="sp-agent365-1",
        appId="22222222-3333-4444-5555-666666666666",
        displayName="M365 Finance Copilot Agent 365",
        servicePrincipalType="Application",
        accountEnabled=True,
        tags=["Agent365", "M365Copilot", "Autonomous"],
        passwordCredentials=[{"keyId": "k1", "startDate": "2024-01-01T00:00:00Z", "endDate": "2029-01-01T00:00:00Z"}],
    )
    agent_app = Application(
        objectId="app-agent365-1",
        appId="22222222-3333-4444-5555-666666666666",
        displayName="M365 Finance Copilot Agent 365",
        availableToOtherTenants=True,
    )
    bad_fic = FederatedIdentityCredential(
        id="fic-wildcard-1",
        applicationObjectId="app-agent365-1",
        appId="22222222-3333-4444-5555-666666666666",
        name="unrestricted-github",
        issuer="https://token.actions.githubusercontent.com",
        subject="repo:contoso/finance:*",
        audiences=["api://AzureADTokenExchange"],
    )
    ar1 = AppRoleAssignment(
        objectId="ar-1",
        principalId="sp-agent365-1",
        resourceId="sp-msgraph",
        id="role-mail-rw",
    )
    ar2 = AppRoleAssignment(
        objectId="ar-2",
        principalId="sp-agent365-1",
        resourceId="sp-msgraph",
        id="role-rolemgmt",
    )
    oauth_grant = OAuth2PermissionGrant(
        objectId="grant-1",
        clientId="sp-agent365-1",
        resourceId="sp-msgraph",
        consentType="AllPrincipals",
        scope="Files.ReadWrite.All Chat.ReadWrite",
    )
    mi_sp = ServicePrincipal(
        objectId="sp-mi-1",
        appId="77777777-8888-9999-aaaa-bbbbbbbbbbbb",
        displayName="prod-aks-agentpool-mi",
        servicePrincipalType="ManagedIdentity",
        accountEnabled=True,
        managedIdentityResourceId="/subscriptions/sub-1/resourcegroups/rg-prod/providers/Microsoft.Compute/virtualMachineScaleSets/aks-pool",
    )
    uami_sp = ServicePrincipal(
        objectId="sp-uami-1",
        appId="88888888-8888-9999-aaaa-bbbbbbbbbbbb",
        displayName="prod-uami-identity",
        servicePrincipalType="ManagedIdentity",
        accountEnabled=True,
        alternativeNames=["isExplicit=True"],
        managedIdentityResourceId="/subscriptions/sub-1/resourcegroups/rg-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/prod-uami",
    )
    dir_role = DirectoryRole(
        objectId="dr-ga",
        displayName="Global Administrator",
        description="Full access",
    )
    mi_sp.memberOfRole.append(dir_role)

    session.add_all([msgraph_sp, agent_sp, agent_app, bad_fic, ar1, ar2, oauth_grant, mi_sp, uami_sp, dir_role])
    session.commit()

    report = analyze_nhi_posture(session)
    assert report["summary"]["collectionStatus"] == "collected"
    assert report["summary"]["federatedCredentialsTablePresent"] is True
    assert report["summary"]["agentMetadataTablePresent"] is True
    assert report["summary"]["totalAgents"] == 1
    assert report["summary"]["totalAutonomousAgents"] == 1
    assert report["summary"]["totalManagedIdentities"] == 2
    assert report["summary"]["totalSystemManagedIdentities"] == 1
    assert report["summary"]["totalUserAssignedManagedIdentities"] == 1
    assert report["summary"]["totalFederatedCredentials"] == 1
    assert report["summary"]["tier0PrivilegedNhIs"] == 2
    assert report["summary"]["criticalFindingsCount"] >= 3

    agent_entry = report["agents"][0]
    assert agent_entry["agentCategory"] == "Agent365"
    assert agent_entry["executionMode"] == "Autonomous"
    assert "Mail.ReadWrite" in agent_entry["m365Scopes"]
    assert "Files.ReadWrite.All" in agent_entry["m365Scopes"]
    assert "RoleManagement.ReadWrite.Directory" in agent_entry["tier0Roles"]

    weights = [f["severityWeight"] for f in report["findings"]]
    assert weights == sorted(weights, reverse=True)
    assert weights[0] == 4

    # Test Flask endpoints
    server_mod.app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    server_mod.app.config["TESTING"] = True
    server_mod.db = SQLAlchemy(server_mod.app)

    with server_mod.app.test_client() as client:
        r_sum = client.get("/api/nhi/summary")
        assert r_sum.status_code == 200
        assert r_sum.get_json()["totalAgents"] == 1

        r_agents = client.get("/api/nhi/agents")
        assert r_agents.status_code == 200
        assert len(r_agents.get_json()) == 1

        r_workloads = client.get("/api/nhi/workloads")
        assert r_workloads.status_code == 200
        assert len(r_workloads.get_json()) == 2

        r_fics = client.get("/api/nhi/federatedcredentials")
        assert r_fics.status_code == 200
        assert len(r_fics.get_json()) == 1

        r_findings = client.get("/api/nhi/findings")
        assert r_findings.status_code == 200
        assert len(r_findings.get_json()) >= 3

        r_app_fics = client.get("/api/applications/app-agent365-1/federatedcredentials")
        assert r_app_fics.status_code == 200
        app_fics_data = r_app_fics.get_json()
        assert len(app_fics_data) == 1
        assert app_fics_data[0]["riskLevel"] == "Critical"

        r_sp_nhi = client.get("/api/serviceprincipals/sp-agent365-1/nhi")
        assert r_sp_nhi.status_code == 200
        sp_nhi_data = r_sp_nhi.get_json()
        assert sp_nhi_data["isAgent"] is True
        assert sp_nhi_data["agent"]["agentCategory"] == "Agent365"
        assert len(sp_nhi_data["federatedCredentials"]) == 1

        # Verify Application detail and ServicePrincipal detail include new schema fields
        r_app_detail = client.get("/api/applications/app-agent365-1")
        assert r_app_detail.status_code == 200
        assert len(r_app_detail.get_json()["federatedIdentityCredentials"]) == 1

    # Simulate legacy DB by dropping FederatedIdentityCredentials and AgentIdentityMetadatas tables
    session.execute(text("DROP TABLE FederatedIdentityCredentials"))
    session.execute(text("DROP TABLE AgentIdentityMetadatas"))
    session.commit()

    legacy_report = analyze_nhi_posture(session)
    assert legacy_report["summary"]["collectionStatus"] == "derived_from_legacy_db"
    assert legacy_report["summary"]["federatedCredentialsTablePresent"] is False
    assert legacy_report["summary"]["agentMetadataTablePresent"] is False
    assert legacy_report["summary"]["totalAgents"] == 1
    assert legacy_report["summary"]["totalManagedIdentities"] == 2
    session.close()


