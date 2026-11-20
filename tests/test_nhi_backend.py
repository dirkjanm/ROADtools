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

