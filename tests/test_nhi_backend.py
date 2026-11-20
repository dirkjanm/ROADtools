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
