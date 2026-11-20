# NHI, Agentic AI, M365 & Agent 365 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full-stack support for Non-Human Identities (NHI), Entra Agent IDs, M365 Copilot / Agent 365 agents, Managed Identities, and Federated Identity Credentials (FICs) across `roadlib`, `roadrecon gather`, Flask API, and the Angular 22 frontend.

**Architecture:** We extend `roadlib.metadef.database` with `FederatedIdentityCredential` and `AgentIdentityMetadata` SQLAlchemy models, add an async MS Graph `v1.0`/`beta` collection phase in `roadrecon/gather.py`, implement a deterministic offline-capable classification and risk engine in `roadrecon/nhi_analyzer.py` exposed via `/api/nhi/*` routes in `roadrecon/server.py`, and build the Angular 22 `NhiComponent` (`/nhi`) plus enriched tabs in `ApplicationsdialogComponent` and `ServicePrincipalsdialogComponent`.

**Tech Stack:** Python 3, SQLAlchemy, aiohttp, Flask, Marshmallow, pytest, Angular 22 (NgModule architecture with `standalone: false`), Angular Material 22, TypeScript 6.

**Spec:** `docs/superpowers/specs/2026-11-20-nhi-agent365-design.md`

## Global Constraints

- Preserve evidence semantics: distinguish uncollected MS Graph beta tables (`collectionStatus: "derived_from_legacy_db"`, `federatedCredentialsCollected: false`) from confirmed-empty sets (`collectionStatus: "collected"`, `federatedCredentialsCollected: true`).
- Severity ordering weights: `Critical = 4`, `High = 3`, `Medium = 2`, `Low = 1`, `Informational = 0`.
- Offline validation first: automated pytest tests must run offline against in-memory/temp SQLite fixtures without requiring live Microsoft Graph or tenant credentials.
- Angular 22 components must use `standalone: false` and be registered in `AppmainModule`; use `<mat-chip-set>` and `<mat-chip>` (never `<mat-chip-list>`).

---

### Task 1: Database Schema Extensions (`FederatedIdentityCredential` & `AgentIdentityMetadata`)

**Files:**
- Modify: `roadlib/roadtools/roadlib/metadef/database.py`
- Create: `tests/test_nhi_backend.py`

**Interfaces:**
- Produces:
  - `FederatedIdentityCredential` model in `roadtools.roadlib.metadef.database` (`id`, `applicationObjectId`, `appId`, `name`, `issuer`, `subject`, `description`, `audiences`, `claimsMatchingExpression`, `application` relationship; `Application.federatedIdentityCredentials` back_populates)
  - `AgentIdentityMetadata` model in `roadtools.roadlib.metadef.database` (`objectId`, `appId`, `agentCategory`, `executionMode`, `blueprintId`, `sponsorUserIds`, `m365Scopes`, `mcpTools`, `collectionSource`, `rawMetadata`, `servicePrincipal` relationship; `ServicePrincipal.agentMetadata` back_populates)

- [ ] **Step 1: Write the failing database model test in `tests/test_nhi_backend.py`**

```python
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

    loaded_sp = session.query(ServicePrincipal).filter_by(objectId="sp-obj-1").one()
    assert loaded_sp.agentMetadata is not None
    assert loaded_sp.agentMetadata.agentCategory == "Agent365"
    assert loaded_sp.agentMetadata.executionMode == "Autonomous"
    session.close()
```

- [ ] **Step 2: Run pytest to verify the test fails**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: FAIL with `ImportError: cannot import name 'FederatedIdentityCredential'`

- [ ] **Step 3: Add `FederatedIdentityCredential` and `AgentIdentityMetadata` models and relationships to `roadlib/roadtools/roadlib/metadef/database.py`**

Add the relationships on `ServicePrincipal` (`agentMetadata = relationship("AgentIdentityMetadata", back_populates="servicePrincipal", uselist=False)`) and `Application` (`federatedIdentityCredentials = relationship("FederatedIdentityCredential", back_populates="application")`), and define `FederatedIdentityCredential` and `AgentIdentityMetadata` classes in `roadlib/roadtools/roadlib/metadef/database.py`.

- [ ] **Step 4: Run pytest to verify the test passes**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: PASS

---

### Task 2: MS Graph Collector Phase for FICs & Agent 365 Metadata (`gather.py`)

**Files:**
- Modify: `roadrecon/roadtools/roadrecon/gather.py`
- Modify: `tests/test_nhi_backend.py`

**Interfaces:**
- Consumes: `FederatedIdentityCredential`, `AgentIdentityMetadata`, `Application`, `ServicePrincipal` from `roadtools.roadlib.metadef.database`
- Produces:
  - `extract_agent_metadata_from_sp(sp_dict: dict) -> dict | None` in `roadtools.roadrecon.gather`
  - `DataDumper.dump_federated_credentials(msgraph_headers: dict)` in `roadtools.roadrecon.gather`
  - `DataDumper.dump_agent_metadata(msgraph_headers: dict)` in `roadtools.roadrecon.gather`
  - `--skip-nhi` CLI argument in `getargs(gather_parser)`

- [ ] **Step 1: Add unit tests in `tests/test_nhi_backend.py` for MS Graph FIC & Agent 365 ingestion**

```python
import asyncio
from roadtools.roadrecon.gather import extract_agent_metadata_from_sp, store_federated_credentials_batch


def test_extract_agent_metadata_from_sp_identifies_agent365_and_copilot():
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
            ]
        },
    }
    meta = extract_agent_metadata_from_sp(sp_raw)
    assert meta is not None
    assert meta["objectId"] == "sp-agent-1"
    assert meta["agentCategory"] in ("Agent365", "EntraAgentId")
    assert meta["executionMode"] == "Autonomous"


def test_store_federated_credentials_batch_persists_records(tmp_path):
    db_file = tmp_path / "test_gather_fic.db"
    engine = database.init(create=True, dburl=f"sqlite:///{db_file}")
    session = database.get_session(engine)
    session.add(Application(objectId="app-1", appId="app-guid-1", displayName="DeployApp"))
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
    session.close()
```

- [ ] **Step 2: Run pytest to verify the new collector tests fail**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: FAIL with `ImportError: cannot import name 'extract_agent_metadata_from_sp'`

- [ ] **Step 3: Implement `extract_agent_metadata_from_sp`, `store_federated_credentials_batch`, and async MS Graph beta collection in `roadrecon/roadtools/roadrecon/gather.py`**

Add helper functions and `DataDumper.dump_nhi_msgraph` in `roadrecon/roadtools/roadrecon/gather.py`, plus `--skip-nhi` in `getargs`. When `token` has a `refreshToken` and `--autotoken` is set (or token audience is MS Graph), automatically exchange for `https://graph.microsoft.com` to query `/beta/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials` and `/beta/servicePrincipals` agent metadata; otherwise run heuristic extraction from collected service principals without failing the gather run.

- [ ] **Step 4: Run pytest to verify the collector tests pass**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: PASS

---

### Task 3: NHI, Agentic AI & M365 Classification + Risk Scoring Engine (`nhi_analyzer.py` & `server.py`)

**Files:**
- Create: `roadrecon/roadtools/roadrecon/nhi_analyzer.py`
- Modify: `roadrecon/roadtools/roadrecon/server.py`
- Modify: `tests/test_nhi_backend.py`

**Interfaces:**
- Consumes: `Application`, `ServicePrincipal`, `FederatedIdentityCredential`, `AgentIdentityMetadata`, `AppRoleAssignment`, `OAuth2PermissionGrant`, `DirectoryRole`, `PIMgovernanceRoleAssignment`, `AZroleAssignment` from `roadtools.roadlib.metadef.database`
- Produces:
  - `analyze_nhi_posture(dbsession) -> dict` in `roadtools.roadrecon.nhi_analyzer` returning keys: `summary`, `agents`, `workloads`, `federatedCredentials`, `findings`
  - Flask endpoints in `roadtools.roadrecon.server`:
    - `GET /api/nhi/summary`
    - `GET /api/nhi/agents`
    - `GET /api/nhi/workloads`
    - `GET /api/nhi/federatedcredentials`
    - `GET /api/nhi/findings`

- [ ] **Step 1: Add unit and Flask API endpoint tests in `tests/test_nhi_backend.py`**

```python
from roadtools.roadrecon.nhi_analyzer import analyze_nhi_posture
from roadtools.roadlib.metadef.database import AppRoleAssignment, OAuth2PermissionGrant, DirectoryRole


def test_analyze_nhi_posture_scores_agents_fics_and_workloads(tmp_path):
    db_file = tmp_path / "test_analyzer.db"
    engine = database.init(create=True, dburl=f"sqlite:///{db_file}")
    session = database.get_session(engine)

    # MS Graph Resource SP holding high-privilege appRoles
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
    # Autonomous Agent 365 SP with Mail.ReadWrite + RoleManagement.ReadWrite.Directory and no owner
    agent_sp = ServicePrincipal(
        objectId="sp-agent365-1",
        appId="22222222-3333-4444-5555-666666666666",
        displayName="M365 Finance Copilot Agent 365",
        servicePrincipalType="Application",
        accountEnabled=True,
        tags=["Agent365", "M365Copilot"],
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
    # Managed Identity
    mi_sp = ServicePrincipal(
        objectId="sp-mi-1",
        appId="77777777-8888-9999-aaaa-bbbbbbbbbbbb",
        displayName="prod-aks-agentpool-mi",
        servicePrincipalType="ManagedIdentity",
        accountEnabled=True,
        managedIdentityResourceId="/subscriptions/sub-1/resourcegroups/rg-prod/providers/Microsoft.Compute/virtualMachineScaleSets/aks-pool",
    )

    session.add_all([msgraph_sp, agent_sp, agent_app, bad_fic, ar1, ar2, mi_sp])
    session.commit()

    report = analyze_nhi_posture(session)
    assert report["summary"]["totalAgents"] >= 1
    assert report["summary"]["totalManagedIdentities"] == 1
    assert report["summary"]["totalFederatedCredentials"] == 1
    assert report["summary"]["criticalFindingsCount"] >= 2

    # Check severity ordering descending (4 = Critical first)
    weights = [f["severityWeight"] for f in report["findings"]]
    assert weights == sorted(weights, reverse=True)
    assert weights[0] == 4
    session.close()
```

- [ ] **Step 2: Run pytest to verify the analyzer test fails**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'roadtools.roadrecon.nhi_analyzer'`

- [ ] **Step 3: Implement `roadrecon/roadtools/roadrecon/nhi_analyzer.py` and wire `/api/nhi/*` endpoints in `roadrecon/roadtools/roadrecon/server.py`**

Implement `analyze_nhi_posture(dbsession)` in `nhi_analyzer.py`:
- Inspect table existence via `sqlalchemy.inspect(dbsession.bind)` so legacy SQLite DBs without `FederatedIdentityCredentials` or `AgentIdentityMetadatas` tables do not throw `OperationalError`, and set `collectionStatus` accurately.
- Classify Agent 365 / Copilot Studio / M365 Declarative Agents / Entra Agent IDs via `AgentIdentityMetadata` or deterministic indicators (`servicePrincipalType`, `tags`, `displayName`, `appMetadata`, M365 Graph/Copilot scopes).
- Classify Managed Identities (System vs. User-Assigned via `servicePrincipalType == 'ManagedIdentity'`, `managedIdentityResourceId`, `alternativeNames`) and Workload Service Principals.
- Evaluate Federated Identity Credentials for wildcard subjects (`*`), unrestricted GitHub Actions subjects, and non-standard issuers.
- Score findings with `severityWeight` (`Critical`: 4, `High`: 3, `Medium`: 2, `Low`: 1, `Informational`: 0).
- Add routes `/api/nhi/summary`, `/api/nhi/agents`, `/api/nhi/workloads`, `/api/nhi/federatedcredentials`, and `/api/nhi/findings` in `server.py` (ensuring `Base.metadata.create_all(db.engine)` is called safely or table inspection handles missing tables).

- [ ] **Step 4: Run pytest across `tests/test_nhi_backend.py`**

Run: `pytest tests/test_nhi_backend.py -v`
Expected: PASS

---

### Task 4: Angular 22 Frontend — `NhiComponent` (`/nhi`) & Dialog Integrations

**Files:**
- Modify: `roadrecon/frontend/src/app/appmain/aadobjects.service.ts`
- Create: `roadrecon/frontend/src/app/appmain/nhi/nhi.component.ts`
- Create: `roadrecon/frontend/src/app/appmain/nhi/nhi.component.html`
- Create: `roadrecon/frontend/src/app/appmain/nhi/nhi.component.less`
- Modify: `roadrecon/frontend/src/app/appmain/appmain.module.ts`
- Modify: `roadrecon/frontend/src/app/appmain/app-routing.module.ts`
- Modify: `roadrecon/frontend/src/app/appnav/appnav.component.html`
- Modify: `roadrecon/frontend/src/app/appmain/applications/applicationsdialog/applicationsdialog.component.ts`
- Modify: `roadrecon/frontend/src/app/appmain/applications/applicationsdialog/applicationsdialog.component.html`
- Modify: `roadrecon/frontend/src/app/appmain/serviceprincipals/serviceprincipalsdialog/serviceprincipalsdialog.component.ts`
- Modify: `roadrecon/frontend/src/app/appmain/serviceprincipals/serviceprincipalsdialog/serviceprincipalsdialog.component.html`

**Interfaces:**
- Consumes:
  - `GET /api/nhi/summary`
  - `GET /api/nhi/agents`
  - `GET /api/nhi/workloads`
  - `GET /api/nhi/federatedcredentials`
  - `GET /api/nhi/findings`
- Produces:
  - TypeScript interfaces in `aadobjects.service.ts`: `NhiSummary`, `NhiAgentItem`, `NhiWorkloadItem`, `FederatedCredentialItem`, `NhiFindingItem`
  - `DatabaseService` methods: `getNhiSummary()`, `getNhiAgents()`, `getNhiWorkloads()`, `getNhiFederatedCredentials()`, `getNhiFindings()`
  - `NhiComponent` (`selector: 'app-nhi'`, `standalone: false`) routed at `/nhi` and linked in `appnav.component.html`

- [ ] **Step 1: Add NHI & Agent 365 TypeScript interfaces and `DatabaseService` methods in `aadobjects.service.ts`**

Add strongly typed interfaces (`NhiSummary`, `NhiAgentItem`, `NhiWorkloadItem`, `FederatedCredentialItem`, `NhiFindingItem`) and HTTP methods to `DatabaseService` in `roadrecon/frontend/src/app/appmain/aadobjects.service.ts`.

- [ ] **Step 2: Create `NhiComponent` (`nhi.component.ts`, `nhi.component.html`, `nhi.component.less`) and register in `AppmainModule`, `AppRoutingModule`, and `appnav.component.html`**

Build the 4-tab Material interface (`Overview & Risk Findings`, `Agent 365 & AI Agents`, `Managed Identities & Workloads`, `Federated Credentials`) with search filtering, sorting, pagination, severity chips (`<mat-chip-set>`), collection-status banner, and router links to `/serviceprincipals/:id` and `/applications/:id`.

- [ ] **Step 3: Add Federated Credentials & Agent 365 posture tabs to `ApplicationsdialogComponent` and `ServicePrincipalsdialogComponent`**

Display associated Federated Identity Credentials in `applicationsdialog.component.html` and Agent 365 / M365 scopes + NHI risk findings in `serviceprincipalsdialog.component.html`.

- [ ] **Step 4: Build Angular frontend and verify zero compilation errors**

Run: `cd C:\Dev\roadtools\roadrecon\frontend && npm run build`
Expected: Exit code 0 with zero TypeScript or Angular template errors; restore `dist_gui/.gitkeep` files if needed.
