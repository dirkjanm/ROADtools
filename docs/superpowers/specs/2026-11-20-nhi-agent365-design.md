# NHI, Agentic AI, M365 & Agent 365 Feature Design Specification

**Date:** 2026-11-20
**Project:** ROADtools / ROADrecon
**Status:** Proposed for User Review

## 1. Overview & Goals

Extend `roadlib` and `roadrecon` (collector, SQLite schema, Flask backend, and Angular 22 GUI) to collect, classify, score, and visualize **Non-Human Identities (NHIs)**, **Agentic AI / Entra Agent IDs**, **Microsoft 365 Copilot / Agent 365** declarative and autonomous agents, **Managed Identities**, and **Federated Identity Credentials (FICs)**.

### Key Objectives
1. **MS Graph Beta Collector Phase (`gather.py`):** Extend `roadrecon gather` with a Microsoft Graph `v1.0`/`beta` collection phase (`--nhi` / automatic when MS Graph token or refresh token is available) that collects:
   - `applications/{id}/federatedIdentityCredentials` (OIDC workload federation for GitHub Actions, Kubernetes, AWS, GCP, Azure DevOps, custom issuers).
   - Entra Agent ID, Agent 365, and Copilot Studio metadata on `servicePrincipals` and `applications` (blueprint IDs, autonomous vs. interactive execution modes, sponsor users, M365/Graph/MCP scopes).
2. **Normalized SQLAlchemy Tables (`database.py`):**
   - `FederatedIdentityCredential` (`FederatedIdentityCredentials`) linked to `Application.objectId`.
   - `AgentIdentityMetadata` (`AgentIdentityMetadatas`) linked to `ServicePrincipal.objectId`.
   - Non-destructive table creation (`Base.metadata.create_all`) so older `roadrecon.db` files open cleanly without crashing and preserve evidence semantics (`collectionState`: `"collected"` vs `"uncollected"`).
3. **Deterministic NHI, Agent 365 & M365 Blast-Radius Engine (`nhi_analyzer.py` + `server.py`):**
   - Classify non-human identities into `Agent365`, `CopilotStudio`, `M365DeclarativeAgent`, `EntraAgentId`, `ManagedIdentity` (System vs. User-Assigned), `WorkloadApp`, and `FirstPartyMicrosoft`.
   - Map M365 data blast radius (`Mail.*`, `Files.*`, `Sites.*`, `Chat.*`, `ChannelMessage.*`, `Calendars.*`, `People.*`, `AiEnterpriseInteraction.*`, `Copilot.*`) and Tier-0 Entra/Azure privileges (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`, Directory Roles, PIM assignments, Azure RBAC Owner/Contributor/User Access Admin).
   - Produce deterministic risk findings with explicit severity weights (`Critical` = 4, `High` = 3, `Medium` = 2, `Low` = 1, `Informational` = 0).
4. **Angular 22 Frontend (`NhiComponent` + Enriched Dialogs):**
   - Top-level sidenav link **NHI & Agent 365** (`/nhi`) with 4 tabs:
     1. *Overview & Risk Findings*
     2. *Agent 365 & AI Agents*
     3. *Managed Identities & Workloads*
     4. *Federated Credentials (OIDC)*
   - Enriched tabs inside `ApplicationsdialogComponent` (*Federated Credentials & NHI Risk*) and `ServicePrincipalsdialogComponent` (*Agent 365 & NHI Posture*).

## 2. Guardrails & Evidence Semantics

1. **Preserve Evidence Semantics:** Do not convert uncollected MS Graph beta tables into confirmed-empty arrays without surfacing collection status. API responses include `collectionStatus` (`"collected"` when MS Graph NHI collection ran, `"derived_from_legacy_db"` when evaluating an existing AAD Graph database without MS Graph FIC/Agent beta collection) and return `$null`/`None` for uncollected metrics rather than false zeroes where applicable.
2. **Offline Validation First:** All backend classification, risk scoring, and unit/integration tests must run offline against SQLite fixtures without requiring live Microsoft Graph or tenant access.
3. **Severity Ordering:** Map findings using explicit severity weights: `Critical` (4), `High` (3), `Medium` (2), `Low` (1), `Informational` (0).
4. **Keep NgModule Architecture:** All new Angular 22 components use `standalone: false` and are declared in `AppmainModule`.

## 3. Data Model (`roadlib/roadtools/roadlib/metadef/database.py`)

### 3.1 `FederatedIdentityCredential`
- `__tablename__ = "FederatedIdentityCredentials"`
- `id = Column(Text, primary_key=True)`
- `applicationObjectId = Column(Text, ForeignKey("Applications.objectId"), index=True)`
- `appId = Column(Text)`
- `name = Column(Text)`
- `issuer = Column(Text)`
- `subject = Column(Text)`
- `description = Column(Text)`
- `audiences = Column(JSON)`
- `claimsMatchingExpression = Column(JSON)`
- `application = relationship("Application", back_populates="federatedIdentityCredentials")`

### 3.2 `AgentIdentityMetadata`
- `__tablename__ = "AgentIdentityMetadatas"`
- `objectId = Column(Text, ForeignKey("ServicePrincipals.objectId"), primary_key=True)`
- `appId = Column(Text)`
- `agentCategory = Column(Text)` — `'Agent365' | 'CopilotStudio' | 'M365DeclarativeAgent' | 'EntraAgentId' | 'AzureAIAgent' | 'CustomAIAgent'`
- `executionMode = Column(Text)` — `'Autonomous' | 'Interactive' | 'Hybrid' | 'Unknown'`
- `blueprintId = Column(Text)`
- `sponsorUserIds = Column(JSON)`
- `m365Scopes = Column(JSON)`
- `mcpTools = Column(JSON)`
- `collectionSource = Column(Text)` — `'msgraph_beta' | 'heuristic'`
- `rawMetadata = Column(JSON)`
- `servicePrincipal = relationship("ServicePrincipal", back_populates="agentMetadata", uselist=False)`

## 4. API Contract (`roadrecon/roadtools/roadrecon/server.py`)

- `GET /api/nhi/summary`:
  Returns KPI counts, `collectionStatus`, severity breakdown, and top findings.
- `GET /api/nhi/agents`:
  Returns list of classified AI Agents / Agent 365 / Copilot Studio / M365 agents with execution mode, M365 scopes, Graph app roles, oauth2 delegations, sponsors/owners, and risk badges.
- `GET /api/nhi/workloads`:
  Returns Managed Identities (System-Assigned, User-Assigned) and Workload Service Principals with credential hygiene (secrets, certs, FIC count, max expiry days), backing resource ID, Entra/PIM/Azure RBAC roles, and risk level.
- `GET /api/nhi/federatedcredentials`:
  Returns all `FederatedIdentityCredential` records joined with `Application` display name and trust risk analysis (e.g., wildcard subject `*`, missing branch/environment restriction on GitHub Actions `repo:*`, unverified custom issuer).
- `GET /api/nhi/findings`:
  Returns all deterministic NHI & Agent 365 security findings ordered by `severityWeight` descending (`4` to `0`).
