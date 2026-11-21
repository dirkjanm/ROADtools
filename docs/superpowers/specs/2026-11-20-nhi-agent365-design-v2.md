# NHI, Agentic AI, M365 & Agent 365 Feature Design Specification (v2)

**Date:** 2026-11-20
**Project:** ROADtools / ROADrecon
**Status:** Implemented on `feat/nhi-agent365-posture` (rev label `NHI-Agent365 Rev1`); not pushed. Collector and analyzer checked against the Newport test tenant; browser re-smoke PASS (headless Edge + Playwright, offline synthetic fixture), full gather still pending. A review-gate fix pass (2026-11-20 ~15:42 PST) addressed a BLOCK verdict with five fixes and four new regression tests. The in-repo adversarial sub-agent review gate was re-run by an independent agent; final verdict **APPROVE_WITH_FOLLOWUPS** (all prior issues resolved, no new defects; the low-severity `sponsorsError` follow-up fixed).
**Supersedes:** `2026-11-20-nhi-agent365-design.md` (kept unchanged; v1 is historical)

v2 keeps the v1 goals and adds the mechanisms v1 left implicit: stored collection state, field-level API contract, CLI precedence, explicit decisions, and a Required / Optional / Deferred mark on every item.

Legend: **Required** = must be true for the feature to be correct. **Optional** = implemented, but removing it would not break the contract. **Deferred** = deliberately not built; see section 9.
The remaining live and browser verification limits are listed in section 10.

## 1. Overview & Goals

Extend `roadlib` and `roadrecon` (collector, SQLite schema, Flask backend, Angular GUI) to collect, classify, score and visualise Non-Human Identities (NHIs): Entra Agent IDs, Agent 365, Copilot Studio and M365 declarative agents, managed identities, workload app registrations, and federated identity credentials (FICs).

| # | Objective | Mark |
|---|---|---|
| G1 | MS Graph beta collection phase in `gather.py` for FICs and agent metadata | Required |
| G2 | Normalised tables `FederatedIdentityCredentials`, `AgentIdentityMetadatas`, `NhiCollectionStates` | Required |
| G3 | Offline deterministic classifier and risk engine (`nhi_analyzer.py`) | Required |
| G4 | `/api/nhi/*` routes plus two per-object routes | Required |
| G5 | Angular `NhiComponent` at `/nhi` with 4 tabs, enriched application and service principal dialogs | Required |
| G6 | Application-side agent metadata collection (`/beta/applications`) | Deferred |
| G7 | `Informational` (weight 0) findings | Deferred (never emitted) |

## 2. Guardrails & Evidence Semantics

1. **Uncollected is not empty (Required).** A source that was skipped, failed or never run must never be reported as a confirmed-empty set. The mechanism is the `NhiCollectionStates` table (section 3.3), not table existence: the collector always creates the tables, so existence proves nothing.
2. **Partial data is never trusted (Required).** A source that fails mid-pagination is `failed`; rows already written are kept on disk but the analyzer ignores FIC rows unless the source state is `collected`, and the collector does not prune stale rows on failure.
3. **Offline validation first (Required).** All classification, scoring and state logic runs against SQLite fixtures without Microsoft Graph or tenant access.
4. **Severity ordering (Required).** `Critical`=4, `High`=3, `Medium`=2, `Low`=1, `Informational`=0. Lists are sorted by `severityWeight` descending.
5. **NgModule architecture (Required).** New Angular components use `standalone: false` and are declared in `AppmainModule`; `<mat-chip-set>`/`<mat-chip>`, never `<mat-chip-list>`.
6. **Legacy databases open cleanly (Required).** Missing NHI tables, missing PIM/Azure tables, missing link tables are detected through `sqlalchemy.inspect` and recorded in `dataGaps`; no `OperationalError` reaches the client.
7. **Analysis runs once per DB state (Required).** All `/api/nhi/*` routes share one cached `analyze_nhi_posture` result (section 6.5).
8. **Agent source gating (Required).** `msgraph_beta` agent rows are honoured only when the `agentMetadata` source state is `collected`; when it is `failed`, `skipped` or `uncollected`, only `collectionSource='heuristic'` rows are used (sections 4.2 and 6.1). Agents are handled in the agent branch and are not also counted as ownerless in the workload branch.
9. **Sponsor lookup failure is unknown ownership (Required).** A failed `/sponsors` GET must not clear previously known `sponsorUserIds` and must not be reported as "no owner". The row carries `sponsorsError` and the source detail is marked; the analyzer adds a `dataGaps` entry "sponsor lookup failed for agent <id>; ownership treated as unknown", suppresses the orphan finding, does not escalate the M365 write finding to Critical, and does not count the agent as ownerless.
10. **Blueprint principals are templates, not running agents (Required).** `agentIdentityBlueprintPrincipal` rows are retained in the agents list (so `totalAgents` is unchanged) but do not produce the "Orphaned AI agent" finding and do not increment `ownerlessNhIs`; a risk reason "Agent identity blueprint template (not a running agent)" is emitted instead.

## 3. Data Model (`roadlib/roadtools/roadlib/metadef/database.py`)

### 3.1 `FederatedIdentityCredential` (table `FederatedIdentityCredentials`) - Required
`id` (PK, Text), `applicationObjectId` (FK `Applications.objectId`, indexed), `appId`, `name`, `issuer`, `subject`, `description`, `audiences` (JSON), `claimsMatchingExpression` (JSON). Relationship `application` / `Application.federatedIdentityCredentials`.

### 3.2 `AgentIdentityMetadata` (table `AgentIdentityMetadatas`) - Required
`objectId` (PK, FK `ServicePrincipals.objectId`), `appId`, `agentCategory`, `executionMode`, `blueprintId`, `sponsorUserIds` (JSON), `m365Scopes` (JSON), `mcpTools` (JSON), `collectionSource`, `rawMetadata` (JSON). Relationship `servicePrincipal` / `ServicePrincipal.agentMetadata`.

Exact value sets:

| Field | Values (exactly these) |
|---|---|
| `agentCategory` | `Agent365`, `EntraAgentId`, `CopilotStudio`, `M365DeclarativeAgent`, `AzureAIAgent`, `CustomAIAgent` |
| `executionMode` | `Autonomous`, `Interactive`, `Hybrid`, `Unknown` |
| `collectionSource` | `msgraph_beta`, `heuristic` |

### 3.3 `NhiCollectionState` (table `NhiCollectionStates`) - Required
Per-source outcome of the MS Graph NHI phase.

| Column | Type | Meaning |
|---|---|---|
| `source` (PK) | Text | `federatedCredentials` or `agentMetadata` |
| `status` | Text | `collected`, `skipped`, `failed`, `uncollected` |
| `detail` | Text, nullable | Human-readable reason (HTTP status, exception, skip reason) |
| `itemCount` | Integer | Items seen in this run (FIC ids, or agent SP ids) |
| `collectedAt` | Text | UTC ISO-8601 timestamp of the write |

State meanings:

| Status | Written when | Analyzer treats as |
|---|---|---|
| `collected` | Every page fetched with 2xx; stale rows pruned; may legitimately have `itemCount` 0. `detail` may read `N skipped: parent object not in local DB` when FICs for applications absent from the AAD-Graph dump were skipped (FK safety) | Confirmed (zero is a true zero) |
| `skipped` | `--skip-nhi`, or no MS Graph token obtainable | Unknown |
| `failed` | HTTP error after retries, exception, malformed/partial pagination, foreign nextLink, page cap, or a DB error while storing or pruning items (session rolled back, state still recorded; confirmed in code) | Unknown; FIC rows ignored; `detail` surfaced |
| `uncollected` | Never written by the collector; the analyzer's fallback when there is no marker and no rows | Unknown |

**Who writes:** only `gather.py` (`record_nhi_state`, `mark_nhi_skipped`), as an upsert (`session.merge` + commit). It is a no-op when the table does not exist. **Who reads:** only `nhi_analyzer.analyze_nhi_posture`.

**Fallback when no marker exists (legacy DB or marker table missing):** rows present in the source table imply `collected`; no rows imply `uncollected`. A marker, when present with a recognised status, always wins.

## 4. Collection (`gather.py`)

### 4.1 CLI flags - Required (`--skip-nhi`), Optional (`--nhi`)

| Flag | Effect |
|---|---|
| `--skip-nhi` | Skip the whole NHI phase; writes `skipped` for both sources. Takes precedence over everything. |
| `--nhi` | Force the MS Graph token exchange when a refresh token is present, even without `--autotoken`. |
| `--autotoken` (existing) | Also triggers the exchange when a refresh token is present. |
| `--evade`, `-ua/--user-agent` (existing) | NHI Graph requests must keep working under `--evade` (the `BatchSession` wrapper bypasses the AAD-Graph `$batch` rewrite for `graph.microsoft.com`) and send the configured user agent (confirmed: `acquire_msgraph_headers(..., user_agent=)` adds `User-Agent` to the Graph headers). |

NHI-phase precedence: `--skip-nhi` > a supplied MS Graph audience token (used as-is) > refresh-token exchange with `--nhi` or `--autotoken` > no token (sources marked `skipped`). The normal `roadrecon gather` CLI rejects a non-AAD-Graph access token before reaching this phase unless `--autotoken` can obtain its AAD Graph token.

### 4.2 Automatic collection rule - Required
Collection happens automatically when either:
1. the supplied access token already has audience `https://graph.microsoft.com` (with or without trailing slash) or `00000003-0000-0000-c000-000000000000`; or
2. the token has a refresh token and `--nhi` or `--autotoken` is given (exchange for the Graph resource).

Otherwise: heuristic agent detection only, message printed, both sources marked `skipped`. The gather run never fails because of NHI collection.

### 4.3 Sources
| Source | Endpoint | Notes | Mark |
|---|---|---|---|
| `federatedCredentials` | `GET https://graph.microsoft.com/beta/applications?$select=id,appId,displayName&$expand=federatedIdentityCredentials` | Paged. FKs to `Applications` require the AAD-Graph application dump to have run. | Required |
| `agentMetadata` | `GET https://graph.microsoft.com/beta/servicePrincipals` | **No `$select`** (default properties) until the property set is verified against a live payload. | Required |
| Application-side agent metadata | `/beta/applications` | See section 9 | Deferred |

### 4.4 Fetch behaviour - Required
- Retry on 429/500/502/503/504, max 3 attempts, honour `Retry-After` (capped at 60 s), else exponential back-off.
- Any non-retryable HTTP error, exception or incomplete pagination raises an internal `NhiFetchError`; the source is marked `failed` and the **other source still runs**.
- `@odata.nextLink` must be on host `graph.microsoft.com` over https; a foreign host or non-https scheme is rejected as a failure before the link is requested, so the bearer token is not sent (confirmed in code). A repeating nextLink fails the source, and a page cap of 10000 is enforced (confirmed).
- Stale rows (FICs not seen; `msgraph_beta` agent rows not seen) are pruned **only** after a fully successful source. Heuristic agent rows are never pruned by Graph success.

### 4.5 Heuristic agent detection - Required
Runs over collected service principals before the Graph phase, writes `collectionSource='heuristic'` rows, never overwrites `msgraph_beta` rows, and removes stale heuristic rows when the classifier no longer matches. Only structured fields classify an SP as an agent: `tags`, `servicePrincipalType`, `appMetadata` keys. Display name, notes and SPNs never do. `executionMode` comes only from an explicit metadata field or a tag exactly equal to `autonomous`/`interactive`/`hybrid`.

## 5. Classification and Scoring (`nhi_analyzer.py`)

### 5.1 Vocabulary - Required
| Output field | Exact values |
|---|---|
| `workloads[].nhiType` | `SystemManagedIdentity`, `UserAssignedManagedIdentity`, `SingleTenantWorkloadApp`, `MultiTenantWorkloadApp`, `FirstPartyMicrosoft` |
| `workloads[].nhiCategory` | `ManagedIdentity`, `WorkloadApp` |
| `agents[].agentCategory` / `executionMode` | as section 3.2 |
| severity | `Critical`, `High`, `Medium`, `Low`, `Informational` |
| `collectionStatus` | `collected`, `derived_from_legacy_db` |

Note: v1 listed `FirstPartyMicrosoft` and `WorkloadApp` as categories; v2 states they are `nhiType` and `nhiCategory` values respectively.

### 5.2 Decisions
| # | Decision | Rationale / source | Mark |
|---|---|---|---|
| D1 | A **literal `*` in a plain FIC `subject`** is **Medium**, not Critical/High. | Microsoft Learn: standard federated credentials compare subject exactly; wildcards exist only via flexible FICs using `claimsMatchingExpression`. A literal asterisk is a likely misconfiguration, not an open trust. The GitHub branch/environment check is skipped for it. | Required |
| D2 | `claimsMatchingExpression` that matches every subject (e.g. `claims['sub'] matches '*'`) is Critical; an expression not referencing `sub` is Critical; one referencing `sub` with `*` is High. Hardened detection of these forms. | Flexible FIC semantics | Required |
| D3 | **Unrecognised issuer** (https but host not on the allowlist) = **Medium**. Non-https or missing issuer = Critical. | Allowlist: GitHub Actions, Azure DevOps, Google, AWS EKS, AKS OIDC, Entra/STS, GitLab, Terraform Cloud, CircleCI, Bitbucket. Matched on parsed hostname, not substring. | Required |
| D4 | GitHub Actions subject trusting `pull_request`, or lacking branch/tag/environment constraint = High. Kubernetes `default` namespace = High. | | Required |
| D5 | **Sponsors count toward ownership only when resolved to a known user** in the `Users` table; unresolved sponsor ids do not satisfy the ownerless check. | An id that maps to nobody is not accountability | Required |
| D6 | **Delegated scopes do not trigger secret/ownerless findings, Tier-0, or app-only M365 write findings.** Tier-0 derives from application permissions (app roles) and roles only. Delegated scopes remain visible for context. | Delegated rights are bounded by the signed-in user | Required |
| D7 | **Heuristic agent promotion** (no metadata, no structured signals) only from **app-role** `AiEnterpriseInteraction.*`/`Copilot.*` scopes, not delegated ones; promoted as `M365DeclarativeAgent`. | Avoid labelling every Copilot-consuming app an agent | Required |
| D8 | `Informational` (weight 0) is **reserved and never emitted**. It stays in `SEVERITY_WEIGHTS` and the summary counter (`informationalFindingsCount`, always 0). | No rule yet produces a weight-0 finding | Deferred |
| D9 | Unknown `executionMode` is promoted to `Autonomous` only when the agent holds an app role that is an M365 data scope or Tier-0. | App-only access acts without a user | Required |
| D10 | Managed identities are excluded from the ownerless count. Unprivileged first-party Microsoft SPs without credentials/FICs are skipped; first-party SPs with secrets, Tier-0 or FICs are kept and typed `FirstPartyMicrosoft`. | | Required |
| D11 | Role data is kept in separate buckets: `directoryRoles` (active), `pimRoles`, `azureRoles`; `tier0Roles` is the union of Tier-0 app roles, Tier-0 directory roles and Tier-0 Azure roles. | Evidence separation | Required |
| D12 | A **blueprint principal** (`agentIdentityBlueprintPrincipal`) is retained in the agents list/counts (`totalAgents` unchanged) but produces **no "Orphaned AI agent" finding** and does **not** increment `ownerlessNhIs`; it emits the risk reason "Agent identity blueprint template (not a running agent)". | A template is not a running agent; the false positive was fixed in the review-gate fix pass (previously accepted as a known limitation). | Required |
| D13 | A **failed `/sponsors` lookup** (`sponsorsError`) is an **unknown-ownership** state, not "no owner": previously known `sponsorUserIds` are preserved across the `msgraph_beta` merge and are not cleared on failure. Add `dataGaps` entry "sponsor lookup failed for agent <id>; ownership treated as unknown"; suppress the orphan finding, do not escalate the M365 write finding to Critical, and do not count the agent as ownerless. | Absence of evidence is not evidence of absence; a lookup failure must not be silently graded as a governance or privilege failure. | Required |
| D14 | `msgraph_beta` agent rows are used only when the `agentMetadata` source state is `collected`; for `failed`/`skipped`/`uncollected` only `collectionSource='heuristic'` rows are used. An agent is never additionally counted as ownerless in the workload branch. | Matches FIC gating and sections 4.2 / 6.1; avoids double-counting and over-claiming from partial agent data. | Required |

### 5.3 Findings catalogue (categories) - Required
`FederatedCredentialTrust` (FIC risk >= Medium), `AgentTier0Privilege` (Critical), `AgentM365BlastRadius` (Critical if no owner/sponsor else High; autonomous + write/send/manage scopes), `AgentGovernance` (orphaned agent: High if autonomous else Medium), `AgentMultiTenancy` (High), `WorkloadTier0Privilege` (Critical), `CredentialHygiene` (High: privileged workload with static secrets; Medium: expired or >365-day credentials).

## 6. API Contract (`server.py`)

All routes are `GET`, JSON. Lists are sorted by `severityWeight` descending, then name, then id. Nullable fields: "null" means *unknown because the source was not collected*, never zero.

### 6.1 `collectionStatus` semantics - Required
- `collectionStatus` is **FIC-only**: `collected` iff the `federatedCredentials` source state is `collected`, else `derived_from_legacy_db`. It does **not** describe agent metadata.
- Per-source flags `federatedCredentialsCollected` and `agentMetadataCollected` (booleans) report each source; `federatedCredentialsCollectionDetail` / `agentMetadataCollectionDetail` carry the stored `detail` (nullable); `federatedCredentialsTablePresent` / `agentMetadataTablePresent` report schema presence only.
- **None-vs-0:** `totalFederatedCredentials` and per-item `federatedCredentialsCount` are `null` when FICs are not collected, `0` only when collected and empty. FIC rows are returned only when collected.
- `agentMetadataCollected=false` means agents are heuristic-only; agent counts are then a lower bound.
- `dataGaps` (array of strings, empty when complete) lists every reason a number may be incomplete: FIC/agent source not collected (with state), PIM tables missing, Azure RBAC tables missing, eager-loading fallback, directory/PIM/Azure role read failures, sponsor-name lookup failure, and sponsor lookup failure (`sponsorsError`: "sponsor lookup failed for agent <id>; ownership treated as unknown").

### 6.2 `GET /api/nhi/summary`
| Field | Type | Nullable | Meaning |
|---|---|---|---|
| `totalNhIs` | int | no | agents + workloads listed |
| `totalAgents` | int | no | `agents` length |
| `totalAutonomousAgents` | int | no | agents with `executionMode=Autonomous` |
| `totalManagedIdentities`, `totalSystemManagedIdentities`, `totalUserAssignedManagedIdentities` | int | no | MI counts |
| `totalWorkloadApps` | int | no | workloads that are not managed identities (includes first-party) |
| `totalFederatedCredentials` | int | **yes** | null = FICs not collected |
| `totalFirstPartyMicrosoftNhIs` | int | no | workloads with `nhiType=FirstPartyMicrosoft` |
| `tier0PrivilegedNhIs` | int | no | distinct NHIs with any Tier-0 role/permission |
| `ownerlessNhIs` | int | no | ownerless non-MI NHIs (agents: no owner and no accepted sponsor) |
| `criticalFindingsCount`, `highFindingsCount`, `mediumFindingsCount`, `lowFindingsCount`, `informationalFindingsCount` | int | no | per severity; informational always 0 |
| `severityBreakdown` | object | no | `{Critical, High, Medium, Low, Informational: int}` |
| `topFindings` | array | no | first 5 findings (same shape as `findings`) |
| `collectionStatus` | string | no | section 6.1 |
| `federatedCredentialsCollected`, `agentMetadataCollected` | bool | no | section 6.1 |
| `federatedCredentialsCollectionDetail`, `agentMetadataCollectionDetail` | string | yes | stored detail |
| `federatedCredentialsTablePresent`, `agentMetadataTablePresent` | bool | no | schema presence |
| `dataGaps` | string[] | no | section 6.1 |

### 6.3 `GET /api/nhi/agents` (array)
`objectId`, `appId`, `applicationObjectId` (nullable), `displayName`, `agentCategory`, `executionMode`, `blueprintId` (nullable), `sponsorUserIds` (string[]), `sponsorNames` (string[]; UPN/display name, id when unresolved), `mcpTools`, `m365Scopes` (merged delegated + application + explicit), `graphAppRoles`, `oauth2Scopes`, `tier0Roles`, `directoryRoles`, `pimRoles`, `azureRoles`, `ownersCount` (int), `ownerNames` (owners only), `hasSecrets`, `hasCerts`, `federatedCredentialsCount` (int or null), `accountEnabled` (bool), `riskLevel`, `severityWeight`, `riskReasons` (string[]).
Sponsor/owner separation: `ownerNames` lists owners only; sponsors are in `sponsorNames`. Agent `ownersCount` includes distinct known owners and sponsors resolved to a user.

### 6.4 Other `/api/nhi/*` routes
- `GET /api/nhi/workloads` (array): `objectId`, `appId`, `applicationObjectId`, `displayName`, `nhiType`, `nhiCategory`, `servicePrincipalType`, `managedIdentityResourceId` (nullable), `accountEnabled`, `secretsCount`, `certsCount`, `federatedCredentialsCount` (int or null), `expiredCredentialsCount`, `longLivedCredentialsCount`, `maxExpiryDays` (int or **null** when no unexpired credential), `credentialSummary`, **role split**: `directoryRoles`, `pimRoles`, `azureRoles`, `graphAppRoles`, `tier0Roles`, and `privilegedRoles` (sorted union of all of them, retained for compatibility), `m365Scopes`, `ownersCount`, `ownerNames`, `riskLevel`, `severityWeight`, `riskReasons`.
- `GET /api/nhi/federatedcredentials` (array; empty when not collected): `id`, `applicationObjectId`, `appId`, `applicationDisplayName`, `name`, `issuer`, `subject`, `description`, `audiences`, `claimsMatchingExpression` (object/string/null), `riskLevel`, `severityWeight`, `riskReasons`.
- `GET /api/nhi/findings` (array): `id`, `severity`, `severityWeight`, `category`, `principalObjectId`, `principalType`, `principalName`, `appId`, `title`, `detail`, `recommendation`, `evidence` (object, category-specific).

### 6.5 Additional endpoints - Required
- `GET /api/applications/<id>/federatedcredentials`: FICs for one application (matched by `applicationObjectId`, or by `appId` when non-null), each risk-evaluated, sorted by severity. 404 if the application is unknown. Returns `[]` if the FIC table is absent or the FIC source was not collected, consistent with `/api/nhi/federatedcredentials`.
- `GET /api/serviceprincipals/<id>/nhi`: `objectId`, `appId`, `displayName`, `isAgent`, `agent` (item or null), `workload` (item or null), `federatedCredentials`, `findings` (by principal id or appId), `collectionStatus`. 404 if the SP is unknown.

### 6.6 Cache behaviour - Required
`get_nhi_report()` memoises the analysis per DB file path under a lock. The key is a fingerprint of the DB file (mtime, size), its `-wal` file, and the SQLite file-change counter (header bytes 24-27). For in-memory or non-file databases there is no cache. One page load triggers one analysis for all five routes plus the SP route. The cache is process-local and unbounded in entries (one per DB path).

## 7. Frontend - Required
- Sidenav entry **NHI & Agent 365** (`/nhi`), `NhiComponent` (`standalone: false`), tabs: Overview & Risk Findings; Agent 365 & AI Agents; Managed Identities & Workloads; Federated Credentials.
- Collection-status banner driven by `collectionStatus`, per-source flags, and `dataGaps`; null FIC counts render as "not collected", not 0.
- Dialog tabs: `ApplicationsdialogComponent` (federated credentials and NHI risk), `ServicePrincipalsdialogComponent` (Agent 365 and NHI posture).
- UI sponsor/owner separation and workload role split (directory / PIM / Azure / Graph app roles).
- `aadobjects.service.ts` interfaces must match section 6 field-for-field. There is no automated check of this seam (see section 10).

## 8. Performance and scale - Required
Target: tens of thousands of service principals. Mitigations: `selectinload` of owner/role relationships (with graceful fallback and a `dataGaps` entry), single analysis per DB state, batched deletes (500 per statement). No pagination on `/api/nhi/*`; the client paginates.

## 9. Deferred items
| Item | Why deferred | To un-defer |
|---|---|---|
| Application-side agent metadata (`/beta/applications`) | Only `servicePrincipals` is read. The shape of agent metadata on applications is unconfirmed. | Capture a live Graph payload, then add a third source and state row. |
| `$select` on beta `servicePrincipals` | Unverified that beta supports selecting `appMetadata`; an unknown property would 400 the whole source. | Verify live, then add `$select` to reduce payload. |
| `Informational` findings | No rule needs weight 0 yet. | Define a rule and a test. |
| Real-agent execution mode | Microsoft Graph exposes no execution-mode field, so real Entra agents always report `executionMode=Unknown` and autonomous-agent findings cannot fire on real data. Accepted as documented behavior (2026-11-20); no speculative inference (see D9). | A real execution-mode source becomes available (e.g. a future Graph field or a verified application-side signal). |

## 10. Not verified / limits
The NHI collector and analyzer were exercised against the Newport test tenant: three Agent Identities and one blueprint principal were identified, and sponsors were fetched. The earlier read-only Newport GET check is retroactively accepted; no full gather and no further live access are planned (offline fixtures only going forward). The full `roadrecon gather --nhi` path remains unverified; headless browser re-smoke (Edge + Playwright, offline synthetic fixture) PASS - `/nhi` and all four tabs render with no page errors or `undefined`/`NaN`, the agent dialog shows "Owners (1)", and the blueprint agent produces no false orphan. The tenant has no FICs, so live FIC row shape remains unverified. The Angular frontend has no unit tests; `$select`/application metadata shapes and the API-to-TypeScript contract are not tested end to end.

Fixed in the review-gate fix pass (2026-11-20 ~15:42 PST): an in-repo adversarial sub-agent review gate returned BLOCK (two HIGH evidence-integrity defects plus one MEDIUM UI bug). The blueprint principal false positive is now FIXED: the row is retained (`totalAgents` unchanged) but no "Orphaned AI agent" finding is emitted and `ownerlessNhIs` is not incremented; the risk reason "Agent identity blueprint template (not a running agent)" is emitted instead. Sponsor lookup failure (`sponsorsError`) is now an unknown-ownership state with a `dataGaps` entry, and failed/skipped/uncollected `agentMetadata` sources fall back to heuristic-only agent rows. Four regression tests cover these fixes. The in-repo adversarial sub-agent review gate was re-run by an independent agent; final verdict **APPROVE_WITH_FOLLOWUPS** - all five prior issues confirmed RESOLVED with file:line evidence and temp repros, no new defects, and the one low-severity follow-up (raw exception text in `sponsorsError`) fixed with `str(exc).split('?')[0]`. Two non-blocking follow-ups remain: a blueprint principal with Autonomous execution + high-write M365 scopes can still get a Critical blast-radius finding (suppression was scoped to orphan/ownerless; needs a product decision), and `sponsor_targets` matches only rows whose `@odata.type` is exactly `agentIdentity` (contrived edge).

Accepted / known limitations (decided 2026-11-20; no code change):
- **Execution mode is always `Unknown` on real agents.** Microsoft Graph exposes no execution-mode field, so real Entra agents always report `executionMode=Unknown` and autonomous-agent findings cannot fire on real data. This is accepted as documented behavior; no speculative inference is made.
- **Token file path.** `-f .roadtools_auth` at the workspace root is the accepted documented path (see `docs/nhi-usage.md`); no token file was written in this work.
