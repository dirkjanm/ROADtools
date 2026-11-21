# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### NHI-Agent365 Rev1 - Non-Human Identity, Agent 365 and federated credential posture

#### Added
- `roadlib`: tables `FederatedIdentityCredentials`, `AgentIdentityMetadatas` and `NhiCollectionStates` (per-source collection outcome: `collected`, `skipped`, `failed`, `uncollected`).
- `roadrecon gather`: MS Graph beta collection of federated identity credentials and Agent 365 / Entra Agent ID metadata, plus heuristic agent detection from structured service principal fields.
- `roadrecon gather --nhi` (force the Graph token exchange when a refresh token exists) and `--skip-nhi` (skip the phase; wins over `--nhi`). Collection also runs automatically with a Graph-audience token, or a refresh token with `--autotoken`.
- `nhi_analyzer.py`: deterministic offline classification (agents, managed identities, workload apps, first-party) and risk findings with severity weights Critical=4 to Low=1.
- API: `/api/nhi/summary`, `/api/nhi/agents`, `/api/nhi/workloads`, `/api/nhi/federatedcredentials`, `/api/nhi/findings`, `/api/applications/<id>/federatedcredentials`, `/api/serviceprincipals/<id>/nhi`.
- GUI: **NHI & Agent 365** page (`/nhi`, four tabs) and NHI tabs in the application and service principal dialogs.
- Tests: `tests/test_nhi_backend.py`, `tests/test_nhi_gather.py`, `tests/test_nhi_analyzer.py`.
- Docs: design spec v2 and implementation plan v3 under `docs/superpowers/`; lessons note under `docs/lessons/`.

#### Changed
- Summary `collectionStatus` is FIC-only; per-source flags `federatedCredentialsCollected` / `agentMetadataCollected`, their details, `severityBreakdown`, `topFindings`, `totalFirstPartyMicrosoftNhIs` and `dataGaps` added. FIC counts are `null` (not 0) when FICs were not collected.
- Analysis runs once per database state and is shared by all `/api/nhi/*` routes (file-fingerprint cache).
- `BatchSession` (`--evade`) sends `graph.microsoft.com` requests as plain GETs instead of AAD-Graph `$batch` POSTs.
- Literal `*` in a plain FIC subject is Medium (Microsoft Learn: standard FICs match exactly); unrecognised OIDC issuers are Medium (hostname allowlist); `Informational` (weight 0) is reserved and never emitted.
- Generic fetch exception details now strip URL query strings before being written to `NhiCollectionStates.detail` or surfaced in the GUI collection-status banner (query parameters/tokens are not persisted).

#### Fixed
- Uncollected, skipped or failed collection is no longer reported as a confirmed-empty result (state is stored, not inferred from table existence).
- Partial or failed fetches never prune existing rows and never count as collected; one failed source no longer hides the other.
- Retry with back-off on 429/5xx, capped; repeating or foreign `nextLink` rejected.
- Delegated scopes no longer count as Tier-0 or app-only M365 write reach. Managed identities are excluded from the ownerless count; only sponsors resolved to a known user count toward agent ownership.
- Sponsor evidence is preserved on a failed lookup: `store_agent_metadata` keeps prior known `sponsorUserIds` across the `msgraph_beta` merge and `_collect_sponsors` no longer clears them when `/sponsors` fails. The failure is recorded as `sponsorsError` and treated as UNKNOWN ownership (a "sponsor lookup failed for agent <id>; ownership treated as unknown" `dataGaps` entry; orphan finding suppressed, M365 write finding not escalated to Critical, agent not counted ownerless).
- `msgraph_beta` agent rows are gated on `agentMetadata == collected` like FIC rows; failed/skipped/uncollected sources use heuristic-only rows, and agents are no longer double-counted as ownerless in the workload branch.
- The `agentIdentityBlueprintPrincipal` no longer produces the false "Orphaned AI agent" finding or increments `ownerlessNhIs`; the row is retained (`totalAgents` unchanged) and a risk reason "Agent identity blueprint template (not a running agent)" is emitted instead. This replaces the earlier accepted known limitation.
- The service principal dialog agent row renders `ownersCount` instead of `ownerNames.length`, so a sponsor that satisfies ownership correctly shows "Owners (1)".

#### Known limitations
- The NHI collector and analyzer were exercised against the Newport test tenant; the earlier read-only GET check is accepted, but a full gather and further live access have not been exercised (offline fixtures only going forward). Headless browser re-smoke (Edge + Playwright, offline synthetic fixture) PASS. The Angular frontend has no unit tests.
- Application-side agent metadata collection is deferred; beta `servicePrincipals` is read without `$select` pending verification.
- Agent ID detection and sponsor lookup were checked against live beta service principal payloads. FIC row shape remains unverified because the Newport tenant has 0 FICs.
- The blueprint principal "Orphaned AI agent" false positive is no longer a known limitation - it is FIXED in the review-gate fix pass (see Fixed above): the row is retained, the orphan finding is suppressed, `ownerlessNhIs` is not incremented, and the risk reason "Agent identity blueprint template (not a running agent)" is emitted.
- Real Entra agents always report `executionMode=Unknown` because Microsoft Graph exposes no execution-mode field, so autonomous-agent findings cannot fire on real data. Accepted as documented behavior; no speculative inference.
- The documented token file path is `-f .roadtools_auth` at the workspace root; no token file was written in this work.
- In-repo adversarial sub-agent review gate re-run by an independent agent after the fix pass: final verdict **APPROVE_WITH_FOLLOWUPS** - all five prior issues confirmed RESOLVED with file:line evidence and temp repros, no new defects; the one low-severity follow-up (raw exception text in `sponsorsError`) was fixed with `str(exc).split('?')[0]`. Two non-blocking follow-ups remain: a blueprint principal with Autonomous execution + high-write M365 scopes can still get a Critical blast-radius finding (suppression scoped to orphan/ownerless; needs a product decision), and `sponsor_targets` matches only rows whose `@odata.type` is exactly `agentIdentity`.
