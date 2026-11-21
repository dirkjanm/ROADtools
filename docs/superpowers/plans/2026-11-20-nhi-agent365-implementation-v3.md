# NHI, Agentic AI, M365 & Agent 365 Implementation Plan (v3)

> Status record. v1 and v2 are kept unchanged. v3 copies the v2 task structure, ticks what is done, records the review gates and the fix pass, and adds Tasks 7 and 8. Rev label: `NHI-Agent365 Rev1`. Branch: `feat/nhi-agent365-posture`. Nothing here has been committed or pushed by this document.

**Goal:** Full-stack support for Non-Human Identities (NHI), Entra Agent IDs, M365 Copilot / Agent 365 agents, managed identities and federated identity credentials across `roadlib`, `roadrecon gather`, the Flask API and the Angular frontend.

**Architecture:** `roadlib.metadef.database` gains `FederatedIdentityCredential`, `AgentIdentityMetadata` and `NhiCollectionState`. `gather.py` gains a MS Graph beta collection phase that records a per-source `NhiCollectionStates` row. `nhi_analyzer.py` is an offline deterministic classifier and scorer exposed through `/api/nhi/*` in `server.py`. Angular `NhiComponent` (`/nhi`) plus enriched dialog tabs.

**Tech Stack:** Python 3, SQLAlchemy, aiohttp, Flask, pytest, Angular 22 (NgModule, `standalone: false`), Angular Material 22, TypeScript 6.

**Spec:** `docs/superpowers/specs/2026-11-20-nhi-agent365-design-v2.md` (supersedes `...-design.md`)

## Global Constraints

- Evidence semantics are driven by the stored `NhiCollectionStates` marker, **not by table existence** (v2 plan instructed table-existence checks; that instruction was wrong, see Task 5).
- Severity weights: `Critical=4`, `High=3`, `Medium=2`, `Low=1`, `Informational=0` (reserved, never emitted).
- Offline validation first: pytest against temp SQLite fixtures, followed by a read-only live collector and analyzer check in the Newport test tenant.
- Angular components `standalone: false`, registered in `AppmainModule`; `<mat-chip-set>`/`<mat-chip>`.
- Existing flags `--evade`, `--user-agent`, `--autotoken` must keep NHI collection working.
- Source and test files are edited in place under their original names; only markdown is versioned (project CLAUDE.md rule).

---

### Task 1: Database Schema Extensions

**Files:** Modify `roadlib/roadtools/roadlib/metadef/database.py`; Create `tests/test_nhi_backend.py`.
**Produces:** `FederatedIdentityCredential`, `AgentIdentityMetadata`, and (added during the fix pass) `NhiCollectionState`, with relationships `Application.federatedIdentityCredentials` and `ServicePrincipal.agentMetadata`.

- [x] Step 1: failing model test
- [x] Step 2: red run (`ImportError`)
- [x] Step 3: models and relationships added
- [x] Step 4: green run
- [x] Step 5 (added in v3): `NhiCollectionState` table (`source` PK, `status`, `detail`, `itemCount`, `collectedAt`)

### Task 2: MS Graph Collector Phase (`gather.py`)

**Files:** Modify `roadrecon/roadtools/roadrecon/gather.py`; Create `tests/test_nhi_gather.py`; Modify `tests/test_nhi_backend.py`.
**Produces:** `extract_agent_metadata_from_sp`, `store_federated_credentials_batch`, `store_agent_metadata`, `record_nhi_state`, `mark_nhi_skipped`, `acquire_msgraph_headers`, `DataDumper.dump_federated_credentials / dump_agent_metadata / dump_nhi_msgraph / _fetch_msgraph_paged / _collect_source`, flags `--skip-nhi` and `--nhi`.

- [x] Step 1: happy-path unit tests (agent extraction, FIC batch store)
- [x] Step 2: red run
- [x] Step 3: collector implemented
- [x] Step 4: green run
- [x] Step 5: failure-path tests (new file `tests/test_nhi_gather.py`): no token -> skipped; HTTP failure isolated per source; exception -> failed while other source still runs; partial pagination is failed; 429 retry with `Retry-After`; retry cap; stale rows pruned only on success; legacy DB without state table; FK orphans; `--evade` BatchSession bypass for graph.microsoft.com; user agent on every Graph request; foreign nextLink rejected; repeating nextLink; page cap; `--nhi` / `--skip-nhi` precedence; generic names do not classify as agents; execution mode only from explicit fields
- [x] Step 6: live NHI collector and analyzer verification against the Newport test tenant (3 Agent Identities, 1 blueprint principal, sponsors fetched). Full `roadrecon gather --nhi` and FIC row shape remain open.

### Task 3: Classification and Risk Engine (`nhi_analyzer.py`, `server.py`)

**Files:** Create `roadrecon/roadtools/roadrecon/nhi_analyzer.py`; Modify `roadrecon/roadtools/roadrecon/server.py`; Create `tests/test_nhi_analyzer.py`; Modify `tests/test_nhi_backend.py`.
**Produces:** `analyze_nhi_posture`, `evaluate_fic_risk`; routes `/api/nhi/summary|agents|workloads|federatedcredentials|findings`, `/api/applications/<id>/federatedcredentials`, `/api/serviceprincipals/<id>/nhi`; per-DB-state report cache.

- [x] Step 1: happy-path analyzer test
- [x] Step 2: red run
- [x] Step 3: analyzer and routes implemented
- [x] Step 4: green run
- [x] Step 5: evidence tests (`tests/test_nhi_analyzer.py`): no marker and no rows is uncollected, never false zero; marker collected with zero rows is a true zero; marker failed ignores partial rows and exposes detail; rows without marker infer collected; missing marker table falls back to inference; `maxExpiryDays` null when only expired; delegated scopes not Tier-0; ownerless excludes managed identities; FIC claims-expression cases; literal `*` subject is Medium; unrecognised issuer Medium; first-party with secret not skipped; severityBreakdown/topFindings; workload role buckets and sponsor names; unknown mode promoted only for M365/Tier-0 app roles; missing PIM tables recorded in `dataGaps`; server cache runs analysis once per DB state

### Task 4: Angular Frontend

**Files:** `aadobjects.service.ts`, new `nhi/nhi.component.{ts,html,less}`, `appmain.module.ts`, `app-routing.module.ts`, `appnav.component.html`, applications and service principals dialog components.

- [x] Step 1: interfaces and `DatabaseService` methods
- [x] Step 2: `NhiComponent` registered, routed, linked
- [x] Step 3: dialog tabs
- [x] Step 4: `npm run build` (passed after the fix pass; rerun on 2026-11-20)
- [ ] Step 5: browser smoke test and unit tests (NOT DONE; the frontend has no unit tests; browser smoke check delegated to another agent)

### Task 5: Adversarial Code Review (sub-agent gate)

Read-only sub-agent tries to break Tasks 1-4 with ranked findings, each with a failing input and the wrong output. **Run twice** (once after the first build, once after the fix pass).

- [x] Step 1: launched after Task 4 (round 1)
- [x] Step 2: triaged and fixed (round 1)
- [x] Step 3: launched again on the fixed code (round 2)
- [x] Step 4: triaged and fixed (round 2), see Task 7

Findings summary (from the project lessons note and the fix brief; the review reports themselves are not stored in the repo):
1. **Evidence-integrity bug (serious):** the plan said to infer collection from table existence, but the collector always creates the tables, so a run that collected nothing looked like a confirmed-empty result. Fixed with `NhiCollectionStates` written by the collector and read by the analyzer.
2. Partial or failed fetches could be mistaken for complete data and used to prune rows. Fixed: `failed` state, no prune on failure, analyzer ignores FIC rows unless `collected`.
3. `--evade` (`BatchSession`) rewrote Graph requests into AAD-Graph `$batch` POSTs, breaking MS Graph collection. Fixed by bypassing the rewrite for `graph.microsoft.com`.
4. Performance: 6-10 queries per service principal repeated by every endpoint. Fixed with `selectinload` and a once-per-DB-state cache.
5. Round 2 items (DB-flush crash handling, user agent, nextLink host check, per-app FIC route consistency, heuristic promotion scope, claims-expression detection, sponsor and delegated-scope handling, UI separations): see Task 7.
False positives: none recorded in the available notes.

### Task 6: Comprehensive Spec Review (sub-agent gate)

Read-only sub-agent produces a requirement-by-requirement traceability table (MET/PARTIAL/MISSING/DEVIATES) against the spec and plan. **Run twice.**

- [x] Step 1: launched after Task 4 (round 1)
- [x] Step 2: gaps closed or deferred (round 1)
- [x] Step 3: launched again after the fix pass (round 2)
- [x] Step 4: gaps closed or deferred (round 2)

Gaps found (round 1, per the lessons note): vocabulary drift (`FirstPartyMicrosoft`/`WorkloadApp` emitted under different names than the spec), `Informational` severity silently dropped, `--nhi` flag missing, sponsor-versus-owner display missing, spec said "return null, not zero" but not per field, behaviour changes made by fix agents without a brief (a default execution mode, a removed query parameter). Resolutions: vocabulary and fields written down in spec v2; `Informational` formally deferred (reserved, never emitted); `--nhi` implemented; sponsor/owner separation in UI; the default execution-mode inference is documented in spec v2. Application-side agent metadata collection explicitly **Deferred**. The removed query parameter is not specified in the available notes and cannot be reconstructed reliably.

### Task 7: Re-review fix pass

Three agents with disjoint file ownership (collector, analyzer/server, frontend) fixed the round 2 findings. Final behaviour:

- [x] `NhiCollectionState` written by collector, read by analyzer; per-source flags and details in summary; `dataGaps`
- [x] Failed/partial/skipped never presented as empty; no prune on failure
- [x] 429/5xx retry with cap; sources isolated
- [x] `--evade` works for Graph; `--nhi` added; `--skip-nhi` wins
- [x] Delegated scopes do not make Tier-0
- [x] Literal `*` FIC subject = Medium; unrecognised issuer = Medium (allowlist by hostname)
- [x] Single analysis per DB state (cache)
- [x] DB-flush crash handling in the collector: a DB error marks the source `failed`, session rolled back, state recorded via `_safe_record` (confirmed in code)
- [x] Evade/user-agent: `acquire_msgraph_headers(..., user_agent=)` adds `User-Agent` to Graph headers (confirmed in code)
- [x] nextLink host/scheme check (https graph.microsoft.com only), repeat guard, page cap 10000 (confirmed in code)
- [x] Per-application FIC route consistent with `/api/nhi/federatedcredentials` collected/uncollected rule
- [x] Heuristic agent promotion limited to app-role `AiEnterpriseInteraction.*`/`Copilot.*`
- [x] Hardened `claimsMatchingExpression` detection
- [x] Sponsors count as owners only when resolved to a known user
- [x] Delegated scopes do not trigger the secret/ownerless or app-only M365 write findings
- [x] UI: sponsor/owner separation and role split (directory/PIM/Azure/Graph)

### Task 8: Docs

- [x] `docs/superpowers/specs/2026-11-20-nhi-agent365-design-v2.md`
- [x] `docs/superpowers/plans/2026-11-20-nhi-agent365-implementation-v3.md` (this file)
- [x] `CHANGELOG.md` (new, Keep a Changelog)
- [x] Lessons note already present: `docs/lessons/2026-11-20-spec-and-plan-lessons-v1.md`
- [x] `docs/nhi-usage.md` and README "NHI and Agent 365 posture" usage section + link (DONE; verified 2026-11-20 ~15:19 PST). The additive in-place README edit is kept by owner decision; spec/plan changes remain versioned as v2/v3.

### Task 9: Review-gate fix pass (2026-11-20 ~15:42 PST)

An in-repo adversarial sub-agent review gate returned **BLOCK**: two HIGH evidence-integrity defects plus one MEDIUM UI bug. All were fixed in code with four new regression tests. `gather.py`, `nhi_analyzer.py`, `tests/test_nhi_gather.py`, `tests/test_nhi_analyzer.py` and `serviceprincipalsdialog.component.html` are modified/uncommitted on top of local commits `48af18b` / `eb97492`.

- [x] `gather.py` (HIGH): `store_agent_metadata` preserves prior known `sponsorUserIds` across the `msgraph_beta` merge; `_collect_sponsors` no longer clears them on a failed `/sponsors` GET - it records `sponsorsError` and marks the source detail, never failing the source.
- [x] `nhi_analyzer.py` (HIGH): `sponsorsError` is UNKNOWN ownership (dataGaps entry "sponsor lookup failed for agent <id>; ownership treated as unknown", orphan finding suppressed, M365 write finding not escalated to Critical, agent not counted ownerless); `msgraph_beta` agent rows are gated on `agentMetadata == collected` (heuristic-only otherwise) and agents are no longer double-counted as ownerless in the workload branch.
- [x] Blueprint principal: retained in the agents list (`totalAgents` unchanged) but no "Orphaned AI agent" finding and no `ownerlessNhIs` increment; risk reason "Agent identity blueprint template (not a running agent)" emitted. This reverses the earlier accepted-known-limitation decision.
- [x] LOW hardening: strip URL query strings from generic fetch exception details before persisting in `NhiCollectionStates.detail` / surfacing in the GUI banner.
- [x] Frontend (MEDIUM): serviceprincipalsdialog agent row renders `ownersCount` instead of `ownerNames.length`, so a sponsor that satisfies ownership shows "Owners (1)".
- [x] Four new regression tests; gates re-run: 132 passed in both orders; `py_compile`, import check and `npm run build` OK with the known warnings.
- [x] Adversarial sub-agent review gate RE-RUN by an independent agent after the fixes. FINAL VERDICT: **APPROVE_WITH_FOLLOWUPS**. All five prior issues were confirmed RESOLVED with file:line evidence and temporary reproductions: F1 sponsor wipe / Critical escalation, F2 failed-source rows trusted, F3 blueprint orphan, F4 URL in exception detail, and the UI owner count. No new defects were introduced.
- [x] Low-severity follow-up from the re-review also fixed: raw exception text in `sponsorsError` in gather.py stripped with `str(exc).split('?')[0]`.
- [x] Final gates (2026-11-20 ~15:50 PST): pytest both file orders = 132 passed; `py_compile` OK on the 4 Python files; import check OK; `npm run build` exit 0 (run after the UI fix; only Python changed afterwards); `dist_gui/.gitkeep` files restored.
- [x] Browser re-smoke (headless Edge + Playwright, offline synthetic fixture) PASS: agent dialog shows "Owners (1)", `/nhi` and all four tabs render with no page errors or `undefined`/`NaN`, blueprint agent produces no false orphan.

## Tests

New and changed test files:
- `tests/test_nhi_backend.py` (modified, 5 tests)
- `tests/test_nhi_gather.py` (new, 28+ test functions, some parametrised)
- `tests/test_nhi_analyzer.py` (new; grew during the fix pass, parametrised)

Command: `python -m pytest tests/test_nhi_backend.py tests/test_nhi_gather.py tests/test_nhi_analyzer.py -q`
Latest result (2026-11-20 ~15:42 PST, after the review-gate fix pass): **132 passed, 0 failed** in both file orders (backend 5, gather 51, analyzer 76). Four new regression tests were added by the fix pass - 1 in `tests/test_nhi_gather.py` and 3 in `tests/test_nhi_analyzer.py` - covering sponsor preservation on `/sponsors` failure, `msgraph_beta` agent gating, and blueprint false-positive suppression. `python -m py_compile` is clean on the four Python files and the import check passes. A test-isolation bug (backend test rebuilding `SQLAlchemy` on the shared Flask app after other tests had served requests) was fixed in `tests/test_nhi_backend.py`. `npm run build` exits 0 with the known warnings. Four unrelated pre-existing tests (`test_asyncauth`, `test_database`, `test_guiserver`) fail identically on a clean checkout of HEAD. Plan v1 checkboxes were ticked in commit `9149005` before the later fixes and live check.

## Known limitations / not verified

- **Partial live Microsoft Graph check.** A real NHI collector and analyzer run against the Newport test tenant found 3 Agent Identities and 1 blueprint principal, fetched sponsors, and stored metadata. A full `roadrecon gather --nhi` run, Graph token exchange, paging/throttling and FIC row shape remain unverified; the test tenant has no FICs.
- **Browser re-smoke (2026-11-20 ~15:50 PST).** Headless Edge + Playwright against an offline synthetic fixture PASS: agent dialog shows "Owners (1)", `/nhi` and all four tabs render with no page errors and no `undefined`/`NaN`, and the blueprint agent produces no false orphan finding. A full live-GUI run against a real tenant was not performed (offline fixtures only).
- **Frontend has no unit tests.** The API-to-TypeScript contract (spec section 6 vs `aadobjects.service.ts`) is not tested.
- Application-side agent metadata is not collected (Deferred). Beta `servicePrincipals` is fetched without `$select`.
- Live Agent ID payloads use `@odata.type` `#microsoft.graph.agentIdentity` and `#microsoft.graph.agentIdentityBlueprintPrincipal`, with `servicePrincipalType=ServiceIdentity` and agent fields; the collector was updated and checked against those shapes.
- Review reports from Tasks 5-6 are not stored in the repo; finding detail above is reconstructed from the lessons note and the fix brief.
- Remaining NON-BLOCKING follow-ups (from the APPROVE_WITH_FOLLOWUPS verdict): (1) a blueprint principal with Autonomous execution + high-write M365 scopes can still get a Critical blast-radius finding - suppression was intentionally scoped to orphan/ownerless; needs a product decision; (2) `sponsor_targets` only includes rows whose `@odata.type` is exactly `agentIdentity`, so a type change would leave preserved sponsors unrefreshed (contrived edge). Unverified items are unchanged: live Microsoft Graph full gather and FIC row shape (tenant has 0 FICs), Postgres, frontend has no unit tests, application-side agent metadata deferred.
- Execution-mode behavior is DECIDED (2026-11-20; no code change): real agents always report `executionMode=Unknown` (Graph has no such field) so autonomous-agent findings cannot fire on real data - accepted behavior, no speculative inference. The blueprint principal governance finding is now DECIDED / FIXED (review-gate fix pass, ~15:42 PST): the row is retained in agent rows/counts (`totalAgents` unchanged) but the "Orphaned AI agent" finding is suppressed and `ownerlessNhIs` is not incremented; the risk reason "Agent identity blueprint template (not a running agent)" is emitted. This reverses the earlier accepted-known-limitation decision. See spec v2 sections 2/5.2/9/10, Task 9 and CHANGELOG.
