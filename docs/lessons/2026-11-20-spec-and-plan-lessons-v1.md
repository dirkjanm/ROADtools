# Lessons for the next spec and implementation plan (v1)

Date: 2026-11-20. Source project: ROADtools NHI / Agent 365 feature (`feat/nhi-agent365-posture`).
Purpose: paste this to an AI assistant at the start of a new project so the spec and plan avoid the mistakes made here.

## The core lesson

The spec described what the feature should be. It never said what must be true when things go wrong, and the plan did not force that to be tested. The first build passed every test and still had a serious evidence-integrity bug. Two independent reviews and a three-agent fix pass were needed to find and fix it.

The plan told the implementer to decide whether data was collected by checking whether the database tables exist. But the collector always creates those tables, so a run that collected nothing looked like a confirmed-empty result. The bug was in the plan, and the code followed it faithfully.

Treat every plan instruction as a claim that can be wrong. Before implementation starts, ask the AI to attack the plan itself: "What would make this step produce a confident wrong answer?"

## What to put in the spec

- **State invariants, not just features.** "Uncollected is not the same as empty" was one sentence, and nothing turned it into a mechanism. For each such rule, require three answers: how the system records the state, who writes it, who reads it. Here the answer was a stored per-source marker that the collector writes and the analyzer reads. It was not designed until the reviewers forced it.
- **Define every state, including the unhappy ones.** For anything collected or derived, list: collected, collected but empty, skipped on purpose, failed, partial, and legacy or never run. The spec had two states and reality had at least five.
- **Name the exact vocabulary.** The spec listed categories such as `FirstPartyMicrosoft` and `WorkloadApp`, and the implementation quietly emitted different names. If names matter, give an enumerated list and say "exactly these values".
- **Say what each API field means when data is absent.** "Return null, not zero" appeared once but never reached the contract field by field. Write the contract as a table: field, type, nullable or not, and what null means.
- **Separate must from nice-to-have.** Informational severity, the `--nhi` flag and sponsor-versus-owner display sat in the spec with equal weight and were silently dropped. Mark each item required, optional or out of scope, so an omission is a decision and not an accident.
- **Give unusual rules their source.** Whether a literal `*` subject is a wildcard was settled only by checking Microsoft's docs. For domain rules the AI might guess wrong, link the authoritative page in the spec.

## What to put in the plan

- **Write failure-path tests into the plan, not just the happy path.** The plan contained working test code only for the success case, which is why five green tests meant nothing. For every component name the failure cases: no token, 4xx or 429 responses, malformed or missing data, a legacy database, empty versus failed. Require those tests written first and seen to fail (red) before implementation.
- **Do not leave implementation as prose.** A paragraph of intentions is where the heuristics, scoring and classification errors came from. If a step is a paragraph, have the AI turn it into explicit rules and test cases, and approve those before coding.
- **Specify scale and performance up front.** One page load triggered 6 to 10 queries per service principal, repeated by five endpoints. State the expected size (for example 20,000+ service principals) and a rule such as one analysis per page load.
- **List the operational modes the new code must work with.** Existing flags such as `--evade` and `--skip-nhi` were never considered, so the first version broke Graph collection under `--evade`. List the existing flags and modes the new code touches, and test each.
- **Build the review gates into the original plan.** The adversarial and spec reviews were added late and were the most valuable part. Number them as tasks from the start, with defined outputs: a requirement-by-requirement traceability table for the spec review, and ranked findings with a failing input and wrong output for the adversarial review.

## How to work with the AI

- **Ask it to challenge before it builds.** For example: "Before writing code, list the three most likely ways this design gives a confidently wrong result, and which test would catch each."
- **Make done mean verified, not claimed.** A claim of completion must list what was not checked. Early in this project a status sounded finished while only happy-path tests and a build had run.
- **Verify the seams between components.** Each agent tested its own part, and the real risk was between parts: the collector writes a marker that the analyzer reads, and the frontend types must match the API output. Require at least one test per boundary using real components, not mocks.
- **Keep file ownership disjoint for parallel agents, and write the shared contract before dispatch.** This worked here because each agent owned separate files and the contract was fixed first.
- **Require disclosure of unrequested changes.** Fix agents changed behavior nobody asked for, such as a default execution mode and a removed query parameter. Ask for a "changes beyond the brief" section in every agent report.

## Checklist to paste into the next project

1. Every rule gets a mechanism: where it is stored, who writes it, who reads it.
2. Every collected or derived value lists all its states, including failed, skipped, partial and empty.
3. Exact enumerated names for categories, statuses and fields; nullable fields documented with their meaning.
4. Required, optional and out-of-scope marked on every item.
5. Failure-path tests are specified in the plan and written first.
6. The plan is attacked for wrong instructions before implementation starts.
7. Existing flags and modes the new code touches are listed and tested.
8. Scale and performance expectations are stated.
9. Adversarial and spec reviews are numbered tasks in the plan, with defined output formats.
10. Done means all gates passed plus an explicit list of what was not verified.
