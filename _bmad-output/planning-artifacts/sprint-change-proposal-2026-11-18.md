---
title: eidbridge sprint change proposal
status: completed
created: 2026-11-18
trigger: implementation-readiness concerns after planning remediation
---

# Sprint Change Proposal

## Issue Summary

The implementation-readiness check returned CONCERNS because the architecture still contains proposed values and choices: the default subject mode, token and capacity values, and whether `private_key_jwt` ships in v1. The current PRD and architecture assign these choices to Q-02, Q-03 and Q-04, name owners, and state when the decisions must be made. The prior readiness report predates the remediation and explicitly says it was not re-judged.

No implementation story triggered this change. It was identified during pre-sprint readiness review. Evidence is in `prd.md` under “Constraints, assumptions and open decisions,” `architecture.md` ADR-007/008 and the decision index, `epics.md` Story 2.4, and `research/planning-review-rv-remediation-checks-2026-11-18.json`.

## Impact Analysis

**Epics:** No epic scope or ordering change is indicated. The foundation packets are listed in `epics.md` and have an execution order. The current sprint parser tracks epic and story headings, not packet rows, so refreshing it will create or merge parent-story entries rather than distinct packet entries.

**Stories:** Story 2.4 already requires resolving subject linkability, token lifetime and userinfo lifecycle, recording conformance-plan deviations, and testing the OIDC contract. Q-02/Q-03/Q-04 identify owners and decision timing. Story 2.5 similarly carries its NFR-007 and NFR-014 configuration and readiness contracts. No new feature story is currently evidenced by this trigger.

**PRD and architecture:** The cited decisions are explicitly recorded as implementation gates. ADR-007 and ADR-008 are proposed and link to the relevant Q gates. The architecture specifies required configuration and provisional bounds, while Q-04 owns confirmation of operating values. Q-03 owns the v1 `private_key_jwt` choice. The readiness concern is whether these documented gates count as sufficient to start only the earlier packets, not evidence of a missing owner or unrecorded decision.

**UX:** No UX flow or interaction change is implicated by these configuration and protocol decisions.

**Technical and tracking impact:** A fresh readiness judgment is needed after the documented remediation. If it passes, `sprint-status.yaml` can be refreshed while preserving backlog statuses. Packet-level tracking would require representing packets as stories or changing the tracking model, which is not part of this proposal.

## Recommended Approach

Choose direct adjustment: apply the readiness gate to the current planning set, treating Q-02/Q-03/Q-04 as explicit implementation gates with the recorded owners and deadlines. Confirm that no story claims completion before its gate. Do not turn provisional values into invented defaults. If the gate passes for the current plan, refresh the existing sprint tracking through `bmad-sprint-planning`; the file will continue to track parent stories.

Effort is low for the readiness re-judgment and tracking refresh. Risk is low if the Q-gate ownership and story boundaries remain explicit. No rollback is relevant because implementation has not started. The PRD MVP remains achievable under the documented gates.

## Detailed Change Proposals

**Readiness record**

Current: The prior readiness report records 12 concerns, says they were corrected, and says they were not re-judged. The remediation-check JSON explicitly states that it is not a fresh readiness judgment.

Proposed: Run a fresh readiness gate against the current PRD, architecture, UX, epics, addendum, source reconciliation, and corrections. Record a new dated verdict and findings. A PASS permits sprint tracking refresh. CONCERNS or FAIL leaves tracking unrefreshed until the gate is addressed.

Rationale: The previous verdict predates the corrections. A structural remediation pass cannot substitute for an implementability judgment.

**Sprint tracking**

Current: `sprint-status.yaml` tracks parent epics and stories. Foundation packets appear as a table in `epics.md`, not parser-recognized story headings.

Proposed: On PASS, regenerate or merge the existing tracking file from the epic document and preserve valid statuses. Report that packet rows are not separately tracked. Packet-level entries require a separate approved backlog decomposition.

Rationale: Avoid representing parent-story tracking as packet-level completion.

No PRD, epic, architecture, or UX edits are proposed by this trigger. If the fresh gate finds a concrete contradiction or missing contract, route that finding to the owning planning skill before generating status.

## Implementation Handoff

Scope is minor. The planning owner runs `bmad-sprint-planning` for a fresh gate. If the result is PASS, the same workflow refreshes `_bmad-output/implementation-artifacts/sprint-status.yaml`. If it is not PASS, the owner resolves the reported findings through the relevant PRD, architecture, UX, or epic workflow and reruns the gate.

Success criteria are a dated readiness judgment grounded in the current corrected artifacts, no unowned decision on any story being started, and a valid tracking file generated only after PASS. Packet-level tracking is explicitly outside this proposal.

## Review State

The user approved this proposal on 2026-11-18. The fresh readiness gate passed. Sprint tracking was regenerated and validated with 8 epics, 30 stories, 38 backlog entries and 8 optional retrospectives. Existing story statuses were matched by story ID and preserved as backlog. The generator reported three non-story heading warnings; all 30 story headings parsed. Packet rows remain represented only through their parent stories.
