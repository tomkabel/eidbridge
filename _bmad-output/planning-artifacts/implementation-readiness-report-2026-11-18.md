---
title: eidbridge implementation readiness
status: draft-with-explicit-gates
created: 2026-11-18
updated: 2026-11-18
---

# Implementation readiness

## Verdict

Source integration is complete and the next feasibility/foundation work is defined. The product is not implemented or release-ready. Scope, evidence and dependencies are usable for planning; no production assurance, legal compliance, conformance or live demo success is claimed. Before a deferred high-effort feature is ready for development, confirm demand and split it into smaller, independently verifiable stories.

The subsequent [RV resolution record](research/planning-review-rv-resolutions-2026-11-18.md) addresses all 32 review items in the planning contracts. Foundation work remains the first increment; a formal readiness re-judgment and implementation evidence remain separate requirements.

## Architecture remediation (2026-11-18)

[architecture.md](architecture.md) was rewritten against 82 review findings (40 behavioral, 17 structure, 25 prose); see the [remediation plan](architecture-remediation-plan.md). Independent checks and reviews were run in this order:

| Judge | Result |
|---|---|
| `tools/check-arch-trace` | Exit 0: 82 of 82 findings have an anchor plus a story AC or gate; 1,723 prose words outside tables against a 1,900 budget; the Mermaid diagram renders. It checks traceability and editorial gates only, not design correctness. |
| `tools/verify_bmad_artifacts.py` (frozen) | PASS, zero failures, after every edit round. |
| Readiness gate ([report](research/readiness-judge-2026-11-18.md)) | CONCERNS, 12 findings (stale NFRs in epics, contradictory chooser and pin-disable text, missing ADR-008 ACs, terminal-state retry, Q-05 reuse, unowned decisions, mode config, forward doc dependency, addendum and UX conflicts). Corrected; not re-judged. |
| Blind adversarial and edge-case re-review, pass 1 ([findings](research/blind-rereview-1-2026-11-18.json)) | 25 findings. Several were in the same classes as the original 40 (state machine, capacity, key custody, configuration invariants), so the hard target of zero recurrence was missed. All were addressed in the architecture. |
| Blind re-review, pass 2 ([findings](research/blind-rereview-2-2026-11-18.json)) | 26 further findings, mostly deeper gaps in the newly written rules (concurrent exchange, Web2App ordering, cookie scope, certificate parameters, limits). Addressed except the items below. |

Open after pass 2, deliberately: account existence is observable in notification mode (recorded as a disclosed residual risk); a missing `trusted_proxies` behind a load balancer warns rather than refuses to start (E18 decision); numeric bounds are provisional until Q-04; the Smart-ID policy OIDs and minimum certificate level wait on Q-02. A third blind pass has not been run, so zero-recurrence is unproven.

Not done: no CI job exists because the repository has no scaffold (Story 1.2 carries the AC), and nothing was committed or pushed.

## Coverage result

The fixed [checker](../../tools/verify_bmad_artifacts.py) was authored by an independent read-only verifier before the candidate documents. Its SHA256 is eedb2568b67cfe502e109cf11cc0221725bc6bfc74613e12c374a42b760b771e. Baseline was FAIL with 232 absent-coverage failures; full report in [baseline](research/validation-baseline-2026-11-18.json). Final result: PASS with zero failures, recorded in [validation result](research/validation-result-2026-11-18.json); verifier and frozen inputs are unchanged. [Supplementary checks](research/supplementary-validation-2026-11-18.json) cover packet order, dated motivations, umbrella mappings, backlog states and resolved customization paths.

Coverage contract: all 30 issues map to FR/story and retain all 111 original checkbox criteria/full Notes; nine opportunities, fourteen comparative capabilities, fifteen milestones, 54 signals, ten forecasts and 94 additional research dispositions are represented. All source files are inventoried by hash, including supporting payloads not individually revalidated. The original issue bodies, labels and states are in a complete live snapshot. All implementation tracking remains backlog.

This is an automated structural/source-preservation proxy and one source-reconciliation review, not a semantic grading loop. For the source-integration pass, subjective review was capped at one pass (K=1), and mechanical repairs at three rounds (Kmax=3). The checker cannot detect a well-linked but poor product decision, prove all natural-language suggestions understood correctly, establish standards/legal applicability, assess cryptographic code or show real user value. Full verification needs working implementation, pinned protocol/profile tests, native language review, external security review where required and actual deployment evidence.

## Ready for initial work

The notices/clean-room foundation packet, minimal source scaffold, sink-only safe logging tests and capped spike can begin in packet order without waiting for later full-login/container acceptance evidence. Parent stories remain incomplete until their original integration/release checks pass. Precise live protocol, build tools and provider-library choices must be confirmed during those implementation stories with current documentation, not inferred from dated research. All original issue acceptance criteria remain required even where estimates are optimistic. No existing test suite or application source was observed.

## Open implementation and release gates

| Gate | Owner | Revisit / exit evidence |
|---|---|---|
| Public demo access/device-link feasibility | Maintainer | Six-hour #2 spike, synthetic fixtures, documented result/fallback/CI capability; stop if public access requires contract/payment |
| Protocol/profile and status policy | Protocol/security maintainer | Before verified production identities: exact protocol version, trust/algorithm/chain/status responsibilities and assurance mapping |
| Provider library/conformance/client auth | Maintainer | Before #6: candidate licence/dependency/feature evidence; exact Basic OP plan and deviations; define token/userinfo lifetimes and key rotation |
| Capacity/calendar | Project owner | After spike: 50–51h source issue sum vs 40h narrative; confirm target dates and resource, no silent safety cuts |
| Actual production agreement/legal applicability | Operator with qualified advice when needed | Own credentials/agreement, reviewed applicable terms and role obligations; no legal clearance inferred from research |
| UX language/interaction evidence | Integration/localization reviewers | Five locales native reviewed; axe/keyboard, mobile/desktop/error paths; final visual contract if needed |
| Core readiness | Maintainer | All core original AC and NFR tests pass, published-artifact smoke/checksum/SBOM and clean-machine demo evidence |
| Adoption matrix | Integration maintainer | Four real pinned IdP setups plus two framework examples; stable subject mapping/demo rejection; no simulated passed matrix |
| Deferred large stories | Project owner/security maintainer | Original demand gate, budget and split into reviewable child stories; Web eID external review, wallet profile/test access, signing scope/validator |

## Structural corrections already captured

The parent identifier graph is earlier-first and acyclic; that structural property alone does not prove semantic executability. The independent review found late integration checks in early parents, now resolved through the execution-packet/parent-closure distinction in epics. The chooser and Mobile-ID activate together on demand (ADR-006), so no backedge remains. Original non-code issue dependencies are preserved in Notes; additional logging/trust/guard sequencing is deliberate. Child story status is not set ready-for-dev; foundational source #1 is not marked done merely because planning files exist. Scope and IDs remain source aligned. Metadata-only future audit is not enabled, and signing/legacy/Python conflicts are documented.

## Workflow and verification limits

This was a user-authorized batch integration, not an interactive BMAD elicitation interview. Product/architecture/UX docs are explicit drafts; menus were not treated as user approval. BMAD PRD/epic conventions, source reconciliation and structure/prose review apply; no false stepsCompleted or final user-approval markers are asserted. The memlog records decisions/assumptions through the installed helper. The installed BMAD framework and skills remain unchanged.

## Independent source and editorial review

A single read-only review applied the PRD rubric and structure→prose lenses. It confirmed the estimate sum and explicit source conflicts, and found five actionable issues: parent-closure dependency cycle, narrow umbrella capability mapping, malformed story introductions, undated source motivations and ambiguous launch clocks. All five were corrected without changing original acceptance criteria or source evidence. See [review record](research/review-source-and-editorial-2026-11-18.md). No second subjective optimization pass or product-quality certification is claimed.
