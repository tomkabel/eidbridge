# RV resolution record — 2026-11-18

All 32 findings and recommendations from planning-review-rv-2026-11-18.json are addressed in the planning baseline. The review record is preserved. These are document and acceptance-contract corrections, not implementation evidence or a new sprint readiness approval.

| ID | Resolution location | Change |
|---|---|---|
| A1 | ADR-007 Key persistence; Story 2.4 TestSigningKeyParametersAndFileMode | Mode-specific demo prefix and production thumbprint rule. |
| A2 | ADR-008 Authorization code; Story 2.4 TestFailedExchangeLeavesFamilylessTombstone | Split initial-failure and initial-success histories; never erase successful family. |
| A3 | ADR-008 Standards deviations; Story 2.4 TestDemoLoopbackRedirectPolicy; addendum #14 | Exact static localhost HTTP callback exception is demo-only. |
| A4 | ADR-010 Flow cookie; Story 2.5 TestFlowCookieAttributes | One creation-time absolute deadline; reload and rotation use remaining lifetime. |
| A5 | ADR-009 Clock; Story 2.6 TestDenyListLifetimeSurvivesWallClockStep | Authenticated monotonic token deadline prevents rollback resurrection. |
| A6 | ADR-003 configuration invariants; NFR-007; Story 2.7 TestProductionRejectsDemoKeyFingerprint | Reject known supplied/fixture history; require fresh production keys and disclose unknowable provenance. |
| A7 | ADR-009 Upstream HTTP; Story 2.5 TestSessionInitTransportBounds | All outbound operations bounded, including init; no blind retry on uncertain creation. |
| A8 | ADR-009 Notification abuse; Story 2.5 TestTargetBucketFullMapAndChurn | Canonical target, full-map refusal, active debt preservation, bounded idle expiry. |
| A9 | ADR-010 Cookie cap; Story 2.5 TestAbsoluteFlowDeadlineAndEvictionRace | Cancel matched nonterminal victim locally; release unfilled capacity; preserve issued codes. |
| A10 | ADR-002 Data lifecycle; ADR-008 Authorization code; Story 2.4 concurrency AC | Atomic consume retains tombstone and publishes family before unlock. |
| A11 | ADR-009 Capacity model; Story 2.5 TestCodeCapacityUnderSustainedExchange | Independent code capacity sized for all populations and retention, including indexes. |
| A12 | Story 7.3 TestDoctorNeverControlsReadiness; ADR-009 Readiness | Explicitly supersede upstream readiness integration. |
| E1 | Same resolution as A5 | Retained separately as independent lens finding. |
| E2 | ADR-008 Replay; ADR-009 Tombstone cap; Story 2.4 TestReplayAtFullCapacityUsesReservedTombstone | Revocation flag stored in reserved tombstone; no separate deny-list allocation. |
| E3 | Same resolution as A8 | Retained separately as independent lens finding. |
| E4 | ADR-008 Client authentication; Story 2.4 TestConcurrentClientAssertionReplayRejected | Atomic jti insert-if-absent with capacity check under same lock. |
| E5 | ADR-010 Web2App return; state machine; Story 2.5 TestCallbackFirstRetainsVerifierUntilSignedResult | Defer unavailable verifier comparison; retain bounded secret until signed result; both required. |
| E6 | ADR-010 Flow-scoped endpoints; Story 2.5 TestRetiredBindingCannotDisruptCompletion | Old binding hash identifies notice-only stale requests without authority or state changes. |
| S1 | epics.md Execution packets and parent-story closure | Moved before inventory and stories; linked all packet references. |
| S2 | readiness Architecture remediation | Moved immediately after Verdict. |
| S3 | prd.md initial sections | Scope and success follow vision; gates precede feature catalog. |
| S4 | README.md Continue work; Verify planning artifacts | Next action precedes catalog; verification has its own section. |
| S5 | architecture.md Status and authority | Moved before Decision index. |
| S6 | architecture.md ADR-008 | Five descriptive table subheadings added. |
| S7 | roadmap.md Gates for every deferred GitHub issue | Moved after delivery increments. |
| S8 | epics.md Non-functional requirements; addendum.md | Preserved source and NFR reinforcement; stated PRD authority and sync policy. |
| P1 | readiness Architecture remediation | Independent checks and reviews wording. |
| P2 | readiness Verdict | Explicit demand and decomposition prerequisites. |
| P3 | epics Execution packets | Expanded DAG and explained its limited ordering check. |
| P4 | readiness Coverage result | Defined historical source-integration review/repair limits. |
| P5 | UX Components and layout contract | Permitted CSS override must preserve warnings and focus. |
| P6 | addendum introduction | Explicit subjects replace unclear pronouns. |

## Verification

Source preservation: PASS, zero failures; 30 stories and all 111 original issue criteria retained. Architecture trace: PASS, 82/82 mapped, zero open/errors, one Mermaid diagram rendered. Targeted consistency: PASS for synchronized NFRs, removed stale replay contracts and required navigation order. Full results and document hashes: [remediation checks](planning-review-rv-remediation-checks-2026-11-18.json). Product acceptance tests remain implementation obligations.
