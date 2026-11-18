# Planning review — 2026-11-18

Review only. Planning source documents were not changed. No formal sprint readiness verdict or implementation validation is issued.

The documents help maintainers turn source-backed plans into verifiable implementation while preserving original requirements. Models: Strategic/Context (Pyramid), with Reference/Database treatment for ADRs, stories and source records. Technical terminology, evidence limits and original issue wording are preserved.

Checks: source-preservation PASS (zero failures); architecture trace PASS (82/82). Mermaid rendering was skipped. These checks do not establish behavioral correctness.

Counts: 12 adversarial findings, 6 edge-case findings, 8 structure recommendations, 6 prose recommendations. Overlap across lenses is retained: clock rollback and target-map capacity were independently identified by both behavioral lenses.

## Adversarial

### A1 — architecture.md:229,289; epics.md:579
Demo kid must have a demo- prefix while every kid must equal its JWK thumbprint.
Suggested guard: Define and test one mode-aware kid rule, including an explicit demo exception.
Consequence: Demo key-format and environment tests require incompatible values.

### A2 — epics.md:423; architecture.md:318
Wrong-then-correct and correct-then-wrong exchanges both require a familyless tombstone.
Suggested guard: Split sequences: initial failure leaves no family; initial success retains the family and subsequent replay revokes it.
Consequence: The criterion can erase the successful exchange replay-revocation association.

### A3 — architecture.md:356; addendum.md:378; epics.md Story 3.2
HTTPS-only redirect registration conflicts with the required HTTP localhost demo RP.
Suggested guard: Choose a narrowly scoped demo loopback exception or an HTTPS demo topology and test registration.
Consequence: The specified demo cannot complete its authorization round-trip.

### A4 — architecture.md:201,329,411; epics.md:471
Cookie expiry alternates between flow_ttl and flow_ttl plus 30 seconds.
Suggested guard: Define one absolute flow expiration and derive cookie expiry, cleanup and tests from it.
Consequence: The browser loses its binding while its server flow remains live.

### A5 — architecture.md:321,386; epics.md:538
Backward wall-clock steps extend token acceptance beyond monotonic revocation retention.
Suggested guard: Define rollback handling or process-relative token deadlines; test a revoked token after deny-list expiry while wall time precedes exp.
Consequence: A revoked token can become usable again.

### A6 — architecture.md:229-230; prd.md NFR-007
Production must reject historical demo keys but cannot access their demo-volume fingerprint history.
Suggested guard: Provide accessible durable fingerprint history or explicitly narrow the guarantee to known supplied history and fixtures.
Consequence: The asserted imported-demo-key rejection cannot be established.

### A7 — architecture.md ADR-009 Upstream HTTP and Upstream session
Bounded HTTP transport rules omit upstream session initialization.
Suggested guard: Apply timeouts, response caps and no-redirect rules to initialization too; define failure transitions.
Consequence: Initialization can retain capacity indefinitely or bypass transport safeguards.

### A8 — architecture.md:383; ADR-009 Capacity model
The bounded notification target map has no full-map or entry-retention rule.
Suggested guard: Define capacity, normalization, retention and fail-closed admission; test target churn.
Consequence: Churn can reset push limits or block login without a recovery rule.

### A9 — architecture.md:416; ADR-009 capacity reservations
The fifth flow expires a cookie without specifying server-flow resource handling.
Suggested guard: Specify cancellation and resource release, or deliberate retention to timeout; test the chosen behavior.
Consequence: Unreachable sessions and reservations continue consuming capacity.

### A10 — architecture.md:197,318; epics.md:410
LoadAndDelete conflicts with retained consumed entries required by the replay design.
Suggested guard: Use one atomic consume operation preserving the family tombstone, or specify race-free separate-store publication.
Consequence: A concurrent replay can fail to find the issued token family.

### A11 — architecture.md:393-394
The shared cap equates pending concurrency with reservations, codes and long-lived tombstones.
Suggested guard: Size each population using its arrival rate and residence time, or document the intentional throughput limit.
Consequence: Successful login tombstones can reject new authorizations despite idle upstream capacity.

### A12 — epics.md:1143; architecture.md:381
The doctor story still permits optional readyz integration.
Suggested guard: Supersede optional readyz integration; keep upstream diagnostics in the opt-in doctor command.
Consequence: Deferred implementation can restore the readiness behavior the architecture retired.

## Edge-case hunter

### E1 — architecture.md ADR-008 Access token, ADR-009 Clock; epics.md Story 2.6
Wall clock moves backwards and replay-denial entries subsequently expire.
Suggested guard: Enforce monotonic token deadlines or invalidate the sealing epoch on unsafe rollback; test beyond deny-list expiry.
Consequence: A replay-revoked token becomes usable again.

### E2 — architecture.md ADR-008 Replay; ADR-009 Capacity model
A code is replayed when the separate bounded deny-list is full.
Suggested guard: Reserve revocation capacity per code or record revocation in its reserved tombstone; preserve unexpired revocations.
Consequence: Issued tokens remain usable because family revocation cannot be recorded.

### E3 — architecture.md ADR-009 Notification abuse; epics.md Story 2.5
New identifiers arrive after the bounded target-bucket map fills.
Suggested guard: Refuse new entries without upstream pushes, preserve active buckets and define idle expiry.
Consequence: Eviction resets abuse limits or undefined admission blocks legitimate login.

### E4 — architecture.md ADR-008 Client authentication; epics.md Story 2.4
Two requests concurrently present the same otherwise valid private_key_jwt assertion.
Suggested guard: Atomically insert-if-absent jti and enforce the per-client cap under the same lock; test concurrency.
Consequence: Both requests can pass a non-atomic replay check.

### E5 — architecture.md Flow state machine; ADR-010 Web2App return
The callback precedes the poll response containing signature.userChallenge.
Suggested guard: Validate available bindings immediately; retain the bounded verifier and compare when the signed poll result arrives.
Consequence: The callback-first path cannot perform its required verifier comparison.

### E6 — architecture.md ADR-010 Flow-scoped endpoints and Web2App return
Cookie rotation overlaps an original-tab request carrying the retired binding token.
Suggested guard: Reject retired bindings without state changes and render the continue-in-other-tab notice; test overlapping requests.
Consequence: An in-flight request can disrupt completion or show the wrong recovery page.

## Editorial findings

| Pass | Original Text | Revised Text | Changes |
|---|---|---|---|
| structure | epics.md §Execution packets and parent-story closure (631 words, lines 1291–1314) | MOVE after Overview and readiness; link story packet references. | Execution semantics follow almost the entire 16,022-word document; establish them before stories. 0 words removed. |
| structure | implementation-readiness-report §Architecture remediation (285 words) | MOVE immediately after Verdict. | Put corrected-but-not-rejudged status and current open matters before historical coverage. 0 words removed. |
| structure | prd.md §Initial release boundary (89), §Success and counter-metrics (114), §Constraints, assumptions and open decisions (181 words) | MOVE scope and success after vision; decisions before features. | Readers need delivery boundaries and gates before all 30 requirements. 0 words removed across 384 measured words. |
| structure | README.md §Continue work (141 words), after 376-word planning index | MOVE next-action paragraph below introduction; keep verification commands separately findable. | Immediate action is buried beneath the evidence catalog. 0 words removed. |
| structure | architecture.md §Decision index (294 words); §Status and authority (79 words) | MOVE Status and authority before the index. | Define proposal status and source authority before decision labels. 0 words removed. |
| structure | architecture.md §ADR-008 (1,206 words) | MOVE existing tables under descriptive subheadings for rules, bounds, claims, parameters and deviations. | Adds heading-based navigation without removing rules. A few heading words added. |
| structure | roadmap.md §Gates for every deferred GitHub issue (374 words), after 1,188 words of source inventories | MOVE after Dependency-ordered increments. | Place activation gates beside the delivery sequence. 0 words removed. |
| structure | epics.md §Non-functional requirements (527 words); addendum.md (5,399 words) | PRESERVE source material and local NFR reinforcement; identify PRD authority beside its copy. | Safety reinforcement and source fidelity justify retention. 0 words removed. |
| prose | readiness §Architecture remediation: Outside judges, run in this order: | Independent checks and reviews were run in this order: | Clarifies that the table records completed activity. |
| prose | readiness §Verdict: Full developer-ready planning for every deferred high-effort feature is intentionally gated on demand and a smaller verified decomposition. | Before a deferred high-effort feature is ready for development, confirm demand and split it into smaller, independently verifiable stories. | Replaces an abstract noun chain with prerequisites and timing. |
| prose | epics §Execution packets: The identifier DAG checks earlier-first prerequisite availability only. | The identifier-based directed acyclic graph checks only that each listed prerequisite has an earlier identifier. | Defines the acronym and the limited ordering check. |
| prose | readiness §Coverage result: K=1 subjective review cap; repair limit Kmax=3 for mechanical failures. | For the source-integration pass, subjective review was capped at one pass (K=1), and mechanical repairs at three rounds (Kmax=3). | Defines symbols and separates historical limits from later reviews. |
| prose | UX §Components: Bound CSS override cannot hide mandatory warnings or remove keyboard focus. | Consider: A permitted CSS override must not hide mandatory warnings or remove keyboard focus? | Clarify the undefined phrase; confirm intended customization policy. |
| prose | addendum introduction: This preserves source proposals and notes too detailed for the PRD. They are proposed, not implemented. | This addendum preserves source proposals and notes too detailed for the PRD. The proposed functionality is not implemented. | Clarifies referents without altering preserved source proposals. |

Eight structure recommendations across 42,009 measured words. Estimated reduction: 0 words (0%); navigation headings add a few words. No length target was supplied. Source evidence, all original acceptance criteria, safety reinforcement and diagrams remain preserved.

Suggested next action: reconcile the behavioral contracts in architecture and story ACs, then run the readiness gate before committing Epic 2. This review does not supersede the foundation packet guidance.
