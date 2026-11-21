---
title: eidbridge sprint change proposal – owner gate override
status: accepted-by-owner
created: 2026-11-20
trigger: project owner instruction of 2026-11-20 (full build of all 30 stories)
---

# Sprint change proposal – owner gate override (2026-11-20)

## Decision

On 2026-11-20 the project owner overrode every activation, demand, deferral and stop/replan gate in the planning set. No such gate blocks implementation any more. All 30 stories across all 8 epics are in scope, in this order:

1. Core packets 1–16 in [epics](epics.md#execution-packets-and-parent-story-closure): LEGAL → SCAFFOLD → LOGS → SPIKE → CLIENT → TRUST → AUTHN → OIDC → WEB → PRIVACY → ENV → NOTIFY → INTEGRATION → DOCS → RELEASE (local evidence only) → ADOPTION.
2. Epics 4–8: 4.1 chooser → 4.2 Mobile-ID → 5.1 Web eID → 6.1 EUDI/OpenID4VP → 6.2 conformance harness → 7.3 doctor → 7.4 mock RP API → 7.5 RP API v2 → 7.2 Python client → 7.1 Keycloak SPI → 7.6 WordPress → 8.1 signing sessions.

Gates are now **disclosure requirements, not blockers**. Every unmet gate below must be listed beside its feature in the PR description, in the final report and in `sprint-status.yaml` (`done-with-disclosure`), until real evidence closes it.

What the override does **not** change:

- Every original acceptance criterion still needs real evidence (commit plus test output) before a story is `done` or `done-with-disclosure`. A finished packet does not close its parent story.
- High-effort stories (5.1, 6.1, 6.2, 8.1, and any other the plan flags) are decomposed into child stories appended to [epics](epics.md) before implementation.
- Privacy, logging, demo/production and trust NFRs apply to every method. Mobile-ID, Web eID and EUDI go through the method-neutral `authn` interface and the single OIDC issuer; no second protocol codebase.
- Out of scope (owner-controlled public actions): publishing to GHCR, PyPI, Maven or WordPress.org; tagging releases; editing GitHub issues; public posts or outreach.
- Live dependencies (Smart-ID demo approval, Mobile-ID demo, Web eID test cards, test EUDI wallet, real IdP versions) are used when available; otherwise spec-derived fixtures are used and live evidence is recorded as **NOT RUN**. No live result is claimed that was not observed.
- Source research, the GitHub snapshot, `tools/verify_bmad_artifacts.py` and its expectations stay unchanged.

## Overridden gates

Each row: the original gate condition, whether it was met on 2026-11-20, and the evidence still missing. "Not met" means the gate condition was not demonstrated before implementation started; it is disclosed, not waived silently.

### Roadmap increments and execution gates

| ID | Feature guarded | Original gate condition (source) | Met on 2026-11-20? | Evidence still missing |
|---|---|---|---|---|
| G-R0 | Whole product (R0 feasibility, Story 1.4, ADR-001) | Six-hour public demo spike shows a verified device-link login; if demo access needs a contract or payment, or no verified path exists, stop and reconsider the product ([roadmap](roadmap.md#dependency-ordered-increments), [ADR-001](architecture.md#adr-001-validate-risky-access-before-building)) | No | A live `AUTHENTICATED` result with a verified certificate from `sid.demo.sk.ee` approved in the Smart-ID demo app; sanitized live fixtures; observed poll quota, session lifetime and callback-replay behavior. Outcome is recorded in `docs/adr/0001-spike-outcome.md`. |
| G-R1 | Feature expansion beyond the core (R1) | A verified OIDC round-trip inside the source week-2 ten-hour budget, else stop expansion and re-estimate | No | A live (non-fixture) OIDC round-trip; a measured effort figure against the ten-hour budget. |
| G-R2 | Launch of the hardened demo release (R2) | Data-flow/security/ops docs, five native-reviewed locales, release artifact evidence and a clean-clone stranger test under five minutes; a failed stranger test means no launch | No | Stranger test by a person who has not seen the project; native-speaker review of et, lv, lt, ru; published-artifact smoke test (publication is out of scope). |
| G-R3 | Native plugins and second protocol codebases (R3) | Do not add native plugins or a second protocol codebase to compensate for unfinished standard integration | No (overridden for 7.1 and 7.6 only) | Three concrete unmet config-only requests (Keycloak SPI); WordPress user requests. The Python client (7.2) is a separate deferred package with its own gate (G-25). |
| G-R4 | All deferred options (R4+, Epics 4–8) | Original per-issue gate plus a reviewed per-option implementation plan; no automatic activation | No | Per-issue evidence in the next table. Child-story decompositions in [epics](epics.md) stand in for the per-option plan; they are not an independent review. |
| G-SEC | Any production release | Security review of the actual implementation before any production release ([architecture status](architecture.md#status-and-authority)) | No | External security review of the implementation; no production release is claimed. |
| G-RDY | Sprint tracking refresh | A fresh readiness judgment with verdict PASS before `sprint-status.yaml` is refreshed ([2026-11-18 proposal](sprint-change-proposal-2026-11-18.md)) | No | A dated readiness re-judgment. Tracking is updated story by story from evidence instead. |
| G-SPLIT | High-effort stories | Child decomposition before sprint readiness ([readiness](implementation-readiness-report-2026-11-18.md#open-implementation-and-release-gates)) | Kept, not overridden | – (decompositions are appended to epics before each such story) |

### Open implementation questions (PRD Q-01 to Q-05)

| ID | Feature guarded | Original gate condition | Met? | Evidence still missing |
|---|---|---|---|---|
| Q-01 | Smart-ID client (FR-003), Web2App binding (ADR-010), capacity values | Resolve spike and exact protocol/profile before FR-003 | No | Live confirmation of callback parameters, callback replay handling, poll quota, `TIMEOUT` duration and certificate Subject name fields on the demo. Implementation follows the pinned RP API 3.2.8 docs. |
| Q-02 | Assurance and claims (`acr`), certificate status checks, `sub` default | Confirm assurance/claim mapping, certificate-status responsibilities and the pairwise `sub` default before production assertions | No | Smart-ID policy OIDs and minimum level from SK; who performs OCSP/CRL under a real RP agreement; owner confirmation of pairwise default. Until then production `acr` is never asserted higher than evidence supports, and the policy-OID list is operator configuration. |
| Q-03 | OIDC provider (FR-006) | Choose an OIDC library (and whether `private_key_jwt` ships in v1) and enumerate conformance-plan differences before FR-006 | No (decided by architecture recommendation, see ADR-0002) | Library evaluation record exists in `docs/adr/0002-oidc-library.md`; owner confirmation. |
| Q-04 | Capacity, token lifetime and rate values | Confirm measured capacity, token lifetime and rate values after the spike | No | Spike measurements (λ, W, RP quota). Provisional ADR-008 bounds are enforced; defaults are recorded as unmeasured. |
| Q-05 | Locales (FR-016) and IdP matrix (FR-015) | Native-speaker review and a concrete IdP matrix before the relevant release | No | Native review for et, lv, lt, ru (human follow-up); the IdP version matrix is recorded with dates in the IdP guides. |

### Per deferred story (roadmap "Gates for every deferred GitHub issue")

| ID | Story / feature | Original gate condition | Met? | Evidence still missing |
|---|---|---|---|---|
| G-20 | 4.1 method chooser | Demand for a second method; chooser and Mobile-ID activate together (ADR-006) | No | Any real deployment asking for a second method. |
| G-19 | 4.2 Mobile-ID | Stable Smart-ID path and deployments asking for Mobile-ID | No | Deployment demand; live Mobile-ID demo run (`tsp.demo.sk.ee`) with a demo phone number; demo trust rotation evidence. |
| G-21 | 5.1 Web eID (ID-card) | Concrete ID-card deployment, stable core, test hardware and **external security review**; split the 80–100 h work | No | No external security review; no real test-card run with the Web eID extension and a card reader; no deployment demand; no OCSP run against a real responder. |
| G-22 | 6.1 EUDI/OpenID4VP | Testable national or reference wallet, stable profile and RP demand; compare native IdP support first | No | No run with the EU reference wallet or a national test wallet; no RP access certificate or registration; profile versions are pinned by this team, not confirmed as stable; no comparison run against native IdP wallet support. |
| G-23 | 6.2 EUDI conformance harness | A verified wallet method and pinned profiles | No (depends on G-22) | A wallet method verified against a real wallet; the harness checks only this project's reading of the pinned specs and is not certification. |
| G-24 | 7.1 Keycloak SPI | At least three concrete unmet config-only integration requests; Java maintenance budget | No | Three user requests; maintenance budget decision. |
| G-25 | 7.2 Python client | At least two direct-library requests | No | Two user requests; second-language maintenance decision. PyPI publication is out of scope. |
| G-26 | 7.3 doctor | First outage that existing diagnostics fail to explain | No | Such an outage report. |
| G-27 | 7.4 standalone mock | External offline-test demand | No | External demand. |
| G-29 | 7.5 RP API v2 | A concrete deployment unable to use v3 | No | Such a deployment; live v2 demo run. |
| G-30 | 7.6 WordPress | WordPress users ask for login; standalone mock available | No (mock is built by 7.4) | User requests; WordPress.org publication is out of scope. |
| G-28 | 8.1 signing sessions | Stable v1 authentication plus a deployment signing need; split 40+ h work; independent container validator; legal/scope review | No | No deployment need; no legal or scope review; no live signing run; independent ASiC-E validation depends on tooling available locally (see the story evidence). No qualified-status claim. |

### Per-story human-review and live prerequisites

| ID | Story | Original requirement | Met? | Evidence still missing |
|---|---|---|---|---|
| H-12 | 1.1 | DCO check enabled on PRs; trademark complaint handling | Partly | DCO workflow is committed; enabling it as a required check is a repository setting the owner controls. Legal review is a human follow-up. |
| H-01 | 1.2 | Tag `v0.0.1-rc1` produces GitHub Release binaries, checksums and a pullable GHCR image; Dependabot opens a PR | No (out of scope) | Tagging and GHCR publication are owner actions. Local goreleaser snapshot and local image evidence only. |
| H-10 | 2.6 | GitHub private vulnerability reporting enabled | No | Repository setting the owner controls. |
| H-14 | 3.2 | Manual demo-app scan under five minutes | No | A human with the demo app. |
| H-15 | 3.5 | Keycloak guide verified manually once against the demo environment, screenshot | No | Human demo-app run; screenshot. |
| H-16 | 3.3 | Native-speaker review per language noted in PR | No | Native reviewers for et, lv, lt, ru (and en proofreading). |
| H-17 | 3.4 | Nightly workflow auto-opens an issue on a simulated pin mismatch | No | Workflow is committed; running it on GitHub and opening an issue is a remote action outside this task. |

## Implementation handoff

Implementation proceeds on branch `feat/full-build` with one atomic commit per packet or child story, test-first. Choices the planning set leaves open follow the architecture recommendation and are recorded as short ADR addenda in `docs/adr/`. Story status in `sprint-status.yaml` changes only with commit and test evidence; `done-with-disclosure` marks a story whose original criteria pass but whose overridden gate evidence (rows above) is still missing.
