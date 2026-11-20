---
title: eidbridge epic and story breakdown
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# eidbridge epic and story breakdown

## Overview and readiness

Thirty source-aligned stories preserve all 111 original issue acceptance criteria. No acceptance checkbox is checked. Source GitHub state is open for all issues; 19–30 are deferred. This is a backlog draft: high-risk or multi-week source issues retain their parent story and require the specified smaller work packets before sprint readiness. Do not mistake source estimates, a completed document or a passing coverage proxy for implemented functionality. The user requested batch integration; interactive workflow menus were bypassed and logged, not treated as approval.

Inputs: [PRD](prd.md), [architecture](architecture.md), [UX contract](ux-design-specification.md), [original proposals](addendum.md), [source reconciliation](source-reconciliation.md) and immutable [issue snapshot](research/github-issues-2026-11-18.json).

## Execution packets and parent-story closure

The numbered stories are source-aligned parents. Their original acceptance criteria sometimes need surfaces created later; a parent is not a safe all-or-nothing prerequisite. The identifier-based directed acyclic graph checks only that each listed prerequisite has an earlier identifier. Use the small packets below for execution; leave each parent backlog/in-progress until every original AC has real evidence. Parent #1 release publication and parent #12 final surface checks do not block the local spike. A parent's later regression is not an implementation prerequisite for its own foundation packet.

| Order / packet | Implement or verify | Prerequisite packet | Parent closure obligations that wait |
|---|---|---|---|
| 1 / PACKET-LEGAL | Project notices, clean-room/dependency rules and agreement boundary | none | #12 template/footer/image label and PR CI checks wait for their surfaces |
| 2 / PACKET-SCAFFOLD | Minimal Go module, unit/build/format/licence CI and test layout | LEGAL policy | #1 tagged artifacts/image/SBOM/Dependabot proof wait for release infrastructure |
| 3 / PACKET-LOGS | Typed safe logger and sink unit vectors for secrets/identifiers | SCAFFOLD | #9 full fixture-login DEBUG capture waits for INTEGRATION |
| 4 / PACKET-SPIKE | Capped demo access/challenge/verify experiment, sanitized fixtures and observed ADR | SCAFFOLD + LOGS + LEGAL | #2 closes only on actual observed result/fallback report, never a planned success |
| 5 / PACKET-CLIENT | Smart-ID create/poll/verify unit/negative/fuzz contract from fixtures | SPIKE evidence | #3 live opt-in and exact profile/status policy evidence remain explicit |
| 6 / PACKET-TRUST | Separate TLS/auth roots, normal TLS+pins, rotation/mixed-env unit tests | CLIENT fixtures | #8 security guide links and integrated start behavior wait for INTEGRATION/RELEASE |
| 7 / PACKET-AUTHN | Method contract, Smart-ID adapter and fake-backend tests | CLIENT | #5 dependency/import assertion becomes meaningful when OIDC packet exists |
| 8 / PACKET-OIDC | Static-client protocol endpoints, code store and negative tests using fake verified identity | AUTHN | #6 full conformance/live composition waits for WEB/INTEGRATION; disclose plan deviations |
| 9 / PACKET-WEB | Bound QR/same-device/status UI and config/health/headers | OIDC + TRUST + LOGS | #7 full login/accessibility/config-doc checks close with integrated run |
| 10 / PACKET-PRIVACY | Complete bounded lifecycle, cookies, egress and terminal deletion | WEB and OIDC stores | #10 isolation/cleanup proof waits for INTEGRATION, no persistent identity data |
| 11 / PACKET-ENV | Demo/prod startup invariants, markers and banner | WEB + TRUST | #11 client-side demo rejection closes with integration recipes |
| 12 / PACKET-NOTIFY | Opt-in identity input/verification code/rate controls | CLIENT + LOGS + WEB | #4 offline negative/live opt-in evidence remains required |
| 13 / PACKET-INTEGRATION | Fixture end-to-end login; rerun #9 DEBUG capture; verify #5 OIDC imports; finish #3/#4/#6/#7/#8/#10/#11 cross-layer checks | CLIENT through ENV; NOTIFY when exercising its flow | Parent partial work is not marked done by packet availability |
| 14 / PACKET-DOCS | Field inventory, five reviewed catalogs, compatibility/incident docs and demo instructions | INTEGRATION behavior | #12 surface notices, #13 claim/doc parity, #16 native review and #17 drills need actual evidence |
| 15 / PACKET-RELEASE | Clean-machine demo, conformance disclosure, actual artifact/provenance smoke and publication acceptance evidence | INTEGRATION + DOCS; explicit future publication context | #1/#12 close all artifact/CI surfaces; all core original AC required before release claim |
| 16 / PACKET-ADOPTION | Four-IdP/version matrix and Django/FastAPI examples | Stable integrated/demo behavior | #15/#18 original e2e and production rejection checks; may progress before actual public publication |

The packet graph has no backedge: later closure evidence does not gate earlier implementation. Each packet can be turned into a small implementation child story when work begins; this document does not mark those children done or assign invented test results. Deferred parent stories require their original activation gates and finer decomposition in addition to this core execution order.

## Requirements inventory

### Functional requirements and coverage

| Requirement | Source issue | Epic/story | State |
|---|---|---|---|
| FR-012 | #12 | E1 / 1.1 | backlog |
| FR-001 | #1 | E1 / 1.2 | backlog |
| FR-009 | #9 | E1 / 1.3 | backlog |
| FR-002 | #2 | E1 / 1.4 | backlog |
| FR-003 | #3 | E2 / 2.1 | backlog |
| FR-008 | #8 | E2 / 2.2 | backlog |
| FR-005 | #5 | E2 / 2.3 | backlog |
| FR-006 | #6 | E2 / 2.4 | backlog |
| FR-007 | #7 | E2 / 2.5 | backlog |
| FR-010 | #10 | E2 / 2.6 | backlog |
| FR-011 | #11 | E2 / 2.7 | backlog |
| FR-004 | #4 | E2 / 2.8 | backlog |
| FR-013 | #13 | E3 / 3.1 | backlog |
| FR-014 | #14 | E3 / 3.2 | backlog |
| FR-016 | #16 | E3 / 3.3 | backlog |
| FR-017 | #17 | E3 / 3.4 | backlog |
| FR-015 | #15 | E3 / 3.5 | backlog |
| FR-018 | #18 | E3 / 3.6 | backlog |
| FR-020 | #20 | E4 / 4.1 | deferred |
| FR-019 | #19 | E4 / 4.2 | deferred |
| FR-021 | #21 | E5 / 5.1 | deferred |
| FR-022 | #22 | E6 / 6.1 | deferred |
| FR-023 | #23 | E6 / 6.2 | deferred |
| FR-024 | #24 | E7 / 7.1 | deferred |
| FR-025 | #25 | E7 / 7.2 | deferred |
| FR-026 | #26 | E7 / 7.3 | deferred |
| FR-027 | #27 | E7 / 7.4 | deferred |
| FR-029 | #29 | E7 / 7.5 | deferred |
| FR-030 | #30 | E7 / 7.6 | deferred |
| FR-028 | #28 | E8 / 8.1 | deferred |

### Non-functional requirements

The [PRD](prd.md#cross-cutting-non-functional-requirements) is authoritative for NFR definitions. This synchronized copy keeps safety constraints beside stories; update both together. Original source criteria remain preserved with explicit reconciliation.

- **NFR-001:** Authentication fails closed on tampered signatures, wrong challenge/identity, untrusted or expired certificates and insufficient requested level; Verify coverage at least 90% per issue #3.
- **NFR-002:** No raw personal codes, certificates, signatures, authorization codes, tokens or secrets in any log level, including DEBUG/error wrapping; redaction cannot be disabled.
- **NFR-003:** Flow/code data is memory only. Delete terminal flows after required one-use code exchange; unfinished flows expire at flow timeout plus 30 seconds. Default pending-flow ceiling 10,000, with an independently sized code-store ceiling covering reservations, codes and retained tombstones (a slot and its family-index overhead are reserved when a flow is created; replay revocation needs no extra capacity) and per-IP and per-client quotas inside the global ceiling. Overflow returns 503 with `Retry-After`; pending and verified entries are never evicted. TTLs use the monotonic clock; sealed tokens authenticate a process epoch and monotonic acceptance deadline, so wall-clock rollback cannot outlive replay protection.
- **NFR-004:** No telemetry, analytics, crash uploads, update beacons or uncontrolled egress. Fixture login succeeds with unrelated egress blocked. Opt-in upstream checks use configured endpoints only.
- **NFR-005:** Codes are single-use, 60-second TTL maximum and bound to client, exact redirect URI and S256 verifier; require state/nonce; reject replay and expiration. Any failed exchange (PKCE, client authentication or redirect URI) still consumes the code, and a replayed code revokes its token family. Access tokens are opaque, sealed, valid for five minutes at most, and userinfo is their only claim source.
- **NFR-006:** Normal TLS chain/hostname validation remains enabled, TLS 1.2 minimum, current and next pins. Explicit pin disable preserves CA validation and creates a warning and deviation; in production it also requires an acknowledgement flag, and startup fails without it.
- **NFR-007:** The mode (`demo` or `production`) is required, with no default. Production requires RP identity, operator-supplied signing key and HTTPS issuer; it rejects demo identity, endpoint, CA, fixture keys and keys matching explicitly supplied demo-key fingerprint deny-lists (unknown historical provenance cannot be inferred from key bytes; operators generate fresh production keys) and mixed trust, and demo mode rejects the production equivalents. Demo tokens carry `acr=demo` and `eid_env=demo`, use a distinct issuer path and are signed with a demo-labelled key.
- **NFR-008:** Static linux/darwin amd64/arm64 release targets, non-root image under 20 MB, checksums/SBOM, licence/formatting gates. Artifact size/reproducibility must be measured, not assumed.
- **NFR-009:** Clean clone reaches QR without credential configuration; prepared demo-app login completes under five minutes. Record unprepared setup/registration time separately.
- **NFR-010:** Keyboard/screen-reader access and no serious axe-core violations. All five catalogs cover the English key set and receive native-speaker review.
- **NFR-011:** Synthetic/demo fixtures, offline negative tests, explicit opt-in live checks. Conformance evidence pins suite/profile/commit/date and distinguishes PASS/FAIL/WARNING/NOT RUN.
- **NFR-012:** Nominative scheme references only, no marks or endorsement/compliance/QES claims; clean-room/permissive-dependency guardrails are not legal clearance.
- **NFR-013:** API/CA/pin changes have a runbook, compatibility/deviation disclosure and key-rotation recovery exercise; fixes ship in the latest minor release, and trust fixes are backported one minor release, subject to capacity. The recovery exercise covers planned key rotation and emergency key revocation separately.
- **NFR-014:** Initial deployment is single replica/no shared store; document restart loss, client retry, trusted proxy headers, size and poll limits, and readiness. Readiness covers configuration and key load only; saturation is a per-request 503, never a readiness failure. On SIGTERM readiness fails, new authorizations and QR page loads stop, and the process drains until every issued code has expired or the grace period ends. No unmeasured SLA.

### Additional architecture requirements

No starter template/database is preselected. Scaffold only what the first flow needs. Protocol verification precedes trusted identity; OIDC/web depend on authn contract. Persistent operator keys are separate from transient identity data. Fixture CI precedes optional live automation. Release safety spans all epics and cannot be removed because comparative rankings omit it. Dependency additions beyond original issue prose order prerequisite packets, not whole-parent completion; integrated closure checks are separate below. GitHub remains unchanged.

### UX design requirements

- **UX-DR-001:** Dynamic desktop QR and same-device button reflect one bounded flow; stale QR/late completion cannot revive it.
- **UX-DR-002:** Waiting, code comparison, refusal, timeout, invalid input, retry and upstream failure have distinct localized accessible text with no personal-data errors.
- **UX-DR-003:** Persistent demo banner and unofficial footer; production examples reject demo assertions.
- **UX-DR-004:** Keyboard access, visible focus, associated labels, bounded status announcements and no focus theft on QR refresh; axe covers success/error screens.
- **UX-DR-005:** ui_locales then Accept-Language then configured default; html lang and locale persist across handoff/errors; include ru from issue body.
- **UX-DR-006:** Notification requires explicit enablement, country/checksum validation, anti-enumeration response and per-client/IP rate control.
- **UX-DR-007:** Future chooser respects client methods/assurance, bypasses single-method step; preference cookie is opt-in/non-identifying/short-lived.
- **UX-DR-008:** Neutral server-rendered visual treatment, accessible contrast, no scheme logos/copied UI/tracking assets; final design tokens remain design work.

UX coverage: UX-DR-001/002/004/008 → Story 2.5; UX-DR-003 → 2.7 and 3.2; UX-DR-005 → 3.3; UX-DR-006 → 2.8; UX-DR-007 → 4.1. NFR coverage: 001→2.1/2.2; 002→1.3; 003/004→2.6; 005→2.4; 006→2.2; 007→2.5/2.7; 008→1.2; 009→3.2; 010→2.5/3.3; 011→2.1/2.4/3.2/6.2; 012→1.1; 013→3.4; 014→2.5/2.6/3.1.

## Epic list

- **Epic 1: Establish a lawful, testable demo feasibility decision.** An evaluator/maintainer has a safe reproducible foundation and measured evidence that the chosen authentication path can work.
- **Epic 2: Complete a verified private authentication round-trip.** An end user completes verified Smart-ID login through one OIDC interface with environment, trust and data-lifecycle protections.
- **Epic 3: Evaluate, operate and integrate the bridge.** A new operator can run the demo, assess data handling, use reviewed locale text and maintain/integrate the release.
- **Epic 4: Add a demanded second national authentication method.** Only after demand: users can choose Smart-ID or Mobile-ID without changing client integration.
- **Epic 5: Enable independently reviewed ID-card login.** Only after demand/hardware/review gates: ID-card users get origin-bound verified login.
- **Epic 6: Enable testable wallet authentication.** Only after demand, pinned profiles and test wallet access: verified PID presentation reaches the same issuer with transparent evidence.
- **Epic 7: Serve demonstrated ecosystem and diagnostic gaps.** Each independently gated package or guide closes a documented gap without expanding default runtime scope.
- **Epic 8: Evaluate a separate signing-session capability.** Only after stable authentication and demand: an authenticated digest-relay experiment is evaluated without qualified-service claims.

## Epic 1: Establish a lawful, testable demo feasibility decision

An evaluator/maintainer has a safe reproducible foundation and measured evidence that the chosen authentication path can work.

### Story 1.1: Add unofficial-project notice, trademark policy and clean-room rules

As a contributor,
I want to follow explicit unofficial-project, attribution and clean-room rules,
So that the project preserves its stated licence and compatibility boundaries.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Integrators and their legal reviewers need to know up front what the bridge is and is not: it is RP-side software, not a certified identity provider, and it does not resell or meter eID transactions. Contributors need clear rules so that no incompatibly licensed code or proprietary documentation text enters the repo.

**Requirement:** FR-012. **Source:** GitHub issue #12; original specification _issues/skid/12-legal-notices-clean-room.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** none.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Disclaimer present in README, login page template and container image labels (`org.opencontainers.image.description`)
- [ ] `docs/legal.md` and `CONTRIBUTING.md` merged and linked from README
- [ ] DCO check enabled on PRs
- [ ] CI check that no file under `docs/spec-pins/` contains copied spec text beyond links and version metadata

**And — reconciliation and safety:** Use neutral package/image/module names. Record dual-license/NOTICE/DCO guardrails as project policy; avoid legal/endorsement claims unsupported by evidence.

**Implementation contract:** Document the project's legal stance on every user-facing surface: unofficial and not affiliated with any eID scheme operator, nominative use of scheme names only, clean-room implementation from published specs, and integrators bring their own production agreements. Full proposal, APIs, exclusions and notes are retained in addendum issue #12.

**Original effort, dependency prose and activation gate:**

Effort: ~1.5 h. No code dependencies. If a trademark complaint arrives, comply first (rename/rewording), discuss later.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 1.2: Scaffold Go module with CI, licence checks and release automation

As an operator,
I want to build and verify portable binaries and a container from a controlled source skeleton,
So that I can inspect and reproduce what I deploy.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Everything else in the roadmap lands on top of this. Integrators evaluating an authentication component need reproducible builds, checksummed artifacts and a dependency licence report before they will run it in front of their IdP.

**Requirement:** FR-001. **Source:** GitHub issue #1; original specification _issues/skid/01-scaffold-ci-release.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** none.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go build ./... && go vet ./... && go test ./...` passes locally and in CI on an empty skeleton
- [ ] CI fails on unformatted code and on a dependency with a disallowed licence
- [ ] Pushing tag `v0.0.1-rc1` produces GitHub Release binaries, `checksums.txt` and a pullable `ghcr.io/tomkabel/eidbridge:v0.0.1-rc1`
- [ ] Image size < 20 MB, runs as non-root
- [ ] Dependabot opens a PR on a pinned dependency bump
- [ ] README shows a CI status badge

**And — reconciliation and safety:** Add source-build/provenance instructions, independent rebuild evidence or documented variance, and smoke checks of the actual release artifact. Package publication is acceptance work for implementation, not an action performed by this planning pass.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A16] Given the CI pipeline runs, when `tools/check-arch-trace` finds any open review finding (missing Review resolution row, anchor, story AC line or gate), then the CI job fails the build. Test: `check-arch-trace`.

**Implementation contract:** Create the repository skeleton for `eidbridge` (single Go binary), a CI pipeline that gates every PR, and a tag-driven release pipeline that publishes binaries and a container image. Full proposal, APIs, exclusions and notes are retained in addendum issue #1.

**Original effort, dependency prose and activation gate:**

Effort: ~4 h. No dependencies. Keep dependencies to stdlib plus a minimal, permissively licensed set; every addition must appear in the `go-licenses` report.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 1.3: Redact personal identity codes at the log sink

As an operator responsible for personal data,
I want to prevent raw identifiers and secrets from entering any log level,
So that diagnostics do not disclose authentication data.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The bridge handles given name, surname, country and national personal code for every login, plus certificates that embed the same data. Personal codes are high-risk identifiers in Estonia, Latvia and Lithuania. Logs get shipped to third-party aggregators, kept for months and read by many people; redacting at the call site is error-prone, so the guarantee has to sit at the sink.

**Requirement:** FR-009. **Source:** GitHub issue #9; original specification _issues/skid/09-pii-log-redaction.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 1.2.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Table-driven tests for each identifier format and for PEM/base64 masking
- [ ] Integration test: full fixture login at DEBUG level; captured log output contains no fixture personal code, cert or signature
- [ ] CI step `grep -rn "personalCode\|IDCode" internal/ | grep -v logx` reviewed: no raw logging calls
- [ ] `docs/security.md` documents what is logged at each level

**And — reconciliation and safety:** DEBUG warning cannot exempt any level from redaction. Primary control is excluding PII/secrets; backstop masks nested fields, error wrappers and long blobs.

**Implementation contract:** Ensure national personal identity codes, certificates, signatures and session secrets never reach logs in full. Redaction happens in the log handler itself and cannot be disabled by configuration. Full proposal, APIs, exclusions and notes are retained in addendum issue #9.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Scaffold Go module with CI, licence checks and release automation". Regex masking is a backstop; the primary control is not passing identity data to the logger at all.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 1.4: Spike Smart-ID v3 device-link login against the public demo env

As a maintainer,
I want to test public demo authentication within a six-hour cap,
So that I can decide whether the proposed product is feasible before expanding it.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The whole project assumes a relying party can develop against `https://sid.demo.sk.ee/smart-id-rp/v3/` using the documented public demo relying party (UUID `00000000-0000-4000-8000-000000000000`, name `DEMO`) and a self-registered Smart-ID demo app account, with no contract. If that is false, the architecture changes. Validate the riskiest assumption first, with a time cap.

**Requirement:** FR-002. **Source:** GitHub issue #2; original specification _issues/skid/02-smartid-device-link-spike.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 1.2, 1.3, 1.1.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go run ./cmd/sidspike` exits 0 with `AUTHENTICATED` and a verified certificate for a demo account, or the ADR documents which fallback was taken and why
- [ ] Captured request/response pairs (with demo data only) saved as test fixtures under `internal/smartid/testdata/`
- [ ] ADR states whether the demo env offers a scriptable test endpoint usable in CI

**And — reconciliation and safety:** Run under safe logging even though the original spike prints subject fields. Record real demo access and stop/replan on a changed product. No copy of unlicensed spec prose; retain URL/version/hash metadata.

**Implementation contract:** Build a throwaway `cmd/sidspike` that completes one Smart-ID RP API v3 device-link authentication against the public demo environment, end to end, and record the outcome before any production code is written. Full proposal, APIs, exclusions and notes are retained in addendum issue #2.

**Original effort, dependency prose and activation gate:**

Effort: 6 h hard cap. Depends on: "Scaffold Go module with CI, licence checks and release automation". Implement clean-room from the published protocol spec; do not copy from LGPL-licensed demo applications or unlicensed documentation repositories. If demo account registration requires a contract or payment, stop and write a post-mortem instead.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 2: Complete a verified private authentication round-trip

An end user completes verified Smart-ID login through one OIDC interface with environment, trust and data-lifecycle protections.

### Story 2.1: Implement Smart-ID RP API v3 client with signature verification

As an integrator,
I want to receive identities only after full challenge, signature and certificate verification,
So that untrusted upstream responses cannot become successful logins.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The response from the RP API is only trustworthy after the relying party verifies the signature over its own challenge and validates the certificate chain and certificate level. Getting this wrong is an authentication bypass. Existing Go wrappers are stale or do not cover v3 device-link flows, so the bridge needs its own, tested client.

**Requirement:** FR-003. **Source:** GitHub issue #3; original specification _issues/skid/03-smartid-rp-v3-client.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 1.4.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go test ./internal/smartid/` passes using recorded fixtures (from the spike) with no network
- [ ] Negative tests: tampered signature, wrong challenge, expired cert, untrusted chain, lower cert level — all rejected
- [ ] Live test against the demo env runs only when `EIDBRIDGE_LIVE=1`
- [ ] Fuzz test for response JSON parsing (`go test -fuzz`)
- [ ] Coverage of `Verify` >= 90%

**And — reconciliation and safety:** Use fail-closed typed results and bounded retries/cancellation; never produce Identity from COMPLETE alone. Record selected profile/status-check responsibilities before production claims.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [E02] Given a Smart-ID session ends with `COMPLETE` and a non-OK `endResult`, when the exhaustive `endResult` table is applied, then refusal maps to `refused`, timeout to `expired`, and other failures, unknown values and malformed responses to `failed`, never success. Test: `TestEndResultMappingExhaustive`.
- [E02] Given revocation status is unknown, stale or unreachable, when the certificate is verified, then the flow is `failed` (`status_unavailable`), never `verified`, and no fetch goes to an unlisted host. Test: `TestRevocationUnavailableFailsFlow`.
- [E02] Given a certificate and signed payload, then `signatureAlgorithm` must be RSASSA-PSS with SHA-256 or stronger, the accepted EKU profiles and `shareMdClientIpAddress=false` are enforced, and poll, OCSP and CRL fetches obey timeout, size, no-redirect and allow-list limits. Test: `TestVerificationParametersAndStatusFetchLimits`.

**Implementation contract:** Add `internal/smartid`: a Go client for Smart-ID RP API v3 that creates device-link authentication sessions, polls status, and cryptographically verifies the result, with a demo/production endpoint switch. Full proposal, APIs, exclusions and notes are retained in addendum issue #3.

**Original effort, dependency prose and activation gate:**

Effort: ~4 h. Depends on: "Spike Smart-ID v3 device-link login against the public demo env". Pin the implemented protocol version in `docs/spec-pins/`. Official MIT-licensed clients may be consulted and reused with the licence notice kept in `NOTICE`.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.2: Pin RP API TLS certificates and make trust anchors configurable

As an operator,
I want to configure, inspect and rotate separate endpoint pins and authentication trust,
So that I can maintain verified connectivity without silently weakening TLS.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The RP API documentation asks relying parties to pin the API server certificate. A bridge that silently trusts the system CA store weakens the chain for every integrator. Server-side TLS policy changes (cipher suite removals) and certificate renewals also break pinned clients, so pins must be updatable without a rebuild.

**Requirement:** FR-008. **Source:** GitHub issue #8; original specification _issues/skid/08-tls-pinning-trust-anchors.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Unit test with a local `httptest.NewTLSServer`: matching pin succeeds, mismatching pin fails
- [ ] Pin rotation: two pins configured, either accepted
- [ ] Production mode refuses to start with an empty pin set unless `EIDBRIDGE_SMARTID_TLS_PINS=disabled` is set explicitly, which logs a warning
- [ ] `docs/security.md` documents how to update pins and CA bundles after a certificate renewal

**And — reconciliation and safety:** Explicit pin-disable only bypasses extra pin check, never CA/hostname verification; log/disclose deviation. Trust groups cannot mix demo/prod; status-policy question remains explicit.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [E17] Given production mode with `TLS_PINS=disabled`, when the second acknowledgement flag is absent, then startup fails; with the flag it starts with a warning and writes the deviation record. Test: `TestPinDisableRequiresAcknowledgement`.
- [E17] Supersedes the original pin-disable criterion above: in production, `EIDBRIDGE_SMARTID_TLS_PINS=disabled` alone fails startup; the acknowledgement flag is also required. Test: `TestPinDisableRequiresAcknowledgement`.
- [E17] Given `TLS_PINS` unset, empty, unparsable or without a current pin and not `disabled`, then startup fails in both modes; `disabled` in demo mode starts with a warning. Test: `TestTLSPinsInvalidValuesFail`.

**Implementation contract:** Harden the outbound HTTPS connection to the RP API: pin the server certificates or public keys as recommended by the protocol documentation, use a modern cipher configuration, and load authentication-certificate trust anchors from config. Full proposal, APIs, exclusions and notes are retained in addendum issue #8.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Risk: pins in a release go stale on server cert renewal; the maintenance runbook issue covers tracking renewals and shipping patch releases.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.3: Define a method-neutral authenticator interface for eID backends

As a method implementer,
I want to provide verified results through one tested internal contract,
So that new methods can reuse the existing issuer.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Relying parties in the Baltics routinely need more than one method. If the OIDC provider is coupled to Smart-ID types, every later method is a rewrite of the provider and the claims mapping. A narrow interface keeps the OIDC surface stable and lets methods be enabled by configuration.

**Requirement:** FR-005. **Source:** GitHub issue #5; original specification _issues/skid/05-authenticator-interface.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Smart-ID client wrapped as `authn.Method`; OIDC package imports only `internal/authn`
- [ ] `authntest.Run(t, method)` contract suite passes for Smart-ID with fixtures
- [ ] A fake method in tests proves a second backend needs no OIDC changes
- [ ] Interface documented in `docs/architecture.md` with a versioning note (internal, may change before v1.0)

**And — reconciliation and safety:** Keep registry and interface internal. Browser protocol details remain server owned; fake method exercises chooser before a real second backend exists.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- Supersedes the chooser sentence above: the fake method exercises only the registry contract; the chooser UI activates together with Mobile-ID on real demand (ADR-006). Test: `TestRegistryContractFakeMethod`.

**Implementation contract:** Introduce `internal/authn` with a small interface that every eID method (Smart-ID now; Mobile-ID, Web eID, EUDI Wallet later) implements, so the OIDC layer and login page never import a method package directly. Full proposal, APIs, exclusions and notes are retained in addendum issue #5.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Keep it internal until at least two real methods exist; the second implementation will reveal what the interface got wrong.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.4: Expose eID logins as a standard OpenID Connect provider

As an OIDC client integrator,
I want to complete a bound authorization-code and PKCE flow,
So that my application can consume verified login using standard client behavior.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Every IdP and most web frameworks already speak OIDC. Making the bridge an OIDC provider means one integration covers them all, and the IdP keeps ownership of users, sessions and account linking. The alternative, a plugin per IdP, has historically been abandoned within a year.

**Requirement:** FR-006. **Source:** GitHub issue #6; original specification _issues/skid/06-oidc-provider.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.3.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go test ./internal/oidc/` covers discovery, code exchange, PKCE failure, code replay, wrong redirect URI, expired code
- [ ] ID token validates with `github.com/coreos/go-oidc` in a test client
- [ ] `curl /.well-known/openid-configuration | jq` returns a valid discovery document
- [ ] OpenID Foundation conformance suite "Basic OP" plan run locally; results recorded in `docs/conformance.md`

**And — reconciliation and safety:** Resolve subject linkability, token lifetime/userinfo lifecycle and actual acr mapping; no raw personal code by default. Record Basic OP suite plan/profile/deviations and test negative flows without adding unrequested protocol surface.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A02] Given a valid code exchange, when the client calls userinfo with the opaque access token, then the bridge decrypts the AEAD-sealed token (`client_id` inside the sealed payload) and returns the authorized claims with no server-side claim cache. Test: `TestUserinfoFromSealedAccessToken`.
- [A03] Given public or pairwise mode, when an ID token is issued, then `sub` is `HMAC-SHA256(K_sub[v], ...)` over sector, certificate identifier type, country and code, and a raw or plainly hashed personal code is never emitted as `sub`. Test: `TestSubIsKeyedHMACNotPersonalCode`.
- [A04] Given the pairwise secret `K_sub` is rotated, when a declared client logs in during the migration window, then the ID token carries both new `sub` and `previous_sub`, and the key id is versioned; rotation is a migration event, not routine. Test: `TestSubKeyVersionMigration`.
- [A06] Given a client registered for `private_key_jwt`, when its registration supplies `jwks_uri` rather than an inline static JWKS, then registration is rejected and the bridge makes no outbound fetch for client keys. Test: `TestPrivateKeyJWTRejectsJWKSURI`.
- [A07] Given an authorize request whose `acr_values` the bridge cannot prove, when it is processed, then the response is `unmet_authentication_requirements` and assurance is never silently downgraded. Test: `TestAuthorizeUnprovableACRFails`.
- [E07] Given two concurrent token requests present the same authorization code, when both are processed, then one atomic consume retains the family tombstone before unlocking, lets exactly one succeed and the other fails, so only one token set is issued. Test: `TestConcurrentCodeExchangeSingleWinner`.
- [E08] Given a valid code presented with a failed PKCE, client-authentication or `redirect_uri` check, when the exchange fails, then the code is still consumed and a retry with correct parameters fails. Test: `TestFailedExchangeStillConsumesCode`.
- [E13] Given a planned signing-key rotation followed by a restart, when a pre-restart ID token is verified, then the retired public key persisted with its `not_after` time is still in JWKS and verification succeeds. Test: `TestRetiredKeysSurviveRestart`.
- [E14] Given a client's `sub_mode` or `sector_id` changes, or `K_sub` is rotated in place, when configuration loads, then startup is rejected unless the same migration is declared. Test: `TestSubKeyOrModeChangeNeedsMigration`.
- [E22] Given both RS256 and ES256 keys are active, when an ID token is issued, then it is signed per the client's `id_token_signed_response_alg` (default RS256), and an unsupported algorithm in a registration fails startup. Test: `TestIDTokenAlgPerClient`.
- [A07] Given any authorization response, success or error, when it is built, then it carries `iss` equal to the discovery issuer and discovery sets `authorization_response_iss_parameter_supported`. Test: `TestAuthorizeResponseCarriesIss`.
- [A07] Given `prompt=none`, then the bridge returns `login_required`; given `max_age`, then `auth_time` is present; given `claims`, `request` or `request_uri`, then they are rejected as unsupported. Test: `TestAuthorizePromptAndMaxAge`.
- [A07] Given an unregistered client or `redirect_uri`, then an error page renders and no redirect happens; post-login redirects after a POST use HTTP 303. Test: `TestInvalidClientRendersErrorPageAnd303`.
- [A02] Given token and userinfo requests, then responses carry `Cache-Control: no-store` and userinfo accepts the `Authorization` header only, never a query parameter. Test: `TestTokenAndUserinfoNoStoreHeaderOnly`.
- [E14] Given production mode with `K_sub` missing or its version unset, then startup fails. Test: `TestProductionFailsWithoutSubKey`.
- [A02] Given scopes `openid`, `profile` and the `personal_code` allow-list, when claims are issued, then each scope yields only its claims, a missing `openid` returns `invalid_scope`, and `given_name` and `family_name` appear only when the verified certificate carries them. Test: `TestScopeToClaimsMapping`.
- [A06] Given `private_key_jwt`, then `aud` must equal the issuer, `iss` and `sub` the `client_id`, `exp` within 60 seconds, `alg` RS256 or ES256, and a reused or overflowing `jti` store is refused. Test: `TestPrivateKeyJWTAssertionRules`.
- [A03] Given a certificate `serialNumber`, then it parses only as `PNO`, `PAS` or `IDC` plus country and code, anything else is rejected, and fixed test vectors give identical `sub` values across builds. Test: `TestSubParsesSerialNumberAndRejectsOtherForms`.
- [E08] Given wrong-then-correct presentation, the initial failed exchange leaves a familyless tombstone and later attempts return `invalid_grant`; given correct-then-wrong presentation, the original family remains and is revoked, so userinfo refuses its token. No later failure erases a successful family. Test: `TestFailedExchangeLeavesFamilylessTombstone`.
- [E08] Given generated codes, binding tokens, flow IDs, callback values and family IDs, then lengths meet 256 or 128 bits from `crypto/rand`, codes are stored as SHA-256, and secret comparisons are constant-time. Test: `TestRandomValueEntropyAndConstantTimeCompare`.
- [A07] Given authorize and userinfo requests by GET and by POST, then validation is identical and userinfo takes the bearer token from the header only. Test: `TestAuthorizeAndUserinfoAcceptGetAndPost`.
- [E07] Given two concurrent presentations of one code, then the loser reads the consumed entry's family and deny-lists it, and the winner's tokens are rejected at userinfo. Test: `TestConcurrentExchangeLoserDenyListsWinnerFamily`.
- [A02] Given a sealed token with `iat` and `exp`, then userinfo rejects it when `exp - iat` exceeds the maximum lifetime. Test: `TestUserinfoRejectsExpIatBeyondMaxLifetime`.
- [E13] Given signing keys, then RSA is at least 2,048 bits, ES256 uses P-256, production `kid` is the JWK thumbprint and demo `kid` is `demo-` plus that thumbprint, and a key file not at mode 0600 fails startup. Test: `TestSigningKeyParametersAndFileMode`.
- [A06] Given a client registered for one authentication method, when a request carries a different method or credentials of two methods, then it is `invalid_client`. Test: `TestSingleRegisteredClientAuthMethod`.
- [A07] Given a repeated parameter, a missing `redirect_uri`, a `response_type` other than `code`, over-long `state` or `nonce`, or a `code_verifier` outside 43 to 128 characters, then the request is `invalid_request`. Test: `TestAuthorizeParameterHygiene`.

**RV resolution acceptance criteria (2026-11-18):**

- TestReplayAtFullCapacityUsesReservedTombstone: successful exchange retains its family; replay at full capacity sets its reserved revoked flag without allocation; missing or revoked families fail userinfo.
- TestConcurrentClientAssertionReplayRejected: simultaneous uses of one valid jti permit exactly one atomic insertion; full capacity preserves unexpired entries.
- TestDemoLoopbackRedirectPolicy: production rejects HTTP callbacks; demo allows only exact static http://localhost:<port>/<path> registrations without wildcards, userinfo or fragments.
- TestSealedTokenEpochAndVersionValidation: unknown epochs, invalid formats and retired sealing keys fail; restart rejects earlier tokens.

**Implementation contract:** Add `internal/oidc`: a minimal OpenID Connect provider (authorization code flow with PKCE) so Keycloak, authentik, Zitadel, Ory and plain OIDC client libraries can consume eID logins as an ordinary external identity provider, with no plugin code. Full proposal, APIs, exclusions and notes are retained in addendum issue #6.

**Original effort, dependency prose and activation gate:**

Effort: ~3-4 h. Depends on: "Define a method-neutral authenticator interface for eID backends". Prefer a small, audited OIDC library over hand-rolled JWT code if one fits without pulling in a large dependency tree.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.5: Wire eidbridge binary with login page, QR and Web2App flows

As a user arriving from an OIDC client,
I want to complete an accessible QR or same-device handoff and understand its result,
So that I can finish or retry the correct authentication flow.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The bridge is only useful if a user arriving from the IdP redirect sees a working, accessible login page on both desktop (scan QR) and mobile (tap to open the app), and if operators can configure it with environment variables alone.

**Requirement:** FR-007. **Source:** GitHub issue #7; original specification _issues/skid/07-binary-login-page-config.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.4, 2.1, 2.2.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go run ./cmd/eidbridge --demo` serves a QR on `http://localhost:8080` and completes a login with the demo app
- [ ] Startup fails with a clear error if production mode lacks RP UUID/name or signing key
- [ ] Page passes axe-core accessibility checks with no serious violations
- [ ] `docs/configuration.md` generated or checked in CI against the config struct

**And — reconciliation and safety:** Trust proxy headers only from configured hops. Bound body/polling/flow identifiers, set CSP consistently with self-hosted QR polling scripts, and avoid exposing status across sessions.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A08] Given the pending-flow cap or a per-IP or per-client bucket is exhausted, when an authorize request arrives, then the bridge returns 503 with `Retry-After`, creates no upstream session, and never evicts pending or verified entries. Test: `TestOverflowReturns503WithRetryAfter`.
- [A09] Given many concurrent flows, when polling upstream, then one server-side poller behind a global concurrency semaphore and rate limit bounds upstream calls, the browser polls only local state, and an abandoned flow stops its local poll (the pinned v3 API has no cancel). Test: `TestSinglePollerBoundsUpstreamConcurrency`.
- [A10] Given a flow is created, when the response is sent, then the cookie is `__Host-eidb-<flow-id>` with `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` and `Max-Age` derived from the original absolute deadline (`flow_ttl` plus 30 seconds); rotation and reload use remaining lifetime only. Test: `TestFlowCookieAttributes`.
- [A10] Given a Web2App callback, when it presents the flow cookie, the unpredictable callback value, a `sessionSecretDigest` equal to the SHA-256 of `sessionSecret` and (for authentication) a `userChallengeVerifier` hashing to `signature.userChallenge`, then the flow verifies and both cookie and value are invalidated; a callback without the cookie shows the restart page. Test: `TestWeb2AppCallbackBinding`.
- [A11] Given any page response, when headers are inspected, then strict CSP and `frame-ancestors 'none'` are present with template autoescaping, no QR older than three seconds is served, and a Web2App callback arriving without the flow cookie fails with the restart page. Test: `TestResponseHeadersAndQRRelay`.
- [A13] Given the store is saturated, when the readiness probe is called, then it stays ready (configuration and key load only) and saturation yields per-request 503; it is not-ready only during a SIGTERM drain. Test: `TestReadinessIgnoresSaturation`.
- [A14] Given SIGTERM, when the bridge shuts down, then it stops accepting new authorize requests and QR page loads, drains until every issued code has expired or the grace period ends, then exits; a flow verified 5 seconds before the code TTL still exchanges. Test: `TestSigtermDrainsUntilCodeTTL`.
- [E01] Given a flow in `created`, when the upstream init fails or the user abandons or cancels before `pending`, then it moves to `failed` or `cancelled`, a terminal state that releases capacity. Test: `TestCreatedFlowTerminatesOnInitFailOrAbandon`.
- [E03] Given poll retries are exhausted while the phone session is still open, then the flow is `failed` (`retries_exhausted`), no upstream cancel is attempted (the pinned v3 API has none), the user is told to cancel on the device, and a later result is never accepted. Test: `TestPollRetryExhaustionFailsFlow`.
- [E04] Given the store is full, when an authorize request arrives, then it receives 503 with `Retry-After` and no `pending` or `verified` entry is evicted. Test: `TestStoreFullNeverEvicts`.
- [E05] Given the code store is at its cap, when a flow verifies, then the code slot reserved at flow creation guarantees the authenticated user still receives a code. Test: `TestCodeSlotReservedAtFlowCreation`.
- [E06] Given an in-flight poll returns `verified` after its entry expired or went terminal, when the result arrives, then it is discarded with a reason code, upstream secrets are zeroed, and the flow is not resurrected. Test: `TestLateResultDiscardedAndSecretsZeroed`.
- [E11] Given two tabs start flows concurrently, when each completes, then each uses its own `__Host-eidb-<flow-id>` cookie and neither flow disturbs the other. Test: `TestTwoTabsRunIndependentFlows`.
- [E19] Given the store is full on a single replica, when the readiness probe is called, then it ignores the transient capacity condition and reports ready, so the load balancer keeps the replica. Test: `TestReadinessIgnoresTransientCapacity`.
- [E20] Given the browser returns with a lost flow handle after restart, when the request arrives, then the bridge shows a stable error page and redirects with `error=access_denied` to the `redirect_uri` from the flow cookie, revalidated against the client registry. Test: `TestUnknownFlowHandleRedirectsAccessDenied`.
- [E05] Given the tombstone cap is reached, when a flow is created, then the bridge returns 503 with `Retry-After`, so replay detection never degrades. Test: `TestTombstoneCapReturns503AtFlowCreation`.
- [E10] Given any terminal state (`verified`, `refused`, `expired`, `failed` or `cancelled`), when the final response is sent, then it carries the return link (`access_denied` for `refused`, `cancelled` and `expired`; `server_error` for `failed`; `iss` and `state` included) and clears the cookie; a fresh attempt is a new authorize request. Test: `TestTerminalResponseReturnsErrorAndClearsCookie`.
- [A10] Given the user chooses QR or same-device, then the choice is stored as `flow.offered` before the upstream session is created and `initialCallbackUrl` is empty for QR. Test: `TestFlowTypeChosenBeforeSessionCreation`.
- [A10] Given a fifth admitted flow, cancel the oldest matched nonterminal flow under its lock, stop polling, destroy secrets, release unfilled reservations and expire its cookie; racing completion preserves issued codes. Admission failure leaves old flows intact; concurrent excess is reconciled on the next request within global quotas. Test: `TestFlowCookieCapFour`.
- [A10] Given a Web2App callback in a second tab, then only the callback response issues the 303 return redirect and the original tab shows a continue-in-the-other-tab notice. Test: `TestOnlyCallbackResponseRedirects`.
- [E01] Given a page reload on a pending flow, then the page renders from stored state without a new upstream session, and explicit cancel works only as a POST with the flow binding token. Test: `TestReloadRendersStoredStateAndCancelNeedsBindingToken`.
- [A09] Given no free poll slot, when a QR page loads, then the response is 503 with `Retry-After` and the flow stays `created`; the pending-flow cap never exceeds the upstream concurrency. Test: `TestNoPollSlotReturns503AndFlowStaysCreated`.
- [A08] Given repeated notification requests for one identifier from many IPs, then a per-target-identity bucket limits them, and init errors, `ACCOUNT_UNUSABLE` and `DOCUMENT_UNUSABLE` show one generic message. Test: `TestPerTargetIdentityBucket`.
- [A10] Given any flow-scoped endpoint (page, QR image, status, cancel, continue, callback) requested without the cookie binding token, then the response is the restart page with no state change and no upstream session. Test: `TestEveryFlowScopedEndpointRequiresCookie`.
- [E06] Given a Web2App flow, when the OK poll result arrives before the callback or the callback before the OK result, then the flow verifies exactly once after both, and a second use of the callback value gets the restart page. Test: `TestWeb2AppOKAndCallbackOrderEitherWay`.
- [A09] Given concurrent QR page loads of one flow, then exactly one upstream session is created. Test: `TestConcurrentQRPageLoadsCreateOneSession`.
- [A14] Given a drain in progress, then token and userinfo keep serving, no new verification starts, and the process exits when issued codes expire or `grace_period` ends. Test: `TestDrainKeepsTokenAndUserinfoServing`.

**RV resolution acceptance criteria (2026-11-18):**

- TestSessionInitTransportBounds: device-link and notification init timeouts, oversized bodies and redirects fail the flow and release resources; uncertain init is not blindly retried.
- TestTargetBucketFullMapAndChurn: normalization shares equivalent identifiers; unseen targets at capacity get 503 with Retry-After and no push; existing active buckets keep their debt and idle expiry cannot precede full refill.
- TestCodeCapacityUnderSustainedExchange: measure reservations, live codes and tombstones across a full retention window; independent sizing includes index memory and overload never evicts replay state.
- TestCallbackFirstRetainsVerifierUntilSignedResult: either event order verifies once only after both validations; retained verifier bytes are bounded and destroyed on completion or expiry.
- TestRetiredBindingCannotDisruptCompletion: stale in-flight bindings get only the other-tab notice and cannot poll, cancel, obtain codes or mutate completion.
- TestAbsoluteFlowDeadlineAndEvictionRace: reload and cookie rotation never extend the creation-time flow deadline; fifth-flow cancellation stops polling and releases only unfilled reservations; racing issued codes remain valid.

**Implementation contract:** `cmd/eidbridge` wires configuration, the enabled authenticator methods and the OIDC provider, and serves the end-user login page: cross-device QR and same-device Web2App for Smart-ID device-link. Full proposal, APIs, exclusions and notes are retained in addendum issue #7.

**Original effort, dependency prose and activation gate:**

Effort: ~3 h. Depends on: "Expose eID logins as a standard OpenID Connect provider", "Implement Smart-ID RP API v3 client with signature verification".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.6: Enforce no telemetry and zero data retention by default

As an operator,
I want to bound and delete transient flow state without telemetry,
So that authentication does not create a persistent identity history.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Relying parties are the data controllers for their users' logins. A self-hosted bridge that never phones home and stores nothing keeps the project author out of the processing chain and makes the integrator's DPIA simple. These properties must be enforced and tested, not just promised.

**Requirement:** FR-010. **Source:** GitHub issue #10; original specification _issues/skid/10-no-telemetry-zero-retention.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.5.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Test: after a completed fixture login and after TTL expiry, the store holds zero entries for that flow
- [ ] Network test in CI (container with egress blocked except a mock RP API) completes a login; no other egress attempted
- [ ] `SECURITY.md` and `docs/security.md` present and linked from README
- [ ] GitHub private vulnerability reporting enabled

**And — reconciliation and safety:** Upstream success may leave a minimal pending code payload until exchange/expiry, not an entire certificate/session; test phase-specific deletion. Named demo volume stores signing key only.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A01] Given a verified flow, when the claim set is held until code exchange or expiry, then it is plaintext in process memory keyed by the code hash with no encryption claim, and the lifecycle table states this. Test: `TestClaimSetKeyedByCodeHash`.
- [E09] Given an authorization code is replayed after token issuance, when presented again, then its existing reserved family tombstone is atomically marked revoked (the logical deny-list), without new allocation, and userinfo rejects it through its original lifetime. Test: `TestCodeReplayDenyListRejectsUserinfo`.
- [E10] Given a flow ends `refused`, `expired` or `failed`, or its code goes unexchanged, when the terminal state is reached, then the bridge clears the flow cookie with an expiring `Set-Cookie`. Test: `TestCookiesClearedOnEveryTerminalState`.
- [E21] Given a wall-clock jump, when flow and code TTLs are evaluated, then they use the monotonic clock, so codes neither expire early nor outlive 60 seconds. Test: `TestTTLsUseMonotonicClock`.
- [E21] Given a backward wall-clock step, userinfo still expires tokens at their process-monotonic acceptance deadline. Replay a revoked token after tombstone expiry while wall time remains before `exp` and assert rejection; restart or a revoked sealing epoch also rejects it. Test: `TestDenyListLifetimeSurvivesWallClockStep`.
- [A01] Given a Web2App callback request, then access logs hold only the method and route template, with no callback parameters, flow IDs or client IPs beyond rate-limit memory. Test: `TestAccessLogOmitsCallbackQueryAndFlowIDs`.

**Implementation contract:** Guarantee the binary makes no outbound connections other than to configured eID endpoints, keeps login state in memory only, and deletes it as soon as the flow completes or expires. Publish the security policy. Full proposal, APIs, exclusions and notes are retained in addendum issue #10.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". Prometheus metrics, if added later, must be pull-only, opt-in and contain counts only.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.7: Warn on demo environment use and block demo credentials in prod

As a production operator,
I want to reject demo identity and mixed-trust configurations,
So that synthetic identities cannot enter a production account flow.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Demo mode is the zero-config default so anyone can try the bridge in minutes. The same convenience is a foot-gun: a deployment left in demo mode accepts demo-app accounts that prove nothing about a real person. The public demo relying party is meant for development and CI only.

**Requirement:** FR-011. **Source:** GitHub issue #11; original specification _issues/skid/11-demo-env-guard.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.5.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Unit tests for each detection rule
- [ ] `EIDBRIDGE_MODE=production ./eidbridge --demo` exits non-zero with a clear message
- [ ] Demo banner visible on the login page (template test)
- [ ] ID tokens issued in demo mode contain `acr=demo`
- [ ] `docs/keycloak.md` shows how to reject `acr=demo` on production realms

**And — reconciliation and safety:** Test all demo indicators independently and combinations of endpoint, UUID, CA and mode. Clients reject demo tokens in production even if a banner is hidden.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A12] Given production mode, when the key has a `demo-` `kid` or its SPKI SHA-256 fingerprint matches embedded fixtures or an operator-supplied demo-key deny-list, then startup fails; malformed lists fail startup; unknown historical provenance is not asserted; demo tokens use a distinct `/demo` issuer and `demo-` prefixed `kid`. Test: `TestProductionRejectsDemoKeyFingerprint`.
- [E16] Given the mode invariant matrix, when `mode` is unset, or demo mode meets production hosts, pins, CA or UUID, then startup fails; `mode` has no default. Test: `TestModeInvariantMatrix`.
- [E18] Given no `trusted_proxies` is configured and every observed peer address is private or a load balancer, when the first requests arrive, then it warns once at runtime, and the per-IP rate-limit key is the resolved client IP. Test: `TestProxyTrustWarningWhenAllPeersPrivate`.
- [E16] Given an `http` issuer other than `http://localhost`, or `EIDBRIDGE_SMARTID_ENV` disagreeing with `mode`, then startup fails. Test: `TestProductionRejectsHTTPIssuerAndEnvMismatch`.
- [E16] Original criterion `docs/keycloak.md` above is produced as `docs/idp/keycloak.md` by Story 3.5; Story 2.7 closes with a stub at that path until then. Test: `TestKeycloakDocStubRejectsDemoACR`.

**Implementation contract:** Make it impossible to accidentally serve real users through the eID demo environments: loud startup and page warnings in demo mode, and a hard failure if production mode is combined with demo endpoints or the public demo relying-party identity. Full proposal, APIs, exclusions and notes are retained in addendum issue #11.

**Original effort, dependency prose and activation gate:**

Effort: ~1 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". Known demo hosts live in one table in `internal/config/demo.go`; update it when endpoints change.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 2.8: Support Smart-ID v3 notification-based authentication flow

As a returning user,
I want to use an explicitly enabled notification flow and compare its verification code,
So that I can authenticate without scanning QR while the service limits push abuse.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Device-link (QR / Web2App) is the default, but some relying parties already know the user's identity code (returning users, call-centre or kiosk flows) and want a push to the phone without a QR. It is also the fallback if device-link sessions turn out to be restricted for a given relying party.

**Requirement:** FR-004. **Source:** GitHub issue #4; original specification _issues/skid/04-smartid-notification-flow.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1, 1.3, 2.5.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Fixture-based tests for notification session create/poll/verify
- [ ] Test that a response for a different identity than requested is rejected
- [ ] Invalid identity codes are rejected locally without an outbound request
- [ ] Entered identity codes are never logged unredacted (covered by the log redaction tests)
- [ ] Live demo test behind `EIDBRIDGE_LIVE=1`

**And — reconciliation and safety:** Add per-IP/client rate limiting and generic anti-enumeration failures, not only checksum validation. Disabled by default; same Verify path as device-link.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [E15] Given a notification-mode session completes with an account identity different from the requested identity, when the result is evaluated, then the flow becomes `failed(identity_mismatch)` and no authorization code is issued. Test: `TestIdentityMismatchFailsWithoutCode`.

**Implementation contract:** Add the v3 notification-based authentication flow (push to a known user's device by national identity number or document number) next to device-link, selectable per request. Full proposal, APIs, exclusions and notes are retained in addendum issue #4.

**Original effort, dependency prose and activation gate:**

Effort: ~3 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification", "Redact personal identity codes at the log sink". Notification flow accepts a user-typed identifier, so rate limiting per client IP on the login form is required to avoid push spam to arbitrary users.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 3: Evaluate, operate and integrate the bridge

A new operator can run the demo, assess data handling, use reviewed locale text and maintain/integrate the release.

### Story 3.1: Document end-to-end personal data flow for integrator DPIAs

As a data-protection reviewer,
I want to inspect each field, purpose, lifetime and recipient,
So that I can assess the actual deployment processing.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The relying party is the GDPR controller for its users' logins and must describe the processing. Data protection officers ask the same questions for every authentication component: which fields, where they go, how long they live, who sees them. Answering once in the repo removes that friction and makes misconfiguration visible.

**Requirement:** FR-013. **Source:** GitHub issue #13; original specification _issues/skid/13-data-flow-doc.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.4, 1.3, 2.6.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `docs/data-flow.md` merged and linked from README and `docs/security.md`
- [ ] Every claim emitted by `internal/oidc` appears in the table (CI test compares claim names in code against the doc table)
- [ ] Mermaid diagram renders on GitHub

**And — reconciliation and safety:** Extend field table with purpose, linkability and code/test evidence plus deployer-completed DPIA/RoPA aids; distinguish operator/proxy logs and token retention outside bridge.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A15] Given the data-flow document's Mermaid sequence diagram, when its edges are parsed, then it includes the browser-to-bridge front channel, the eID app-to-Smart-ID leg and trust-boundary groupings. Test: `TestDataFlowDocDiagramEdges`.

**Implementation contract:** Add `docs/data-flow.md`: a field-by-field map of every piece of personal data the bridge receives, holds, emits and discards, written so an integrator can paste it into their records of processing or DPIA. Full proposal, APIs, exclusions and notes are retained in addendum issue #13.

**Original effort, dependency prose and activation gate:**

Effort: ~1.5 h. Depends on: "Expose eID logins as a standard OpenID Connect provider", "Redact personal identity codes at the log sink", "Enforce no telemetry and zero data retention by default". Update the table whenever a method is added.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 3.2: Ship a zero-config docker compose demo with a sample relying party

As a new evaluator,
I want to start the bridge and sample client with one command,
So that I can observe a clearly marked demo round-trip before configuring production.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Evaluating eID integration usually starts with contracts, keys and a week of reading. A one-command demo shows the full OIDC round-trip immediately and doubles as the reference configuration for real deployments.

**Requirement:** FR-014. **Source:** GitHub issue #14; original specification _issues/skid/14-compose-quickstart.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.5, 2.7, 1.2, 2.6.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] From a clean clone, `docker compose up` reaches a QR page with no extra steps
- [ ] Manual check: demo-app scan completes and claims are shown, in under 5 minutes wall time
- [ ] `scripts/e2e-demo.sh` runs in CI against the fixture upstream and passes
- [ ] Demo banner from the demo-guard issue visible

**And — reconciliation and safety:** Separate demo app registration prerequisites from prepared five-minute stopwatch. Fixture upstream is required now; standalone distributable mock remains deferred under #27.

**Implementation contract:** Provide `docker-compose.yml` that starts the bridge in demo mode plus a tiny sample relying party, so a new user can clone the repo and complete a demo-app login in under five minutes with no accounts or keys. Full proposal, APIs, exclusions and notes are retained in addendum issue #14.

**Original effort, dependency prose and activation gate:**

Effort: ~3 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows", "Warn on demo environment use and block demo credentials in prod", "Scaffold Go module with CI, licence checks and release automation". The live demo-app check stays manual unless the demo environment offers a scriptable test endpoint (see spike ADR).

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 3.3: Localize the login page for Estonian, Latvian, Lithuanian, English

As a Baltic end user,
I want to see reviewed login and error text in my selected language,
So that I understand the device interaction and recovery steps.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

End users of Baltic eID schemes expect their own language. Error messages such as "request refused on device" or "verification code mismatch" are exactly where a confused user abandons the login. The RP API also accepts an interaction language for on-device texts, which should match.

**Requirement:** FR-016. **Source:** GitHub issue #16; original specification _issues/skid/16-login-page-i18n.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.5.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Test: every key in `en.json` exists in all other catalogs (CI fails on missing keys)
- [ ] `ui_locales=et` renders Estonian page; unknown locale falls back to default
- [ ] Interaction display text exceeding protocol limits is rejected at config load
- [ ] Native-speaker review noted in PR for each language

**And — reconciliation and safety:** Body requires five locales including Russian despite four-language title. Native review is a delivery prerequisite; optional Estonian README is separate.

**Implementation contract:** Translate all end-user strings on the login page and error states into Estonian, Latvian, Lithuanian, English and Russian, selected via the OIDC `ui_locales` parameter or `Accept-Language`. Full proposal, APIs, exclusions and notes are retained in addendum issue #16.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h plus translation review. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". README may also get an Estonian translation later; keep the English README authoritative.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 3.4: Add a maintenance runbook for upstream API, TLS and key changes

As a maintainer,
I want to follow versioned compatibility and incident procedures,
So that upstream changes and key compromise have an evidence-backed recovery path.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

An unmaintained eID connector is a security and availability hazard for its users: a cipher-suite removal or a server certificate renewal silently breaks every pinned client. The value of a shared OSS bridge is that each upstream change is absorbed once, in the open, for everyone. That needs a written process, not memory.

**Requirement:** FR-017. **Source:** GitHub issue #17; original specification _issues/skid/17-protocol-change-tracking.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.2, 1.2.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `docs/api-tracking.md` and `CHANGELOG.md` merged
- [ ] Nightly workflow runs and auto-opens an issue on a simulated pin mismatch (tested with a bogus pin on a branch)
- [ ] Release checklist template in `.github/ISSUE_TEMPLATE/upstream-change.md`

**And — reconciliation and safety:** Add reason-code incident matrix, key compromise/drain/rotation drill and release deviation evidence. Planned nightly/auto-issue behavior is not deployed by this task.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A05] Given a compromised signing key, when the emergency revocation drill runs, then the key is removed from JWKS immediately, the access-token sealing key is rotated, and clients must re-authenticate, unlike planned rotation. Test: `TestEmergencyRevocationDropsKeyFromJWKS`.
- [E12] Given a key marked compromised, when JWKS is served, then it is dropped immediately and not retained until token expiry, so tokens it signed no longer validate. Test: `TestCompromisedKeyDroppedImmediately`.
- [A05] Given `K_sub` compromise, then the drill issues a new `K_sub` version, runs the `previous_sub` migration window, retires the old version and notifies clients; emergency revocation first activates a replacement signing key. Test: `TestKSubCompromiseAndReplacementKey`.

**Implementation contract:** Write `docs/api-tracking.md`: how the project tracks and responds to upstream changes that break relying parties (RP API minor versions, TLS policy changes, server certificate renewals, demo key and CA rotations), with a release checklist for each. Full proposal, APIs, exclusions and notes are retained in addendum issue #17.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Pin RP API TLS certificates and make trust anchors configurable", "Scaffold Go module with CI, licence checks and release automation".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 3.5: Add config-only IdP integration guides with e2e tests per IdP

As an IdP administrator,
I want to follow a tested configuration-only OIDC recipe,
So that I can integrate the bridge without maintaining a native plugin.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Self-hosted IdPs are where most small and mid-size relying parties manage users. None of them ships Baltic eID login, and past plugin-based attempts were abandoned. A tested "Add OIDC provider" recipe gets eID into an existing realm in minutes and stays working across IdP upgrades because CI catches regressions.

**Requirement:** FR-015. **Source:** GitHub issue #15; original specification _issues/skid/15-idp-integration-kits.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.4, 3.2.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Following `docs/idp/keycloak.md` on a fresh Keycloak container results in a logged-in user via the demo environment (verified manually once, screenshot in doc)
- [ ] `go test -tags e2e ./test/e2e/...` passes for all four IdPs in CI with fixture upstream
- [ ] Each guide lists the IdP version tested and the date
- [ ] README links each guide

**And — reconciliation and safety:** Pin actual tested IdP versions; record Ory Kratos/Hydra composition and browser/issuer reachability explicitly. Do not assume Hydra alone supplies the login frontend.

**Implementation contract:** Write configuration-only guides for adding the bridge as an external OIDC identity provider in Keycloak, authentik, Zitadel and Ory (Kratos/Hydra), each backed by a compose-based end-to-end test that runs in CI. Full proposal, APIs, exclusions and notes are retained in addendum issue #15.

**Original effort, dependency prose and activation gate:**

Effort: ~6 h (Keycloak first at ~3 h, others ~1 h each). Depends on: "Expose eID logins as a standard OpenID Connect provider", "Ship a zero-config docker compose demo with a sample relying party". Risk: IdP UI churn; prefer API/import-based config in tests so docs drift is caught.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 3.6: Add Django and FastAPI examples that log in through the bridge

As a Python application developer,
I want to use tested standard OIDC examples in Django and FastAPI,
So that I can integrate without implementing an eID protocol client.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Many relying parties have no central IdP and want eID login directly in their web app. Because the bridge speaks OIDC, they need no eID-specific code at all; a working example in their framework proves that and saves a day of trial and error with claims and redirect URIs.

**Requirement:** FR-018. **Source:** GitHub issue #18; original specification _issues/skid/18-framework-oidc-examples.md.

**Status:** backlog. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 3.2.

**Acceptance Criteria:**

**Given** the listed prerequisite packets have the required evidence (full parent closure may follow integrated checks),
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `pytest examples/` passes locally and in CI
- [ ] Neither example contains eID-protocol code; only OIDC client configuration
- [ ] Examples reject `acr=demo` when `PRODUCTION=1`

**And — reconciliation and safety:** Use standard client-library configuration only, production demo rejection and subject-based linking; version/library choices require current docs during implementation.

**Implementation contract:** Add `examples/django/` and `examples/fastapi/` showing how a Python web app uses eID login through the bridge with standard OIDC client libraries, plus a test that runs each against the fixture stack. Full proposal, APIs, exclusions and notes are retained in addendum issue #18.

**Original effort, dependency prose and activation gate:**

Effort: ~2 h. Depends on: "Ship a zero-config docker compose demo with a sample relying party".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 4: Add a demanded second national authentication method

Only after demand: users can choose Smart-ID or Mobile-ID without changing client integration.

### Story 4.1: Let users choose among multiple enabled eID methods

As an end user,
I want to select only methods enabled and permitted for the client,
So that my authentication follows the required policy without an unnecessary chooser.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

A single OIDC provider fronting Smart-ID, Mobile-ID, ID-card and later the EUDI Wallet is the main reason to run one bridge instead of several integrations. Relying parties also need control: some apps require LoA high only, some want to skip the chooser.

**Requirement:** FR-020. **Source:** GitHub issue #20; original specification _issues/skid/20-method-chooser.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.3, 2.5.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Tests: `acr_values` filtering, `login_hint` preselect, per-client restriction, `amr` in token
- [ ] Single enabled method still skips the chooser
- [ ] Accessible keyboard navigation across method choices

**And — reconciliation and safety:** Dependency repair: implement chooser with a fake second method after #5, then #19 consumes it. The gate is second-method demand, not an already shipped second method. Optional preference cookie requires privacy update.

**Architecture remediation AC (2026-11-18 review):** These criteria are additional to the original criteria above, trace to [Review resolution](architecture.md#review-resolution) and close only with the named test.

- [A17] Given exactly one method is registered, when the login page renders, then no chooser UI appears; only the registry contract test with a fake method exists until a demand trigger. Test: `TestNoChooserWithSingleMethod`.
- [E23] Given the remember-method cookie names a method no longer in the registry, when the login page loads, then the cookie is ignored and the flow proceeds without error. Test: `TestRememberCookieIgnoredWhenMethodRemoved`.
- [A17] Supersedes the fake-method chooser sentence above: the chooser UI activates together with Mobile-ID on real demand (ADR-006); until then only the registry contract test uses a fake method. Test: `TestNoChooserWithSingleMethod`.

**Implementation contract:** When more than one method is enabled, show a method selection step on the login page and let OIDC clients restrict or preselect methods via standard request parameters. Full proposal, APIs, exclusions and notes are retained in addendum issue #20.

**Original effort, dependency prose and activation gate:**

Effort: ~3 h. Depends on: "Define a method-neutral authenticator interface for eID backends". Deferred until a second method exists (Mobile-ID or Web eID); with one method this is dead code.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 4.2: Add Mobile-ID authentication via the MID REST API

As a Mobile-ID user,
I want to choose and complete verified Mobile-ID authentication when that capability is activated,
So that I can reach the same relying party through a supported method.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Mobile-ID remains in use in Estonia and Lithuania, especially among users without a smartphone app. Relying parties that serve the general public usually need it alongside Smart-ID, and today that means a second, separate integration.

**Requirement:** FR-019. **Source:** GitHub issue #19; original specification _issues/skid/19-mobile-id.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.3, 4.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `go test ./internal/mobileid/` with recorded fixtures, including tampered signature and identity mismatch cases
- [ ] `authntest.Run` passes
- [ ] `EIDBRIDGE_METHODS=smartid,mobileid` serves both on one login page
- [ ] Data-flow doc updated with phone number field

**And — reconciliation and safety:** Activate together with a justified chooser, update phone-number data inventory and demo trust, and require rate-limited E.164/identity input and contract tests.

**Implementation contract:** Implement `internal/mobileid` as a second `authn.Method`: Mobile-ID authentication through the MID REST API (phone number + personal code, verification code, poll, signature and certificate verification). Full proposal, APIs, exclusions and notes are retained in addendum issue #19.

**Original effort, dependency prose and activation gate:**

Effort: ~8-10 h. Depends on: "Define a method-neutral authenticator interface for eID backends", "Let users choose among multiple enabled eID methods". Deferred: v1 is one method done well; start once the Smart-ID path is stable and at least a few deployments ask for it. Note the demo environment rotates its keys/certs occasionally; covered by the maintenance runbook.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 5: Enable independently reviewed ID-card login

Only after demand/hardware/review gates: ID-card users get origin-bound verified login.

### Story 5.1: Add ID-card login via Web eID token validation in Go

As an ID-card user,
I want to complete an independently reviewed origin-bound card login when activated,
So that my card can authenticate through the same issuer.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Estonian ID-cards (and other smart-card eIDs supported by Web eID) remain a high-assurance method for many users and public-sector services. There is no maintained Go implementation of Web eID token validation, so Go services cannot accept ID-card login without a Java or .NET sidecar.

**Requirement:** FR-021. **Source:** GitHub issue #21; original specification _issues/skid/21-web-eid-idcard.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 4.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Test vectors: valid token, wrong origin, replayed nonce, expired cert, revoked cert (mock OCSP), untrusted CA
- [ ] Fuzz tests on token parsing
- [ ] Manual login with a test ID-card and the Web eID extension documented
- [ ] `authntest.Run` passes

**And — reconciliation and safety:** Before sprint readiness split validator/parser, origin/nonce/session, cert/status, adapter/browser, hardware/interop and external-review work. Preserve original 80–100h range; no implied cheap fallback.

**Implementation contract:** Implement `internal/webeid`: ID-card authentication using the Web eID browser extension protocol, including a Go library for validating Web eID authentication tokens (challenge nonce, signature, certificate chain, revocation). Full proposal, APIs, exclusions and notes are retained in addendum issue #21.

**Original effort, dependency prose and activation gate:**

Effort: ~80-100 h (spec stack, OCSP and trust-chain handling). Deferred: exceeds the initial scope by far; unblock when the Smart-ID path is stable and there is a concrete deployment needing ID-card. Depends on: "Let users choose among multiple enabled eID methods". Security-critical: request an external review before release.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 6: Enable testable wallet authentication

Only after demand, pinned profiles and test wallet access: verified PID presentation reaches the same issuer with transparent evidence.

### Story 6.1: Accept EUDI Wallet presentations via OpenID4VP as a login method

As a wallet holder,
I want to present the permitted PID attributes through a verified wallet flow when activated,
So that the client receives only supported verified claims.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

EU Digital Identity Wallets are being rolled out, and relying parties will need to accept them next to national schemes. Putting the wallet behind the same OIDC surface means the integrator's IdP and apps do not change when the wallet arrives; users simply see another method.

**Requirement:** FR-022. **Source:** GitHub issue #22; original specification _issues/skid/22-eudi-wallet-oid4vp.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 4.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Presentation from the EU reference wallet verified end to end in a test environment
- [ ] Negative tests: wrong nonce, revoked credential, untrusted issuer, missing key binding
- [ ] `authntest.Run` passes
- [ ] Docs state clearly the bridge does not confer any regulatory compliance on the integrator's service

**And — reconciliation and safety:** Before sprint readiness split profile/trust/RP registration, parser/holder binding, request-response/session binding, adapter/claims and interop. Compare native IdP support first and use the adjacent requirements table in architecture.

**Implementation contract:** Add an `authn.Method` that requests a PID presentation from an EUDI Wallet over OpenID for Verifiable Presentations (OpenID4VP) and maps the verified attributes to the same OIDC claims as the national eID methods. Full proposal, APIs, exclusions and notes are retained in addendum issue #22.

**Original effort, dependency prose and activation gate:**

Effort: 60+ h and ongoing spec tracking. Deferred: OpenID4VP, HAIP and the ARF are still moving, wallet acceptance obligations for private relying parties are not yet in force, and mainstream IdPs may add native support. Unblock when the reference specs stabilise and a national wallet is available for testing. Depends on: "Let users choose among multiple enabled eID methods".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 6.2: Build an EUDI Wallet relying-party conformance test harness

As a verifier maintainer,
I want to run a pinned positive and negative wallet test catalog after wallet authentication exists,
So that I can disclose reproducible requirement-level results.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Relying parties preparing for wallet acceptance have no lightweight, self-hostable way to check their verifier against the profiles they must follow. A harness also keeps the bridge's own OpenID4VP method honest as specs change.

**Requirement:** FR-023. **Source:** GitHub issue #23; original specification _issues/skid/23-eudi-conformance-harness.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 6.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Runs against the bridge's EUDI method in CI and produces a JUnit report
- [ ] At least the core positive flow plus 10 negative cases implemented
- [ ] Each case links the spec section and version it checks

**And — reconciliation and safety:** Separate harness schema, generated positive/negative catalog, runner/report and pinned-profile maintenance. It follows a working wallet method; no certification claim.

**Implementation contract:** A test harness (`cmd/eudi-conformance`) that exercises a relying-party verifier implementation against the EUDI Wallet protocol profiles and reports pass/fail per requirement, usable for the bridge's own wallet method and for other verifiers. Full proposal, APIs, exclusions and notes are retained in addendum issue #23.

**Original effort, dependency prose and activation gate:**

Effort: well over 60 h plus continuous spec tracking. Deferred: a half-finished harness against a moving spec is worse than none. Unblock only after "Accept EUDI Wallet presentations via OpenID4VP as a login method" ships and the specs are stable enough to pin.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 7: Serve demonstrated ecosystem and diagnostic gaps

Each independently gated package or guide closes a documented gap without expanding default runtime scope.

### Story 7.1: Provide a native Keycloak identity provider SPI for eidbridge

As a Keycloak administrator,
I want to use an optional version-tested SPI after unmet demand is demonstrated,
So that I can close a concrete gap in the configuration-only route.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

The generic OIDC provider setup already works in Keycloak without code. A native SPI could still help some operators: one-click setup, built-in claim mappers for country and personal code, first-broker-login flows tuned for eID identity linking, and validation of `acr=demo` tokens.

**Requirement:** FR-024. **Source:** GitHub issue #24; original specification _issues/skid/24-keycloak-spi.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 3.5.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Jar deploys into Keycloak `providers/`; provider appears in admin console
- [ ] Testcontainers e2e login passes for the two latest Keycloak majors
- [ ] Docs explain when the plain OIDC guide is enough

**And — reconciliation and safety:** Three users must describe a concrete gap config-only OIDC cannot cover; compatibility maintenance budget confirmed before Java module work.

**Implementation contract:** Package a Keycloak Identity Provider SPI (Java, separate `keycloak-spi/` module or repo) that preconfigures the bridge as an identity provider with eID-specific mappers and admin UI fields. Full proposal, APIs, exclusions and notes are retained in addendum issue #24.

**Original effort, dependency prose and activation gate:**

Effort: 20+ h (Java/Keycloak ramp) plus per-release upkeep. Deferred: the config-only guide covers the use case and previous SPI-based eID plugins went unmaintained after Keycloak API changes. Unblock if at least three users request it with a concrete gap the OIDC guide cannot close. Depends on: "Add config-only IdP integration guides with e2e tests per IdP".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 7.2: Publish a minimal Python client for Smart-ID RP API v3

As a Python protocol integrator,
I want to use a shared-fixture direct client after its demand gate opens,
So that I can integrate where running a separate bridge is impractical.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Official clients exist for Java and PHP; Python has no maintained client at all. Some teams cannot run an extra service and want a library. A Python client also gives the project an independent second implementation to cross-check the Go verifier against shared fixtures.

**Requirement:** FR-025. **Source:** GitHub issue #25; original specification _issues/skid/25-python-rp-client.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] `pip install` from built wheel; `python -c "import eidbridge_rp"` works
- [ ] pytest against shared fixtures incl. negative verification cases
- [ ] Release workflow publishes to PyPI via trusted publishing

**And — reconciliation and safety:** Two independent users must need a direct client; neutral eidbridge-rp naming, shared fixtures, no claim to be an official scheme SDK. Release PyPI only in future authorized implementation.

**Implementation contract:** A small Python package (`python/` in this repo) implementing Smart-ID RP API v3 session create, poll and verify, for apps that want to call the API directly instead of going through the bridge. Same pattern could later extend to other languages lacking a client. Full proposal, APIs, exclusions and notes are retained in addendum issue #25.

**Original effort, dependency prose and activation gate:**

Effort: ~4-6 h initial, ongoing upkeep per API change. Deferred: two codebases double protocol maintenance; the OIDC path already serves Python apps. Unblock when at least two users ask for a direct library. Depends on: "Implement Smart-ID RP API v3 client with signature verification".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 7.3: Add an eidbridge doctor command for upstream connectivity checks

As an on-call operator,
I want to run bounded local connectivity and trust diagnostics after a diagnostic gap is demonstrated,
So that I can explain the upstream outage from my own deployment network.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

When logins start failing after an upstream TLS policy change or certificate renewal, operators need a quick, local diagnosis instead of reading stack traces. The same checks can warn days ahead about expiring pins or CA certificates.

**Requirement:** FR-026. **Source:** GitHub issue #26; original specification _issues/skid/26-doctor-health-check.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.2.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Tests with `httptest` TLS servers for pin mismatch, expiring cert, unreachable host
- [ ] `--json` schema documented
- [ ] No outbound calls beyond configured endpoints

**And — reconciliation and safety:** Require an outage/report inadequately explained by existing errors; diagnostics stay configured-endpoint only, no hosted monitor. Optional metrics remain pull-only/no PII.

**RV resolution acceptance criteria (2026-11-18):**

- TestDoctorNeverControlsReadiness: upstream outage makes doctor fail while readiness remains local configuration/key-load/drain state.

**Implementation contract:** `eidbridge doctor` checks the configured upstream eID endpoints from the operator's own network: DNS, TLS handshake and negotiated cipher, pin match, server certificate expiry, CA bundle validity, API reachability and latency. Upstream `/readyz` integration is superseded: readiness remains local configuration/key-load/drain state; diagnostics run exclusively through the opt-in doctor command. Full proposal, APIs, exclusions and notes are retained in addendum issue #26.

**Original effort, dependency prose and activation gate:**

Effort: ~4 h. Deferred: no operator has asked yet; the pin-mismatch startup error and nightly CI check cover the basics. Unblock on the first user report of an upstream-change outage that the existing error messages did not explain. Depends on: "Pin RP API TLS certificates and make trust anchors configurable".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 7.4: Ship a mock RP API server and test identities for offline testing

As a CI integrator,
I want to control a safe standalone synthetic upstream after external demand is demonstrated,
So that I can reproduce success and failure without a real identity or phone.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Integrators want deterministic CI for their login flows without a phone, demo-app account or network access to the demo environment. The bridge's own e2e tests already need a fixture upstream; promoting it to a documented tool helps every downstream project test failure paths (user refused, timeout, wrong verification code) that are hard to trigger by hand.

**Requirement:** FR-027. **Source:** GitHub issue #27; original specification _issues/skid/27-mock-rp-api-server.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Bridge e2e and IdP e2e suites run against the mock in CI with no external network
- [ ] Each scenario (complete, refuse, timeout, wrong VC) covered by a test
- [ ] Mock refuses to start bound to a non-loopback address unless `--allow-remote`

**And — reconciliation and safety:** Internal fixture server is not this deliverable. Gate standalone CLI/image on external offline-testing demand; no claim that fake checksum-valid identity is a reserved real-world identity range without authoritative allocation.

**Implementation contract:** `cmd/eidmock`: a local mock of the Smart-ID (and later Mobile-ID) RP API that completes, refuses or times out sessions on command, signs responses with a generated test CA, and ships a set of synthetic test identities. Full proposal, APIs, exclusions and notes are retained in addendum issue #27.

**Original effort, dependency prose and activation gate:**

Effort: ~6 h. Deferred: the initial e2e work uses recorded fixtures; promote to a standalone tool when external users ask for offline testing. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Implement from the published spec only.

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 7.5: Support legacy Smart-ID RP API v2 for existing relying parties

As a legacy deployment operator,
I want to select a tested v2 backend only when my deployment cannot use v3,
So that I can adopt the bridge with an explicit migration route.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Some relying parties have existing agreements and configurations tied to the older API generation and cannot migrate immediately. Supporting v2 would let them adopt the bridge first and switch API versions later with a config change.

**Requirement:** FR-029. **Source:** GitHub issue #29; original specification _issues/skid/29-legacy-rp-api.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.3.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Fixture tests for v2 create/poll/verify incl. negative cases
- [ ] `authntest.Run` passes for v2
- [ ] Docs explain migration v2 to v3

**And — reconciliation and safety:** Source issue supports v2; never inherit ranking prose asking for rejection of all legacy fixtures. Excludes v1, warns migration to v3 and maintains separate negative vectors.

**Implementation contract:** Add an RP API v2 backend (notification flow by identity code, verification code display) behind the same `authn.Method` interface, selectable with `EIDBRIDGE_SMARTID_API=v2`. Full proposal, APIs, exclusions and notes are retained in addendum issue #29.

**Original effort, dependency prose and activation gate:**

Effort: ~6 h plus doubled protocol maintenance. Deferred: v3 is current and building for legacy versions doubles upkeep for a shrinking user base. Unblock only if a concrete deployment cannot use v3. Depends on: "Define a method-neutral authenticator interface for eID backends".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

### Story 7.6: Document or ship a WordPress login integration via the bridge

As a WordPress administrator,
I want to configure a maintained OIDC login plugin after users request this integration,
So that I can add login without taking on a new plugin maintenance burden.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Small organisations, municipalities and NGOs often run WordPress and have no IdP. Earlier eID WordPress plugins were abandoned and never supported Smart-ID. Because the bridge speaks OIDC, a generic OIDC plugin should be enough.

**Requirement:** FR-030. **Source:** GitHub issue #30; original specification _issues/skid/30-wordpress-plugin.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 7.4.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Guide followed on a fresh WordPress container produces a logged-in user via the mock upstream
- [ ] Example compose stack has an automated login test

**And — reconciliation and safety:** Guide first using a maintained OIDC plugin; new plugin needs a remaining gap and maintenance budget. Login differs from adjacent WooCommerce age checkout; GPL-compatible boundary if code is later added.

**Implementation contract:** Enable WordPress sites to offer eID login through the bridge, preferably by documenting configuration of an existing maintained OIDC login plugin, and only if that proves insufficient, shipping a thin plugin. Full proposal, APIs, exclusions and notes are retained in addendum issue #30.

**Original effort, dependency prose and activation gate:**

Effort: ~3 h for the guide; 15+ h for a maintained plugin. Deferred: no demonstrated demand yet, and WordPress plugin maintenance is costly. Unblock when WordPress users ask. Depends on: "Ship a mock RP API server and test identities for offline testing".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.

## Epic 8: Evaluate a separate signing-session capability

Only after stable authentication and demand: an authenticated digest-relay experiment is evaluated without qualified-service claims.

### Story 8.1: Support document signing sessions alongside authentication

As a signing integrator,
I want to use a separately authenticated digest-relay capability after scope and demand review,
So that I can verify a returned signature without attributing qualified status to the bridge.

**Source motivation (issue snapshot, 2026-11-18; not refreshed market evidence):**

Many relying parties that authenticate with Baltic eID also need users to sign contracts or applications. Having one self-hosted component for both avoids a second integration with different configuration and trust settings.

**Requirement:** FR-028. **Source:** GitHub issue #28; original specification _issues/skid/28-signing-sessions.md.

**Status:** deferred. **Implementation prerequisite parents ([packet semantics](#execution-packets-and-parent-story-closure)):** 2.1.

**Acceptance Criteria:**

**Given** the original demand/security gate is satisfied and prerequisite packets have the required evidence,
**When** the capability is implemented and tested against its source contract,
**Then** every original criterion below is satisfied and evidence is recorded:

- [ ] Fixture tests for signing session create/poll/verify
- [ ] Example produces a valid ASiC-E container verified by an independent validator
- [ ] API requires client authentication; unauthenticated requests rejected

**And — reconciliation and safety:** Before sprint readiness split threat/API authorization, protocol relay/verification, container example/independent validation and legal/scope review. External QTSP orchestration is a different adjacent option.

**Implementation contract:** Extend the bridge with an API for creating signing sessions (Smart-ID, later Mobile-ID and ID-card) and returning signatures that integrators can embed into ASiC-E/XAdES or PAdES containers. Full proposal, APIs, exclusions and notes are retained in addendum issue #28.

**Original effort, dependency prose and activation gate:**

Effort: 40+ h including container example and validation. Deferred: legally heavier than authentication, and authentication-only keeps scope and liability small. Unblock after v1 authentication is stable and a deployment needs signing. Depends on: "Implement Smart-ID RP API v3 client with signature verification".

**Evidence to close:** source AC results with implementation commit, fixture/live distinction, documentation links, applicable NFR/UX evidence and unresolved deviations. Deferred gates must be demonstrated first; no work is marked done by this plan.


## Verification and next work

The frozen coverage proxy validates exact source AC preservation, identifiers and an acyclic earlier-first parent identifier graph; semantic execution uses packets and later parent-closure checks. It does not assess story size, legal applicability or security. Stories 5.1, 6.1, 6.2 and 8.1 are large deferred parent stories, explicitly not ready-for-dev; their listed work packets must be broken into independently verifiable child stories when activated. Epic 7 is a container of separately gated options, not one committed delivery bundle. Epic 1 produces a feasibility decision, Epic 2 a verified round-trip, Epic 3 operator adoption. Security stories revisiting shared code do so to prove distinct threat boundaries; no duplicate protocol implementation is planned.

## Child-story decomposition (owner override 2026-11-20)

Recorded before implementation under the [sprint-change proposal of 2026-11-20](sprint-change-proposal-2026-11-20.md). Child stories do not close their parent; the parent closes only when every original criterion has evidence. Overridden gates stay disclosed per parent.

#### Child 5.1-a: Web eID token parser and validator

Parse `web-eid:1.0` and `web-eid:1.1` tokens strictly (size caps, Base64, allowed `algorithm` values); validate certificate time, client-authentication purpose, disallowed policies, chain to configured CAs (1.1 intermediates as untrusted candidates only) and the signature over `hash(origin)+hash(nonce)` for ES, PS and RS algorithms. Done when each validation step has a negative test and the token parser is fuzzed.

#### Child 5.1-b: Nonce, origin and browser binding

Generate ≥ 256-bit nonces per flow, single use, short TTL, bound to the flow cookie; reconstruct the ASCII origin from the configured public origin only. Done when wrong origin, replayed nonce, expired nonce and other-browser submission fail.

#### Child 5.1-c: Certificate status

OCSP with the AIA or a designated responder through `internal/revocation`, unknown fails closed. Done when a mock-OCSP revoked certificate fails and good passes.

#### Child 5.1-d: Method adapter and browser page

`authn.Method` with the `browser` flow, contract suite, vendored MIT `web-eid.js`, CSP-compatible page script, CSRF through the flow form token. Done when `authntest.Run` passes and the login page posts a token through the flow.

#### Child 5.1-e: Hardware interop and external review (human)

Manual login with a test ID-card and the Web eID extension; external security review. Not executable in the build sandbox: recorded as NOT RUN with the gate.

#### Child 6.1-a: OpenID4VP request side

Signed request object by reference (`request_uri`), DCQL query for PID claims, nonce and `state` per flow, same-device link and cross-device QR, `direct_post` response endpoint bound to the flow. Done when request objects verify against the verifier key and each parameter is covered by a test.

#### Child 6.1-b: SD-JWT VC verification

Issuer signature against configured trust anchors, disclosure digests, key-binding JWT (`nonce`, `aud`, `iat` window, `sd_hash`), expiry, status-list check, claim ceilings (only requested claims reach tokens). Done when every step has a negative test and the VP-token parser is fuzzed.

#### Child 6.1-c: mdoc verification

Deferred inside the parent: ISO 18013-5 mdoc device authentication and MSO validation. Recorded as not implemented with the gate if time does not allow.

#### Child 6.1-d: Method adapter, configuration and docs

`authn.Method` (`same-device`, `qr`), configuration invariants (demo trust never in production), data-flow update for PID attributes, `amr` `eudi_pid`. Done when `authntest.Run` passes and a fixture wallet logs in through the issuer.

#### Child 6.2-a: Simulated wallet and case catalog

Wallet simulator producing valid and malformed SD-JWT VC presentations; `conformance/cases/*.yaml` with spec section links pinned by version. Done when one positive and at least ten negative cases exist.

#### Child 6.2-b: Runner and reports

Runner against a verifier endpoint, JUnit XML and Markdown report. Done when the run against the bridge produces both and every negative case is rejected.

#### Child 8.1-a: Signing API and authentication

Client-credentials authenticated `POST /api/v1/sign` and `GET /api/v1/sign/{id}`, separate from login, rate-limited, no persistence. Done when unauthenticated, wrong-client and replayed requests fail.

#### Child 8.1-b: Smart-ID signature session relay and verification

Relay the digest to the RP API signature session, verify the returned signature against the signer certificate (chain, non-repudiation purpose, status). Done when tampered signature, wrong digest and authentication-certificate cases fail.

#### Child 8.1-c: Documentation and example

`docs/signing.md` with a container-building example using an existing library; no qualified-signature claims. Done when the example runs against the fixture.
