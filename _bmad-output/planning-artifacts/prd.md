---
title: eidbridge product requirements
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# PRD: eidbridge

## Decision and document purpose

Deliver one self-hosted Go bridge from verified Smart-ID RP API v3 authentication to standard OIDC. Device-link is the first hypothesis to validate; config-only IdP integrations are the adoption path. This document defines capabilities; implementation details live in [architecture](architecture.md) and [addendum](addendum.md). All 30 source issues remain open. This source-backed draft records planning, not user approval, implemented behavior or production readiness.

## Vision and target users

Small relying parties and integrators can add Baltic eID to an OIDC-capable app without maintaining a proprietary plugin per IdP. Operators own deployment, keys, production agreements and account policy. Users complete a clear device handoff without the bridge retaining an identity history. Project authors receive no authentication data by design.

Jobs: prove integration locally before procurement; connect verified login to an existing IdP; understand personal-data movement; diagnose upstream changes. Managed-SLA broker customers, credential issuers, wallet builders and qualified-trust-service operators are outside the initial audience.

## Initial release boundary

Issues 1–14, 16 and 17 are the source-defined hardened authentication release candidate; notification is opt-in. Issues 15 and 18 are the next adoption increment. An earlier device-link-only experiment must be labelled a narrower preview; it does not complete this release set. None of the 12 deferred issues is committed to initial delivery.

Non-goals: hosted SaaS/paid brokerage, transaction resale/metering, project-supplied production credentials, user database, refresh tokens/dynamic registration/logout endpoints, per-IdP plugin code by default, QES/QSCD/timestamping/long-term validation, wallet issuance, proxy/OSINT tooling, legacy RP API v1. HA/shared state/default audit persistence require separate decisions.

## Success and counter-metrics

- SM-1: resolve the six-hour public demo spike and automation limits, FR-002; no success currently claimed.
- SM-2: clean clone reaches QR without secret setup and prepared demo login completes within five minutes, FR-014; disclose app registration/setup separately.
- SM-3: required negative verification/OIDC/privacy tests and original AC all pass before a story is done, FR-003/006/008–013.
- SM-4: source adoption hypothesis is at least three external adopters in 90 days after actual launch. Public counters support, but do not prove, safe authentication. Source forecasts resolve separately on 2027-02-14.
- Counter-metrics: never trade verification, zero retention, truthful assurance or cost disclosure for setup speed/download counts. Deduplicate asks. PyPI downloads are not applicable until FR-025 is activated.

## Source-derived flows

These scenarios are reconstructed from issues, not customer-interview narratives. UJ-1: evaluator starts Compose, sees a marked demo, scans QR or opens the demo app on the same device, confirms, and reaches sample OIDC claims. UJ-2: operator configures RP identity, trust, key and static client, validates demo rejection, and tests an IdP account linked by stable subject. UJ-3: user refuses or times out; the page explains the outcome and permits a fresh bounded attempt without retaining the old identity. UJ-4: operator follows a pin/CA or upstream error through the runbook and verifies recovery without sensitive logs.

## Glossary

Bridge: eidbridge, an RP to the eID service and OIDC provider to clients. Method: internal backend producing a cryptographically verified identity. Flow: bounded browser transaction, upstream session and OIDC context. Device-link: Smart-ID v3 same-device link or cross-device dynamic QR. Notification: explicitly enabled identifier-based v3 push flow. Demo: non-production environment with visible and token markers. Subject: configured stable public or pairwise OIDC identifier; never link by name. Conformance evidence: dated suite results for a pinned profile, not certification.

## Constraints, assumptions and open decisions

Research was frozen on 2026-11-16; issues retrieved on 2026-11-18. Competitor prices, versions, package absence and legal interpretations are dated source claims, not independently refreshed facts. Source libraries/frameworks are candidates; check versions/docs during implementation.

[ASSUMPTION A-01] Preserve the Smart-ID-to-OIDC product focus and the deferred labels: capture does not activate every feature. [ASSUMPTION A-02] Ten hours/week and zero marketing budget are study assumptions, not confirmed availability. [ASSUMPTION A-03] Go, dual permissive licensing and one replica are source constraints, not implemented choices.

Q-01: resolve spike and exact protocol/profile before FR-003; owner maintainer. Q-02: confirm assurance/claim mapping and certificate-status responsibilities under chosen profile/agreement before production assertions, and confirm the pairwise `sub` default; owner protocol/security maintainer. Q-03: choose OIDC library (and whether `private_key_jwt` ships in v1) and enumerate conformance-plan differences without adding unrequested flows before FR-006; owner maintainer. Q-04: confirm capacity/dates after spike because 40 hours underestimates issue scope, and set the measured capacity, token-lifetime and rate values; owner project owner. Q-05: secure native-speaker review and concrete IdP matrix before relevant release; owner integration/localization maintainer. These are implementation gates, not missing input to this integration task.

## Features and stable requirements

FR numbers match GitHub issue numbers. See [roadmap](roadmap.md) for release sets and [source reconciliation](source-reconciliation.md) for source-to-story coverage.

### Verified authentication

#### FR-001: Scaffold Go module with CI, licence checks and release automation

Operators can obtain static Go binaries and a non-root container with CI, dependency-licence checks, checksums and SBOM.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `go build ./... && go vet ./... && go test ./...` passes locally and in CI on an empty skeleton

#### FR-002: Spike Smart-ID v3 device-link login against the public demo env

A maintainer can resolve public demo device-link feasibility in a six-hour capped spike, capture synthetic fixtures, and record fallback and CI-automation outcomes.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `go run ./cmd/sidspike` exits 0 with `AUTHENTICATED` and a verified certificate for a demo account, or the ADR documents which fallback was taken and why

#### FR-003: Implement Smart-ID RP API v3 client with signature verification

The bridge can create and poll Smart-ID v3 device-link sessions and produce an identity only after challenge, signature, chain, validity and certificate-level verification.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `go test ./internal/smartid/` passes using recorded fixtures (from the spike) with no network

#### FR-004: Support Smart-ID v3 notification-based authentication flow

When explicitly enabled, users can authenticate by v3 notification with locally validated identity inputs, verification-code display, identity-match verification and abuse limits.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Fixture-based tests for notification session create/poll/verify

#### FR-005: Define a method-neutral authenticator interface for eID backends

The OIDC provider can consume verified identities through an internal method-neutral contract tested for success, refusal, timeout and verification failure.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Smart-ID client wrapped as `authn.Method`; OIDC package imports only `internal/authn`

#### FR-006: Expose eID logins as a standard OpenID Connect provider

Statically configured clients can complete authorization-code OIDC with PKCE, discovery, JWKS, token and userinfo, single-use bound codes and explicit claim allow-lists.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `go test ./internal/oidc/` covers discovery, code exchange, PKCE failure, code replay, wrong redirect URI, expired code

#### FR-007: Wire eidbridge binary with login page, QR and Web2App flows

Operators can configure the binary; users can complete QR or same-device login through an accessible bounded flow page with health endpoints and documented options.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `go run ./cmd/eidbridge --demo` serves a QR on `http://localhost:8080` and completes a login with the demo app

### Security and operator responsibilities

#### FR-008: Pin RP API TLS certificates and make trust anchors configurable

Operators can configure normal TLS validation plus rotating SPKI pins and authentication trust anchors, inspect active trust, and receive actionable failures.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Unit test with a local `httptest.NewTLSServer`: matching pin succeeds, mismatching pin fails

#### FR-009: Redact personal identity codes at the log sink

All log sinks irreversibly mask personal identifiers, certificates, signatures and session secrets; unsafe logging cannot be enabled by configuration.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Table-driven tests for each identifier format and for PEM/base64 masking

#### FR-010: Enforce no telemetry and zero data retention by default

The bridge can authenticate without telemetry or persistent personal flow data, with bounded memory, terminal-state deletion and restricted egress.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Test: after a completed fixture login and after TTL expiry, the store holds zero entries for that flow

#### FR-011: Warn on demo environment use and block demo credentials in prod

Demo logins visibly identify their environment, tokens carry demo markers, and production startup rejects demo or mixed-trust configurations.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Unit tests for each detection rule

#### FR-012: Add unofficial-project notice, trademark policy and clean-room rules

Integrators and contributors can find unofficial-project notices, production-agreement responsibilities, attribution and clean-room rules on every relevant surface.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Disclaimer present in README, login page template and container image labels (`org.opencontainers.image.description`)

#### FR-013: Document end-to-end personal data flow for integrator DPIAs

Integrators can inspect every personal-data field received, held, emitted and discarded, with roles, purpose, lifetime and evidence for their own processing assessment.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `docs/data-flow.md` merged and linked from README and `docs/security.md`

### Evaluation and adoption

#### FR-014: Ship a zero-config docker compose demo with a sample relying party

An evaluator can start a one-command bridge and sample RP demo, reach QR without credential setup and complete a prepared demo-app login within five minutes.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** From a clean clone, `docker compose up` reaches a QR page with no extra steps

#### FR-015: Add config-only IdP integration guides with e2e tests per IdP

Operators can configure Keycloak, authentik, Zitadel and Ory using OIDC guides validated against versioned fixture-based end-to-end stacks.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Following `docs/idp/keycloak.md` on a fresh Keycloak container results in a logged-in user via the demo environment (verified manually once, screenshot in doc)

#### FR-016: Localize the login page for Estonian, Latvian, Lithuanian, English

Users can select en, et, lv, lt or ru for login/error text via ui_locales, Accept-Language or configured default, with reviewed catalog completeness.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** Test: every key in `en.json` exists in all other catalogs (CI fails on missing keys)

#### FR-017: Add a maintenance runbook for upstream API, TLS and key changes

Maintainers can track API, TLS, certificate and demo-key changes and execute a documented incident/rotation process with dated compatibility evidence.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `docs/api-tracking.md` and `CHANGELOG.md` merged

#### FR-018: Add Django and FastAPI examples that log in through the bridge

Django and FastAPI developers can use standard OIDC examples with fixture tests, stable subject linking and production rejection of demo assertions.

**Scope:** Active backlog; release safety gates apply.

**Testable consequence:** `pytest examples/` passes locally and in CI

### Deferred authentication methods

#### FR-019: Add Mobile-ID authentication via the MID REST API

When its demand gate opens, users can authenticate through Mobile-ID behind the same verified-identity contract and OIDC issuer.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** `go test ./internal/mobileid/` with recorded fixtures, including tampered signature and identity mismatch cases

#### FR-020: Let users choose among multiple enabled eID methods

When a second method is justified, users and clients can select only enabled and permitted methods; tokens describe the method and evidence-supported assurance actually used.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Tests: `acr_values` filtering, `login_hint` preselect, per-client restriction, `amr` in token

#### FR-021: Add ID-card login via Web eID token validation in Go

When security and demand gates open, ID-card users can authenticate through Web eID with origin/nonce binding, certificate validation and revocation checks.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Test vectors: valid token, wrong origin, replayed nonce, expired cert, revoked cert (mock OCSP), untrusted CA

#### FR-022: Accept EUDI Wallet presentations via OpenID4VP as a login method

When profiles, demand and wallet access gates open, users can present a verified wallet PID through OpenID4VP and receive allow-listed OIDC claims.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Presentation from the EU reference wallet verified end to end in a test environment

#### FR-023: Build an EUDI Wallet relying-party conformance test harness

After wallet authentication exists, maintainers can run a versioned verifier harness with positive/negative cases, JUnit and per-requirement evidence, without certification claims.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Runs against the bridge's EUDI method in CI and produces a JUnit report

### Demand-gated ecosystem and operations

#### FR-024: Provide a native Keycloak identity provider SPI for eidbridge

Only if three deployers identify a gap in config-only integration, Keycloak operators can use a version-tested optional native SPI.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Jar deploys into Keycloak `providers/`; provider appears in admin console

#### FR-025: Publish a minimal Python client for Smart-ID RP API v3

Only if two users require direct protocol access, Python developers can use a separately maintained client with shared verification fixtures and neutral package naming.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** `pip install` from built wheel; `python -c "import eidbridge_rp"` works

#### FR-026: Add an eidbridge doctor command for upstream connectivity checks

After a diagnostic-gap outage report, operators can run connectivity, pin, certificate-expiry and trust diagnostics with JSON output and endpoint-only traffic.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Tests with `httptest` TLS servers for pin mismatch, expiring cert, unreachable host

#### FR-027: Ship a mock RP API server and test identities for offline testing

After offline-testing demand, integrators can run a loopback-first synthetic RP API mock controlling success, refusal, timeout and wrong-code paths.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Bridge e2e and IdP e2e suites run against the mock in CI with no external network

#### FR-029: Support legacy Smart-ID RP API v2 for existing relying parties

Only for a deployment unable to use v3, integrators can select a separately tested legacy v2 notification backend; v1 remains excluded.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Fixture tests for v2 create/poll/verify incl. negative cases

#### FR-030: Document or ship a WordPress login integration via the bridge

When WordPress users ask, integrators can configure a maintained OIDC login plugin through a tested guide; a new plugin requires a demonstrated remaining gap.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Guide followed on a fresh WordPress container produces a logged-in user via the mock upstream

### Deferred signing

#### FR-028: Support document signing sessions alongside authentication

After stable authentication and a concrete signing need, authenticated integrators can relay digests and verify returned signatures without the bridge asserting qualified status.

**Scope:** Deferred; original demand/security gate applies.

**Testable consequence:** Fixture tests for signing session create/poll/verify

## Cross-cutting non-functional requirements

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

## Operations requirements

### Operator documentation requirements

Operator documentation includes a table of field, purpose, source, location, lifetime, emission and logging; a code-to-document check of claim names; a Mermaid sequence diagram; the effects of configurable claims, `sub` mode and access-log settings; and deployer-completed DPIA and RoPA aids. The project issues no completed legal assessment or universal role determination. Project authors have no intended data path, but actual hosting or support arrangements can change data protection roles. Operators evaluate their own agreements, sector duties and data protection obligations.

### Production checklist

- Own RP agreement and identity.
- HTTPS, issuer and trusted-proxy configuration.
- Secret mounts, non-root user and read-only runtime.
- Correct trust groups and fresh keys.
- Strict client redirects and claim allow-lists.
- Demo-negative tests.
- Configured request and rate bounds.
- Incident contacts.
- A successful recovery drill that covers planned key rotation and emergency key revocation.

### Incident reason-code matrix

The matrix separates user refusal, abuse, upstream outage, stale pin or CA, and key compromise. Each row lists the detect, contain, drain, rotate, recover and notify steps with evidence. The operator reviews legal notification timing and applicability; this project does not prescribe them from unverified source PDFs.

## Assumptions index

A-01 product/deferred gates; A-02 capacity/budget; A-03 stack/licence/deployment. Further conflicts are in [source reconciliation](source-reconciliation.md); unresolved implementation choices are in [readiness](implementation-readiness-report-2026-11-18.md).
