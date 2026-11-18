---
title: eidbridge architecture and decision baseline
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
  - research/architecture-review-2026-11-18.json
  - research/smart-id-v3-facts-2026-11-18.md
  - research/rfc9700-checklist-2026-11-18.md
  - ../../docs/spec-pins/spec-pins.json
---

# Architecture and decision baseline

## Status and authority

This is an architecture proposal derived from issues and research, not an implementation survey. In this document, *source* means the GitHub issues and research inputs in the frontmatter, never source code. No application starter is installed or selected; do not invent one or copy a competitor app. Original API sketches remain in [addendum](addendum.md). Complete a security review of the actual implementation before any production release: this document is neither a cryptographic review nor evidence that any product test passes.

## Decision index

| ADR | Decision | Status | Q-xx | Owner | Blocks | Evidence |
|---|---|---|---|---|---|---|
| [ADR-001](#adr-001-validate-risky-access-before-building) | Six-hour demo spike before building | Proposed gate | [Q-01](prd.md#constraints-assumptions-and-open-decisions) | Maintainer | [FR-003](prd.md#fr-003-implement-smart-id-rp-api-v3-client-with-signature-verification) | Redacted spike notes |
| [ADR-002](#adr-002-privacy-and-transient-state-lifecycle) | Memory-only flow state, state machine, data lifecycle | Retained default; resolution proposed | None | Maintainer | [FR-007](prd.md#fr-007-wire-eidbridge-binary-with-login-page-qr-and-web2app-flows), [FR-010](prd.md#fr-010-enforce-no-telemetry-and-zero-data-retention-by-default) | Stories 2.5 and 2.6 tests |
| [ADR-003](#adr-003-trust-and-production-separation) | TLS pins, mode separation, configuration invariants | Retained guardrail | [Q-02](prd.md#constraints-assumptions-and-open-decisions) | Protocol and security maintainer | [FR-008](prd.md#fr-008-pin-rp-api-tls-certificates-and-make-trust-anchors-configurable), [FR-011](prd.md#fr-011-warn-on-demo-environment-use-and-block-demo-credentials-in-prod) | Story 2.2 and 2.7 tests |
| [ADR-004](#adr-004-oidc-boundary-and-dependency-hygiene) | Maintained OIDC library over handwritten code | Proposed choice | [Q-03](prd.md#constraints-assumptions-and-open-decisions) | Maintainer | [FR-006](prd.md#fr-006-expose-eid-logins-as-a-standard-openid-connect-provider) | Library evaluation record |
| [ADR-005](#adr-005-release-evidence-operations-and-deviations) | Release evidence and deviation table | Accepted criterion | [Q-04](prd.md#constraints-assumptions-and-open-decisions) | Project owner | [FR-001](prd.md#fr-001-scaffold-go-module-with-ci-licence-checks-and-release-automation), [FR-013](prd.md#fr-013-document-end-to-end-personal-data-flow-for-integrator-dpias), [FR-017](prd.md#fr-017-add-a-maintenance-runbook-for-upstream-api-tls-and-key-changes) | Per-release table |
| [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | Future method gates | Deferred | None; a demand trigger | Maintainer | [FR-019](prd.md#fr-019-add-mobile-id-authentication-via-the-mid-rest-api), [FR-020](prd.md#fr-020-let-users-choose-among-multiple-enabled-eid-methods) | Demand trigger |
| [ADR-007](#adr-007-subject-and-key-management) | HMAC `sub`, versioned keys, two key procedures | Proposed | [Q-02](prd.md#constraints-assumptions-and-open-decisions), [Q-03](prd.md#constraints-assumptions-and-open-decisions) | Protocol and security maintainer | [FR-006](prd.md#fr-006-expose-eid-logins-as-a-standard-openid-connect-provider) | Stories 2.4 and 3.4 tests |
| [ADR-008](#adr-008-token-model-and-authorize-contract) | Sealed opaque access tokens, authorize contract | Proposed | [Q-02](prd.md#constraints-assumptions-and-open-decisions), [Q-03](prd.md#constraints-assumptions-and-open-decisions) | Protocol and security maintainer | [FR-006](prd.md#fr-006-expose-eid-logins-as-a-standard-openid-connect-provider) | Story 2.4 tests |
| [ADR-009](#adr-009-capacity-and-availability) | Capacity model, poller, readiness, shutdown | Proposed | [Q-01](prd.md#constraints-assumptions-and-open-decisions), [Q-04](prd.md#constraints-assumptions-and-open-decisions) | Maintainer | [FR-007](prd.md#fr-007-wire-eidbridge-binary-with-login-page-qr-and-web2app-flows), [FR-010](prd.md#fr-010-enforce-no-telemetry-and-zero-data-retention-by-default) | Story 2.5 tests |
| [ADR-010](#adr-010-browser-binding) | Per-flow cookie and Web2App return binding | Proposed | [Q-01](prd.md#constraints-assumptions-and-open-decisions) | Maintainer | [FR-007](prd.md#fr-007-wire-eidbridge-binary-with-login-page-qr-and-web2app-flows) | Story 2.5 tests |

Open gates: [Q-01](prd.md#constraints-assumptions-and-open-decisions) to [Q-05](prd.md#constraints-assumptions-and-open-decisions) in the PRD stay implementation gates. The [Review resolution](#review-resolution) table traces every 2026-11-18 review finding to a section and a verifying test or gate.

## Context and boundaries

Constraints:

- Go single binary with standard-library-first dependencies.
- Dual MIT/Apache-2.0 licensing.
- Exact runtime and library versions are chosen at implementation, from their current documentation.
- Memory-only state, with no database or shared store in v1.

Request flow, trust inputs and trust boundaries:

~~~mermaid
flowchart LR
  subgraph Device[User device]
    B[Browser]
    E[eID app]
  end
  subgraph Client[Integrator]
    I[Integrator app or IdP]
  end
  subgraph Host[Operator host]
    O[eidbridge OIDC provider]
    A[Verified identity method interface]
    M[Bounded memory flow and code store]
    K[Operator keys and trust config]
  end
  subgraph Scheme[Smart-ID scheme]
    S[Smart-ID v3 RP API]
  end
  B <-->|front channel| I
  B <-->|login page, QR, flow cookie| O
  I -->|code exchange, userinfo| O
  O --> A
  A --> S
  O --> M
  K --> O
  K --> A
  E <-->|authentication| S
~~~

The OIDC client owns account provisioning, linking, and long-lived user sessions. The bridge is an RP toward the scheme, not a scheme-certified identity provider. The operator supplies production RP credentials through configuration; the code never includes them. No payment, billing, resale, hosted deployment or project-author data collection is part of this design.

Proposed layout (implementation targets, not present source files):

- `cmd/eidbridge`: binary entry point.
- `internal/smartid`: Smart-ID v3 client.
- `internal/authn`, `internal/authn/authntest`: method interface and contract suite.
- `internal/oidc`: provider endpoints and tokens.
- `internal/web`: pages, flow handles and cookies.
- `internal/config`: configuration and startup invariants.
- `internal/logx`: typed no-PII logging.
- `internal/store`: bounded flow and code stores.
- `internal/tlspin`: pinned TLS client.
- `trust`: trust anchors and pins.
- `examples`: integration examples.
- `docs/spec-pins`: pinned specification metadata.
- `test/e2e`: end-to-end tests.

The method registry stays internal until several implementations justify stabilizing it. OIDC and web code receive a registry interface, not direct backend imports. Browser-only middleware calls methods through server-owned flow handles.

## Threat and validation model

| Threat | Control | Evidence required |
|---|---|---|
| Fake upstream success or identity substitution | Protocol signature, challenge, identity, chain and level checks | Offline mutation vectors and `Verify` coverage |
| Flow takeover, code replay or open redirect | Unguessable server-owned state; cookie, nonce, client, redirect and PKCE binding; one-use codes with a TTL | Browser and session swap, late callback, replay and redirect negatives |
| Push spam, enumeration or resource exhaustion | Opt-in notification (account existence stays observable there: a disclosed residual risk), local input validation, per-IP and per-client limits, bounded store and polling | No-egress invalid inputs, rate and capacity tests |
| Real-time QR relay phishing | The bridge regenerates the QR every second and never serves one older than three seconds; the interaction text names the bridge; same-device Web2App is phishing-resistant through callback binding (ADR-010); notification mode shows a verification code, device-link shows none; cross-device QR relay stays a disclosed residual risk | Staleness test; relay-attempt test (a Web2App callback in another browser fails; the QR relay outcome is recorded as a deviation) |
| UI injection and framing | Strict CSP, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, template autoescaping, no third-party resources | Response-header test on every page |
| Authorization-server mix-up | RFC 9207 `iss` in every authorization response, advertised in discovery | Authorize-response test |
| Token theft or replay | Sealed opaque tokens of five minutes or less, replay deny-list | Replay and expiry tests |
| Demo identity in production | Startup configuration invariants, separate demo issuer and key, demo token rejection in clients | Mixed-environment matrix and production realm negatives |
| Signing-key compromise | Emergency revocation procedure, separate from planned rotation | Recovery drill covering both procedures |
| Overload | Quotas, 503 without eviction, readiness independent of saturation | Capacity and saturation tests |
| PII or secret leak | Typed logging plus non-disableable sink redaction; no default persistence or telemetry | `DEBUG` fixture log capture, filesystem and egress isolation, lifecycle assertions |
| Upstream trust drift | Separate rotating pins and CA groups, explicit status policy, runbook | Rotation, stale trust, expiry and recovery drill |
| False compliance or confidence | Scope limits and versioned deviations | Release checklist separates pass, fail and not-run; no unsupported claims |

## ADR-001: validate risky access before building

**Status.** Proposed execution gate.

**Decision.** Run the six-hour synthetic spike after the minimal scaffold and safe logging. Record the protocol and profile, the device-link behavior, the signature and chain results, the demo registration requirements, and scriptable-test availability, plus what the pinned docs leave open: the poll quota, session lifetime, upstream cancellation, and callback replay handling. Use no production identities, redact console output and keep fixtures under `testdata`. The original spike prints subject fields and offers Mobile-ID, then Web eID, as fallbacks; apply the privacy guards anyway. Notification mode may be measured as a fallback without changing the primary method (device link).

**Source reconciliation.** If the public demo is blocked or access needs a contract or payment: stop and replan. Mobile-ID and Web eID are not automatic cheap substitutes (ADR-006).

**Open gates and evidence.** [Q-01](prd.md#constraints-assumptions-and-open-decisions); redacted spike notes. The pinned source is Smart-ID RP API 3.2.8 (its OpenAPI file reads 3.1); see the [facts note](research/smart-id-v3-facts-2026-11-18.md) and `docs/spec-pins/spec-pins.json`.

## ADR-002: privacy and transient state lifecycle

**Status.** Retained default; lifecycle resolution proposed.

**Decision.** Personal flow data stays in memory, within the ceilings in ADR-009. Unfinished flows expire at flow timeout plus 30 seconds; authorization codes live at most 60 seconds and are single-use. The claim set is plaintext in process memory, keyed by the code hash, until code exchange or code expiry. Upstream secrets are destroyed when verification completes, and every terminal state removes its entry and clears the flow cookie. Each terminal response carries a return link that redirects to the validated `redirect_uri` with `iss` and `state`: `access_denied` for `refused`, `cancelled` and `expired`, and `server_error` for `failed`. A fresh attempt is a new authorize request from the client, never a reuse of the old flow. The two tables below are normative and become test fixtures.

| Concern | Rule |
|---|---|
| Persistence | Signing keys, trust files, configuration and synthetic fixtures are not user flow history. The demo volume stores only the demo signing key. There is no shared store, so a restart loses pending flows and users start again (ADR-009); claim no high availability. Sticky sessions are at most future deployment advice. |
| Logging | Access logs record the method and route template only, never raw paths or queries (callback parameters and flow IDs stay out); no IP is stored beyond rate-limit memory; core dumps are disabled and the swap and `mlock` requirement is documented; IP and user-agent handling is documented; reverse-proxy logs are the operator's responsibility. Typed no-PII logging is the primary control and sink masking the backstop at every level. A source warning that `DEBUG` may contain PII does not permit logging raw identifiers. |
| Egress | No telemetry, update or crash beacons. Outbound traffic uses configured endpoint clients, and egress-isolated tests prove no unrelated traffic. DNS and trust-status checks are explicit in the selected profile. Pull-only metrics stay deferred with [FR-026](prd.md#fr-026-add-an-eidbridge-doctor-command-for-upstream-connectivity-checks). |

**Source reconciliation.** This reconciles [#10](https://github.com/tomkabel/eidbridge/issues/10) ("delete on completion") with [#13](https://github.com/tomkabel/eidbridge/issues/13) ("until code exchange"): authentication success is not completion of OIDC delivery. Deleting bridge state does not retract tokens clients already hold (ADR-008).

**Open gates and evidence.** Tests for Stories 2.5 and 2.6 in Review resolution.

### Flow state machine

Cell values: a state name is the next state; `stay` changes nothing; `discard` ignores the input, destroys any secret it carries and records a reason code. Terminal states are `verified`, `refused`, `expired`, `failed` and `cancelled`.

| Input | created | pending | verified | refused | expired | failed | cancelled |
|---|---|---|---|---|---|---|---|
| Upstream session created (QR page loaded) | pending | discard | discard | discard | discard | discard | discard |
| Upstream init error | failed | discard | discard | discard | discard | discard | discard |
| Explicit cancel (POST with the flow binding token); abandonment is detected only by timeout | cancelled | cancelled | stay | stay | stay | stay | stay |
| Poll result: `endResult` OK and verification passes (QR or notification, or Web2App after the callback) | discard | verified | discard | discard | discard | discard | discard |
| Poll result: `endResult` OK in Web2App before the callback | discard | stay (`ok_seen`) | discard | discard | discard | discard | discard |
| Poll result: `endResult` OK but verification fails | discard | failed | discard | discard | discard | discard | discard |
| Poll result: identity mismatch (notification mode) | discard | failed | discard | discard | discard | discard | discard |
| Poll result: user-refusal `endResult` | discard | refused | discard | discard | discard | discard | discard |
| Poll result: upstream timeout `endResult` | discard | expired | discard | discard | discard | discard | discard |
| Poll result: other documented failure `endResult` | discard | failed | discard | discard | discard | discard | discard |
| Poll result: unknown `endResult` or malformed response | discard | failed | discard | discard | discard | discard | discard |
| Web2App callback passes available bindings; deferred verifier checked against signed result | discard | verified only if `ok_seen` and final verifier matches, else stay (`callback_seen`) | discard | discard | discard | discard | discard |
| Web2App callback without the flow cookie (another browser) | discard | stay | discard | discard | discard | discard | discard |
| Web2App callback fails the value, digest or verifier check | discard | failed | discard | discard | discard | discard | discard |
| Session creation blocked (no free poll slot) | stay | discard | discard | discard | discard | discard | discard |
| Page reload on an existing session | stay | stay | stay | stay | stay | stay | stay |
| Poll HTTP 404 (session unknown or expired upstream) | discard | expired | discard | discard | discard | discard | discard |
| Poll HTTP 400, 401 or 480 | discard | failed | discard | discard | discard | discard | discard |
| Poll transient error within the retry budget | discard | stay | discard | discard | discard | discard | discard |
| Poll retry exhaustion | discard | failed | discard | discard | discard | discard | discard |
| Flow timeout (`created`: the code TTL; `pending`: flow timeout plus 30 seconds) | expired | expired | stay | stay | stay | stay | stay |
| Late result for a missing or terminal entry | discard | discard | discard | discard | discard | discard | discard |
| Unknown input or unknown state | failed | failed | discard | discard | discard | discard | discard |

`failed` carries a reason code: `upstream_error`, `wrong_code`, `account_unusable`, `verification_failed`, `identity_mismatch`, `unknown_end_result`, `status_unavailable` or `retries_exhausted`. The pinned v3 API has no cancel operation, so on retry exhaustion the bridge tells the user to cancel on the device, lets the upstream session expire, and never accepts a later result. An identity mismatch never issues a code. In Web2App flows an `OK` result waits in `pending` until the callback passes the ADR-010 checks; if the flow timeout comes first, the flow is `expired`. A callback without the cookie shows the restart page and leaves the flow to expire.

The pinned session status has `state` `RUNNING` (poll again) or `COMPLETE`; only `COMPLETE` with `endResult` `OK` can succeed, after the verification steps in ADR-003. Every other combination maps as follows.

| Smart-ID result | Meaning | State |
|---|---|---|
| `COMPLETE` and `OK` | Success; certificate and document number returned | Verify, then `verified`, or `failed` (`verification_failed`) |
| `USER_REFUSED`, `USER_REFUSED_CERT_CHOICE`, `USER_REFUSED_INTERACTION` | User declined | `refused` |
| `TIMEOUT`, HTTP 404 (session unknown or expired) | No user response in time, or the session expired upstream | `expired` |
| `WRONG_VC` | Wrong code chosen | `failed` (`wrong_code`) |
| `DOCUMENT_UNUSABLE`, `ACCOUNT_UNUSABLE` | Account cannot complete the request | `failed` (`account_unusable`) |
| `REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP`, `PROTOCOL_FAILURE`, `EXPECTED_LINKED_SESSION`, `SERVER_ERROR` | App, protocol or server failure | `failed` (`upstream_error`) |
| HTTP 429 | Rate limited | Retry after `Retry-After` within the budget, then `failed` (`retries_exhausted`) |
| HTTP 400, 401, 480 or any other 4xx | Malformed request, wrong RP identity or source IP, client too old; a retry cannot succeed | `failed` (`upstream_error`) |
| HTTP 580, other 5xx or a network error | Maintenance or transient failure | Retry within the budget, then `failed` (`retries_exhausted`) |
| Any other `state` or `endResult` value, a 3xx, or a 2xx with an empty or malformed body | Not in the pinned spec | `failed` (`unknown_end_result`) |

### Data lifecycle

| Item | Created | Destroyed at | Memory owner |
|---|---|---|---|
| Flow entry | Authorize request accepted (state `created`) | Removed once a terminal state's response is sent, or at flow timeout plus 30 seconds | Flow store |
| Challenge and session secrets (`rpChallenge`, `sessionSecret`, stored `interactions`) and certificate material | Upstream session created | Verification completes after both callback and poll validation, or any terminal state; retained callback verifier bytes obey the same bounded lifetime; cleared with `clear()` where held as `[]byte`, best effort under Go's GC (disclosed residual) | Flow entry, held as `[]byte` or a wrapper type, never as strings; `sessionSecret` never reaches the browser |
| Entered identifier (notification mode) | Form submit | Verification completes, or any terminal state; held as `[]byte`, never logged | Flow entry |
| Claim set (plaintext) | Verification succeeds | Code exchange (success or failure), or 60-second code expiry | Code store, keyed by code hash |
| Authorization code (hash only) | Slot reserved at flow creation; filled at verification | Atomic consume at exchange; retain the consumed tombstone until its monotonic deadline, or release unexchanged codes after 60 seconds | Code store |
| Code tombstone (code hash to token family) | Atomic exchange; publish family-to-slot index before returning tokens | Maximum access-token lifetime plus skew after exchange, measured monotonically | Reserved code slot; fixed index overhead is in its memory budget |
| Sealed access token | Token response | Expiry (five minutes or less); the bridge keeps no copy | Client |
| Replay deny-list entry (token family) | Replay marks the existing tombstone revoked without allocation | Original family monotonic deadline, never extended by replay | Reserved code slot and bounded family index |
| Flow cookie | Flow created | Every terminal state, by an expiring `Set-Cookie`; otherwise the remaining lifetime to the original absolute deadline | Browser |

## ADR-003: trust and production separation

**Status.** Retained source guardrail; configuration invariants added.

**Decision.** The rules below hold in every deployment.

| Control | Rule |
|---|---|
| TLS identity | Normal chain and hostname verification plus SPKI SHA-256 pins (current and next), TLS 1.2 minimum, no re-enabled legacy suites. TLS trust is separate from authentication-signature CA roots; demo and production endpoints, pins and CA groups never mix. |
| Endpoints and proxies | A configurable endpoint must not become a browser-controlled SSRF target. Validate the production HTTPS issuer and explicitly configured trusted proxy hops; ignore spoofed `Forwarded` and `X-Forwarded-*` headers by default. When trusted hops are configured, only `X-Forwarded-For` is read (all header lines concatenated, parsed right to left). |
| `TLS_PINS=disabled` | Issue [#8](https://github.com/tomkabel/eidbridge/issues/8)'s escape hatch. It skips only the additional pin check, never CA or hostname verification, and a deployment that uses it cannot claim to be hardened. Production also needs the acknowledgement flag and emits the published deviation record. |
| Demo separation | Demo tokens carry `acr=demo` and `eid_env=demo`, use a distinct issuer path and a demo-labeled key; every production recipe rejects them. The demo banner appears on every demo login page and holds no personal data (UX-DR-003). |
| Certificate verification | Callback binding, `COMPLETE` with `OK`, signature protocol, root chain to configured CAs only, validity, revocation, Smart-ID policy and purpose, certificate level, identity match, signature over the rebuilt payload, and a returned `flowType` the bridge offered. Revocation status that is unknown, stale or unreachable fails with `failed` (`status_unavailable`), never `verified`; status fetches use only configured endpoints and count against the flow timeout. |
| Verification parameters | `signatureAlgorithm` RSASSA-PSS with SHA-256 or stronger (PKCS#1 v1.5 rejected); accepted certificate profiles are the authentication EKU `1.3.6.1.4.1.62306.5.7.0` and the older `clientAuth` profile; `shareMdClientIpAddress` is false; the minimum certificate level and the Smart-ID policy OIDs come from the [Q-02](prd.md#constraints-assumptions-and-open-decisions) decision (the pinned docs do not list the OIDs). |

**Source reconciliation.** Issue [#8](https://github.com/tomkabel/eidbridge/issues/8) excludes Smart-ID OCSP and AIA work from its scope, but the pinned RP API v3 response verification requires revocation checks (OCSP through AIA, with CRL fallback). [Q-02](prd.md#constraints-assumptions-and-open-decisions) must resolve status responsibilities before any production-sufficiency claim, and the egress policy must then name those endpoints explicitly. Web eID separately needs origin handling, nonce handling and revocation handling.

**Open gates and evidence.** [Q-02](prd.md#constraints-assumptions-and-open-decisions); mixed-environment matrix and production realm negatives.

### Configuration invariants

| Invariant | Mode | Startup result | Evidence |
|---|---|---|---|
| Mode unset (`EIDBRIDGE_MODE` or `--demo`) | Any | Fail: `mode` is required and has no default | Story 2.7 |
| Demo mode with anything outside the published demo allow-list (RP UUID, hosts, CA) | Demo | Fail | Story 2.7 |
| Production mode with any value on the demo allow-list, or a key with a `demo-` `kid` or on the embedded fixture-key fingerprint list | Production | Fail | Story 2.7 |
| Demo signing key | Demo | Auto-generated, `kid` prefixed `demo-`, issuer path `/demo`; the demo volume is never mounted in production | Story 2.7 |
| Production key matching embedded fixture or explicitly supplied demo-key fingerprints | Production | Fail for embedded fixtures or an operator-supplied demo-key fingerprint deny-list; malformed lists fail startup. Production never mounts the demo volume. Unknown historical provenance cannot be inferred from key bytes; operators generate fresh production keys | Story 2.7 |
| `TLS_PINS=disabled` without the acknowledgement flag | Production | Fail; with the flag, start with a warning and write the deviation record | Story 2.2 |
| No `trusted_proxies` configured and the first requests all come from private or load-balancer peers | Any | Warn once at runtime; the rate-limit key stays the resolved client IP | Story 2.7 |
| Production: any non-`https` issuer; demo: `http` only on `localhost`, where Web2App is not offered (`flow.offered` is QR) | Any | Fail | Story 2.7 |
| `EIDBRIDGE_SMARTID_ENV` disagrees with `mode` | Any | Fail | Story 2.7 |
| Unsupported signing algorithm in a client registration | Any | Fail | Story 2.4 |
| `K_sub` missing or its version unset | Production | Fail | Story 2.4 |
| `TLS_PINS` unset, empty, unparsable, or without a current pin (and not `disabled`) | Any | Fail | Story 2.2 |
| `TLS_PINS=disabled` | Demo | Start with a warning, no acknowledgement flag | Story 2.2 |
| Any ADR-008 configuration value (flow TTL, retry budget, clock skew, size and rate limits) unset or outside its bound | Any | Fail | Story 2.5 |

## ADR-004: OIDC boundary and dependency hygiene

**Status.** Proposed implementation choice.

**Decision.** Prefer a maintained provider library over handwritten JWT and protocol code, but name none until the evaluation is done. Evaluate license, dependency footprint, PKCE support, client-authentication support, key rotation, scope behavior, suite compatibility, and support for the RFC 9207 `iss` parameter and ADR-008 errors; handwrite only narrow gaps. A library qualifies only if it passes the ADR-008 behavior tests through store and hook interfaces; otherwise the code store, the sealing, and the deny-list are declared handwritten and sit outside the library boundary. Go clients in `oss_inventory` are dated candidates, not proof of adequate v3 device-link support. Reuse official permissively licensed code with attribution; do not copy the LGPL demo or unlicensed documentation. Spec pins in `docs/spec-pins` store the URL, version, hash, and license metadata, never harvested text. Add no IdP Java SPI or second OIDC provider because adjacent wallet research suggests one.

**Source reconciliation.** [Q-03](prd.md#constraints-assumptions-and-open-decisions) decides the library and the conformance-plan differences without adding unrequested flows.

**Open gates and evidence.** [Q-03](prd.md#constraints-assumptions-and-open-decisions); library evaluation record.

## ADR-005: release evidence, operations and deviations

**Status.** Accepted criterion, not an executed release.

**Decision.** Extend [FR-001](prd.md#fr-001-scaffold-go-module-with-ci-licence-checks-and-release-automation), [FR-013](prd.md#fr-013-document-end-to-end-personal-data-flow-for-integrator-dpias) and [FR-017](prd.md#fr-017-add-a-maintenance-runbook-for-upstream-api-tls-and-key-changes) with portable source-built artifacts, pinned inputs, checksums, SBOM, provenance, verification instructions, and a smoke test of the published artifact. Claim reproducibility only with independent rebuild evidence; otherwise disclose build variance. Do not inherit Rust constraints, glibc constraints, or CPU constraints from wallet code. Maintain the per-release table below. Run the OIDF Basic OP plan from [#6](https://github.com/tomkabel/eidbridge/issues/6), record results and reconcile unsupported plan features; valid discovery or third-party token validation alone is not conformance. Record the RFC 9700 self-check as PASS, FAIL, or NOT RUN. Operator documentation, the production checklist and the incident matrix live in the [PRD operations requirements](prd.md#operations-requirements).

**Source reconciliation.** Do not hide a failure by marking omitted acceptance criteria done. The nightly compatibility workflow in [FR-017](prd.md#fr-017-add-a-maintenance-runbook-for-upstream-api-tls-and-key-changes) is an acceptance requirement only; implement it separately with deduplication, bounded retries and sanitized reports. Support policy: fixes ship in the latest minor release, and pin and CA fixes are backported one minor release if it is maintained. No paid SLA is inferred.

**Open gates and evidence.** [Q-04](prd.md#constraints-assumptions-and-open-decisions); one table row per release.

| Requirement or profile version | Status (implemented, deviation or not run) | Test or evidence path and commit | Scope and risk | Owner and next action |
|---|---|---|---|---|
| | | | | |

## ADR-006: future method gates and dependency repairs

**Status.** Deferred.

**Decision.** Until a demand trigger arrives, only the registry contract test with a fake method exists. The chooser UI ([FR-020](prd.md#fr-020-let-users-choose-among-multiple-enabled-eid-methods)) and Mobile-ID ([FR-019](prd.md#fr-019-add-mobile-id-authentication-via-the-mid-rest-api)) activate together, on real Mobile-ID demand. This breaks the source's circular dependency, where the chooser waits for a second method while Mobile-ID waits for the chooser. The remember-method cookie stays opt-in, short-lived and non-identifying, and is ignored when its method leaves the registry (ADR-010). Web eID ([FR-021](prd.md#fr-021-add-id-card-login-via-web-eid-token-validation-in-go)) needs a separate validator, an origin-bound one-use nonce, chain checks, usage checks, policy checks, correct status validation, hardware tests, parser fuzzing, a library license choice and external security review. Split its 80–100 hour estimate into reviewable stories before sprint commitment, with no "cheap fallback" assumption. Wallet work ([FR-022](prd.md#fr-022-accept-eudi-wallet-presentations-via-openid4vp-as-a-login-method), [FR-023](prd.md#fr-023-build-an-eudi-wallet-relying-party-conformance-test-harness)) first needs exact OpenID4VP versions, HAIP versions, ARF versions, and credential-format versions, a test wallet and real RP demand; compare native IdP support before building. The conformance harness follows a verified wallet method, with a core positive case, at least ten negative cases, pinned spec references, JUnit output and no certification claim.

**Source reconciliation.** Deferred adjacent wallet candidates (ADJ-01 to ADJ-18) and out-of-product items are tracked in [source reconciliation](source-reconciliation.md#deferred-adjacent-wallet-candidates). None is an initial-release promise.

**Open gates and evidence.** A demand trigger (real Mobile-ID demand); the fake-method contract test.

## ADR-007: subject and key management

**Status.** Proposed.

**Decision.** The rules below are normative.

| Rule | Specification |
|---|---|
| `sub` | `base64url(HMAC-SHA256(K_sub[v], "eidbridge-sub-v1" ‖ 0x00 ‖ sector ‖ 0x00 ‖ type ‖ 0x00 ‖ country ‖ 0x00 ‖ code))`, where `sector` is `g:public` or `c:<sector_id>` (a `sector_id` that collides is rejected) and the last three come from the certificate Subject `serialNumber` parsed with `^(PNO|PAS|IDC)([A-Z]{2})-(.+)$` (any other form is rejected). A raw or plainly hashed personal code is never a `sub`: guessable national codes fall to enumeration. |
| `K_sub` | 256 bits, versioned in configuration, never rotated in place. Back it up under the same custody as the signing key; losing it is a migration for every client. |
| Rotation | A migration. During the window, ID tokens for declared clients carry `sub` (new version) and `previous_sub` (old version), so clients relink accounts at the next login. `migration_window_days` is required and bounded; after it `previous_sub` is dropped automatically. |
| Mode change | Changing a client's `sub_mode` or `sector_id` is rejected unless the same migration is declared. |
| Default mode | Pairwise is a proposed privacy default that still needs confirmation; the source does not approve it. |
| Algorithms | RS256 baseline, ES256 optional. `id_token_signed_response_alg` is set per client and defaults to RS256; registering an unsupported algorithm fails startup. Allow-list only, never `none`, and every key has a `kid` (RFC 8725). |
| Key persistence | Signing keys persist across restarts. RSA keys are at least 2,048 bits (3,072 recommended), ES256 uses P-256 only, each enabled algorithm has one active key, production `kid` is the JWK thumbprint and demo `kid` is `demo-` plus that thumbprint, and the key file mode (0600) is verified at startup. The recovery drill exercises both procedures below. |

| Linkability (LINDDUN) | Public mode | Pairwise mode |
|---|---|---|
| Sector | One global sector, `public` | One per client (`sector_id`, default `client_id`) |
| Clients can link one user across services | Yes, by design; disclosed | No |
| Clients can recover the personal code from `sub` | No | No |
| Operator can recompute any `sub` | Yes, holds `K_sub` | Yes, holds `K_sub` |

| Procedure | Steps |
|---|---|
| Planned rotation | Publish and sign with the new key. The retired public key stays in JWKS until the longest token expiry plus clock skew. Retired keys persist with a `not_after` time, so they survive restarts. |
| `K_sub` compromise | Issue a new `K_sub` version, run the migration window with `previous_sub`, retire the old version as soon as clients have relinked, and notify clients. Treat it as a privacy incident: guessable national codes allow enumeration. |
| Emergency revocation | Generate and activate a replacement signing key, then remove the compromised key from JWKS immediately. Rotate the access-token sealing key (ADR-008). Require clients to re-authenticate. Clients with a cached JWKS may accept the old key until they refresh; ID tokens are consumed at login only. |

**Source reconciliation.** The addendum derived the public `sub` from country plus ID code, which leaks the national ID; this ADR supersedes it and `addendum.md` is corrected.

**Open gates and evidence.** [Q-02](prd.md#constraints-assumptions-and-open-decisions), [Q-03](prd.md#constraints-assumptions-and-open-decisions); Stories 2.4 and 3.4 tests.

## ADR-008: token model and authorize contract

**Status.** Proposed.

**Decision.** Endpoints ([FR-006](prd.md#fr-006-expose-eid-logins-as-a-standard-openid-connect-provider)): authorize (GET and POST), token (POST), userinfo (GET and POST, bearer in the header only), and discovery and JWKS (GET). Authorization code only. Out of initial scope: dynamic registration, refresh tokens, implicit flows, hybrid flows, logout, `request` and `request_uri`, the `claims` parameter and a user database. The rules below are normative.

### Endpoint and token rules

| Area | Rule |
|---|---|
| Client authentication | The source requests `client_secret_basic`, `client_secret_post` and `private_key_jwt`. `private_key_jwt` takes inline static client JWKS only, never `jwks_uri` (NFR-004 egress isolation, SSRF); `aud` must equal the issuer, `iss` and `sub` the `client_id`, `exp` within 60 seconds, `alg` RS256 or ES256, and after signature and claims verify, `jti` insertion-if-absent and the per-client capacity check run atomically under the same lock. Exactly one concurrent use proceeds; replay fails authentication. Entries remain through `exp` plus skew; full capacity returns 503 with `Retry-After` without evicting unexpired entries. Each client has one registered authentication method; a request with credentials of more than one method, or a method other than the registered one, is `invalid_client`; [Q-03](prd.md#constraints-assumptions-and-open-decisions) decides whether it ships in v1. |
| Authorize request | PKCE S256 only (`plain` rejected), `state` and `nonce` required, exact `redirect_uri` match, static clients. |
| Authorization code | Random, held by hash. A locked atomic consume changes live to consumed and publishes its token family before unlocking; never delete an unexpired tombstone. Initial validation failure consumes the code with no family. After success, every subsequent presentation preserves and revokes that family, including invalid credentials or PKCE; it never overwrites the family with a familyless tombstone. |
| Random values | `crypto/rand` only, base64url: at least 256 bits for codes and binding tokens, 32 random bytes for each `rpChallenge`, 128 bits for flow IDs, callback values and token-family IDs. Codes are stored as SHA-256; every secret comparison is constant-time. |
| Replay | The deny-list is a logical view of revoked flags on existing family tombstones, not a separate allocation. Replay atomically marks the existing family revoked even at full capacity. Userinfo requires a present, unexpired, unrevoked family record. No unexpired record is evicted. |
| Access token | Opaque to clients. Layout: format-version byte, explicit sealing-key version, 12-byte nonce, then AES-256-GCM ciphertext and tag (associated data authenticates the fixed label `eidbridge-at-v1`, the format version and the key version) under a versioned `K_at[v]` that lives only in process memory. The sealed payload holds `client_id`, the token family ID, process epoch, monotonic acceptance deadline, `iat`, `exp` and the authorized claims; userinfo rejects nonpositive or excessive lifetime, an unknown epoch, either expired deadline, or a missing or revoked family record. Lifetime is configurable at five minutes or less. There is no server-side claim cache. |
| userinfo | Validate AEAD, process epoch, monotonic deadline, wall expiry and unrevoked family record before returning exactly the authorized claims; `personal_code` only for an allow-listed client. Key-version routing accepts configured in-memory versions only. |
| Assurance | Never treat a method name, a `QUALIFIED` certificate level or the source sketch's `LoA='high'` as legally established assurance. Keep `acr=demo` in demo mode. Publish an evidence-backed production mapping and the selected policy or profile, including who performs certificate status checks ([Q-02](prd.md#constraints-assumptions-and-open-decisions)). When policy is conflicting or unverified, do not assert the higher level; future `amr` and `acr` selection keeps this rule. The ID token lifetime does not exceed the maximum access-token lifetime, and the JWKS retention formula uses it. |
| Configuration | Token lifetime, flow TTL (one name for the flow timeout everywhere, at least the upstream `timeoutMs` plus a margin), retry budget and backoff, clock skew, header and body sizes, and rate thresholds are required at startup, each within stated bounds, and are explicit configuration decisions before [FR-006](prd.md#fr-006-expose-eid-logins-as-a-standard-openid-connect-provider) and [FR-007](prd.md#fr-007-wire-eidbridge-binary-with-login-page-qr-and-web2app-flows) complete; this document fixes no operating values. Provisional bounds below are confirmed under [Q-04](prd.md#constraints-assumptions-and-open-decisions). |

### Configuration bounds

| Setting | Provisional bound |
|---|---|
| `access_token_lifetime` | 1 to 300 seconds |
| `flow_ttl` (flow timeout) | At least the upstream `timeoutMs` plus 30 seconds, at most 300 seconds |
| `retry_budget` | At least 1 attempt, with exponential backoff and a stated total window; `Retry-After` honored on HTTP 429 |
| `grace_period` | 10 to 300 seconds |
| `migration_window_days` | 1 to 90 |
| Clock-skew allowance | 0 to 120 seconds |

### Scope and claims

| Scope | Claims |
|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `acr`, `amr`, `country`, `eid_method`, `eid_env` (demo only) |
| `profile` | `given_name` and `family_name`, only when the verified certificate Subject carries them (the pinned docs do not list them; [Q-01](prd.md#constraints-assumptions-and-open-decisions) confirms) |
| `personal_code` | Only when the client is allow-listed for it |

### Authorization parameters

| Authorize parameter | Behavior |
|---|---|
| `acr_values` | A value the bridge cannot prove fails with `unmet_authentication_requirements`; never silently downgraded |
| `prompt` | `none` returns `login_required` (the bridge keeps no sessions); `login` is accepted; `consent` and `select_account` are ignored; `none` combined with another value is `invalid_request` |
| `max_age` | Always met, because every login is fresh; `auth_time` is always set |
| `claims`, `request`, `request_uri` | Not supported; discovery says so |
| `scope` | `openid` is required, else `invalid_scope`; unknown scopes are ignored; `personal_code` without the allow-list is `invalid_scope` |
| `iss` | Present in every authorization response, success or error (RFC 9207); discovery sets `authorization_response_iss_parameter_supported` |
| Errors before validation | An invalid client or `redirect_uri` renders an error page and never redirects; error redirects happen only after both validate; a repeated parameter is `invalid_request`, `redirect_uri` is required, `response_type` must be `code`, `state` and `nonce` are 1 to 512 unreserved characters and `code_verifier` is 43 to 128 |

### Standards deviations

| RFC 9700 and related item | Decision | Result |
|---|---|---|
| Sender-constrained access tokens (RFC 9700 §2.2.1, §4.10) | Not implemented: tokens are opaque, with `client_id` inside the sealed payload, valid for five minutes or less, and accepted only by the bridge's own userinfo | Deviation |
| Refresh tokens (§2.2.2, §4.14) | None issued | Not applicable |
| JWT access tokens and audience restriction (§2.3, RFC 9068) | Not used; ID tokens only are JWTs (`typ` and algorithm allow-list per RFC 8725 §3.1, §3.11) | Not applicable |
| Exact redirect URI match, no open redirectors (§2.1, §4.1.3, §4.11.2) | Authorize request and error rows above; HTTPS redirect URIs in production; demo alone permits exact statically registered `http://localhost:<port>/<path>` callbacks, with no wildcards, userinfo or fragments; all other HTTP hosts fail | NOT RUN |
| PKCE S256 for every client, downgrade rejected (§2.1.1, §4.8.2) | `code_challenge_methods_supported` is `["S256"]`; a `code_verifier` without a stored challenge is rejected | NOT RUN |
| Single-use codes and revocation on replay (§4.2.4, RFC 6749 §4.1.2) | Authorization code and Replay rows | NOT RUN |
| Issuer identification (RFC 9207) | `iss` row; discovery, ID token and response parameter use one issuer string | NOT RUN |
| Clickjacking, `Referer` leakage, third-party resources (§4.16, §4.2.4) | CSP `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, no third-party resources, no CORS on authorize or login pages | NOT RUN |
| Redirects that may carry form data (§4.12) | HTTP 303 after POST | NOT RUN |
| Tokens in URLs (§4.3.2) | userinfo accepts the `Authorization` header only; token and userinfo responses send `Cache-Control: no-store` | NOT RUN |
| Reverse-proxy header sanitizing (§4.13) | ADR-003 trusted-hop rule | NOT RUN |
| `acr_values`, `state` and `nonce` | Stricter than OIDC Core §3.1.2.1, which treats `acr_values` as voluntary and `nonce` as optional in the code flow | Deviation |

**Source reconciliation.** Sealed access tokens resolve the userinfo claim-source gap: no claim cache survives code exchange.

**Open gates and evidence.** [Q-02](prd.md#constraints-assumptions-and-open-decisions), [Q-03](prd.md#constraints-assumptions-and-open-decisions); Story 2.4 tests.

## ADR-009: capacity and availability

**Status.** Proposed.

**Decision.** The capacity model below and these rules are normative.

| Rule | Behavior |
|---|---|
| Overflow | 503 with `Retry-After`; pending and verified entries are never evicted. Per-IP and per-client token buckets apply inside the global ceiling. The per-client bucket is charged only after the client and `redirect_uri` validate, and a per-IP cap applies to `created` flows. The rate-limit key is the IPv4 address or the IPv6 /64, resolved as the rightmost hop not in the configured `trusted_proxies`. |
| Upstream session | Created when the QR page loads, not at the authorize request, by a compare-and-swap of the flow under its per-flow lock, so concurrent loads create one session; every state transition takes that lock. A `created` flow holds only local memory and expires within the code TTL. The pending-flow cap is the lower of the NFR-003 ceiling and the upstream concurrency; when no poll slot is free the page returns 503 with `Retry-After` and the flow stays `created`. |
| Polling | One server-side poller (a worker pool sharing the semaphore) long-polls the session endpoint (`timeoutMs` 1,000 to 120,000, default 60,500 in the pinned spec) behind a global concurrency semaphore and a rate limit sized from the RP quota (Little's law: concurrency = rate × mean session time). The browser reads only local status and the server-rendered QR. An abandoned flow stops its local poll; the pinned API cannot cancel the upstream session, which expires on its own. |
| Readiness | Configuration and key load only; `healthz` is local liveness. Saturation is a per-request 503, never a readiness failure. Not-ready only during a SIGTERM drain. Upstream diagnostics stay opt-in under [FR-026](prd.md#fr-026-add-an-eidbridge-doctor-command-for-upstream-connectivity-checks) and never make a health probe call the network. |
| SIGTERM | Stop accepting new authorize requests and QR page loads (503), drain until every issued code has expired or the grace period ends, then exit. `grace_period` is a required, bounded setting. During the drain polling and callbacks for new verifications stop, while token and userinfo keep serving; only codes issued before the drain count. Pending flows that cannot finish recover through the restart page. |
| Notification abuse | Normalize country and identifier using authentication validation; HMAC the canonical target under a separate process key, never K_sub. Require positive target-map capacity, burst, refill rate and idle retention of at least burst/refill-rate seconds. Charge existing-target attempts even when denied; retain from the last charge. At full capacity, unseen targets receive 503 with Retry-After and no push. Preserve active buckets; reclaim only expired idle entries. Init and unusable-account errors share a generic message. Account existence remains a disclosed residual risk. |
| Upstream HTTP | Every outbound operation, including device-link and notification initialization, poll, OCSP and CRL, has a request deadline shorter than remaining flow lifetime, a configured response-size cap and no redirects. Status requests use configured allow-listed hosts and a bounded cache. Initialization timeout, oversize or redirect moves created to failed, releases reservations and stops local work; uncertain initialization is not blindly retried. Verification runs outside the poll semaphore. |
| Unknown flow handle | A stable error page and a redirect with `error=access_denied` to the `redirect_uri` recovered from the flow cookie and revalidated against the client registry (ADR-010). |
| Clock | Internal TTLs use process monotonic time. Sealed tokens authenticate their process epoch and monotonic acceptance deadline, computed at issuance from configured lifetime without extending for skew. Userinfo checks that deadline, wall-clock expiry, positive bounded lifetime and the family record; expiration under either clock rejects. Backward wall-clock steps cannot extend acceptance. Restart replaces the in-memory sealing key and epoch, invalidating old tokens. |

### Capacity model

| Quantity | Formula | Value | Notes |
|---|---|---|---|
| Pending-flow cap | At least λ_peak × W_p99 (Little's law), and at most the upstream concurrency | 10,000 default (NFR-003) | λ and W are measured in the spike, not assumed |
| Code store cap | Reservations + live codes + retained family tombstones | Independent required code_store_cap, not the pending-flow cap | Size from measured peak arrival rate times the sum of maximum reservation, code and tombstone residence times, with documented headroom and all index overhead; validate against memory budget under the capacity gate. Admission reserves one slot covering verification, exchange and replay |
| Tombstone cap | Included in code store cap; reservation converts to tombstone | At most code_store_cap, including its family index and revoked flag | Replay needs no extra allocation. Never evict unexpired records. Sustained-exchange tests cover a full retention window; admission overload returns 503 with Retry-After even when upstream is idle |
| Upstream concurrency | R_upstream × S_mean; each pending flow holds at most one long poll | Set from the RP quota recorded under [Q-01](prd.md#constraints-assumptions-and-open-decisions) | The pinned docs state no quota, so there is no default without [Q-01](prd.md#constraints-assumptions-and-open-decisions) |
| Per-IP bucket | Burst and refill rate per IPv4 address or IPv6 /64 | Set from spike measurements | Applies inside the global cap |
| Per-client bucket | Burst and refill rate per `client_id` | Set from spike measurements | Applies inside the global cap |

**Source reconciliation.** NFR-003 and NFR-014 carry these limits and the readiness definition.

**Open gates and evidence.** [Q-01](prd.md#constraints-assumptions-and-open-decisions), [Q-04](prd.md#constraints-assumptions-and-open-decisions); Story 2.5 tests.

## ADR-010: browser binding

**Status.** Proposed.

**Decision.** The rules below are normative.

| Rule | Specification |
|---|---|
| Flow cookie | One per flow, named `__Host-eidb-<flow-id>`, with `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` and no `Domain`. Creation fixes the monotonic absolute deadline as created_at + flow_ttl + 30 seconds; Max-Age is the remaining duration. Server expiry and cookie expiry derive from this deadline; reload and completion rotation never extend it. Earlier terminal response clears the cookie. A created flow that never starts expires after 60 seconds; clear its cookie on the next response. Two tabs use independent bindings. |
| Flow-scoped endpoints | Every page, QR image, status, cancel, continue and callback requires the current constant-time-checked cookie binding. Missing or unrelated bindings get restart without state change or upstream work. Retain only a hash of a rotated binding until cleanup: in-flight requests with that retired binding receive the continue-in-the-other-tab notice, no codes or claims, and cannot poll, cancel or consume callbacks. |
| Cookie value | A fixed-schema base64url struct holding a random binding token, a creation timestamp, and the authorize request's `client_id`, `redirect_uri` and `state` (together capped at 1,024 bytes; longer requests are rejected at authorize); none is secret or personal. After a restart the bridge revalidates `client_id` and `redirect_uri` against the static registry before redirecting, so the cookie cannot create an open redirect. |
| Web2App return | initialCallbackUrl is HTTPS, fragment-free, at most 1,800 characters and has an unpredictable flow-bound value. Under the flow lock validate cookie, value and sessionSecretDigest, consume the value once and rotate to a fresh completion cookie. Retain bounded callback verifier bytes until the signed poll result arrives; then compare their hash with signature.userChallenge and perform full verification. Callback-first sets callback_seen; poll-first sets ok_seen. Only both valid results permit success. Mismatch fails and timeout expires; both destroy secrets. Rotation preserves attributes and the original absolute deadline. Only the callback page polls with the completion cookie and issues the 303 client redirect; old requests follow the retired-binding rule. Replay gets restart; missing-cookie callbacks leave the pending flow unchanged. |
| Flow type | The user picks QR or same-device before the session is created. The choice is stored as `flow.offered` (QR, Web2App or Notification) and `initialCallbackUrl` is empty for QR. |
| Cookie cap | At most four live flow cookies per browser. For a fifth admission reserve new global capacity first; rejection leaves old flows intact. Select the oldest server-recorded flow with a matching binding cookie. Under its lock cancel only if nonterminal, stop local polling, destroy secrets, release unfilled reservations and expire its cookie; upstream expires naturally. Racing completion preserves issued codes and tombstones. Concurrent admissions may briefly exceed four cookies; reconcile excess bound flows on the next request within global quotas. |
| QR | Rendered server-side, sent with `Cache-Control: no-store`, and regenerated every second by a one-second refresh; `sessionSecret` and link computation never reach the browser. QR flows have no callback. |
| Remember-method cookie | Ignored when its method is no longer in the registry. |

**Source reconciliation.** The callback parameters come from the pinned RP API v3 callback page. [Q-01](prd.md#constraints-assumptions-and-open-decisions) confirms them on the demo environment, including whether the scheme rejects callback replay (not stated in the pinned docs).

**Open gates and evidence.** [Q-01](prd.md#constraints-assumptions-and-open-decisions); Stories 2.5 and 4.1 tests.

## Review resolution

Each finding in [the review JSON](research/architecture-review-2026-11-18.json) has one row. `tools/check-arch-trace` fails when a row, anchor, story AC line or gate is missing. A and E findings need a story AC and a named test; S and P findings need a story or a gate.

| ID | Section | Story | Test or gate |
|---|---|---|---|
| A01 | [ADR-002](#adr-002-privacy-and-transient-state-lifecycle) | 2.6 | `TestClaimSetKeyedByCodeHash` |
| A02 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.4 | `TestUserinfoFromSealedAccessToken` |
| A03 | [ADR-007](#adr-007-subject-and-key-management) | 2.4 | `TestSubIsKeyedHMACNotPersonalCode` |
| A04 | [ADR-007](#adr-007-subject-and-key-management) | 2.4 | `TestSubKeyVersionMigration` |
| A05 | [ADR-007](#adr-007-subject-and-key-management) | 3.4 | `TestEmergencyRevocationDropsKeyFromJWKS` |
| A06 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.4 | `TestPrivateKeyJWTRejectsJWKSURI` |
| A07 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.4 | `TestAuthorizeUnprovableACRFails` |
| A08 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestOverflowReturns503WithRetryAfter` |
| A09 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestSinglePollerBoundsUpstreamConcurrency` |
| A10 | [ADR-010](#adr-010-browser-binding) | 2.5 | `TestFlowCookieAttributes` |
| A11 | [Threat and validation model](#threat-and-validation-model) | 2.5 | `TestResponseHeadersAndQRRelay` |
| A12 | [ADR-003](#adr-003-trust-and-production-separation) | 2.7 | `TestProductionRejectsDemoKeyFingerprint` |
| A13 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestReadinessIgnoresSaturation` |
| A14 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestSigtermDrainsUntilCodeTTL` |
| A15 | [Context and boundaries](#context-and-boundaries) | 3.1 | `TestDataFlowDocDiagramEdges` |
| A16 | [Decision index](#decision-index) | 1.2 | `check-arch-trace` |
| A17 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | 4.1 | `TestNoChooserWithSingleMethod` |
| E01 | [Flow state machine](#flow-state-machine) | 2.5 | `TestCreatedFlowTerminatesOnInitFailOrAbandon` |
| E02 | [Flow state machine](#flow-state-machine) | 2.1 | `TestEndResultMappingExhaustive` |
| E03 | [Flow state machine](#flow-state-machine) | 2.5 | `TestPollRetryExhaustionFailsFlow` |
| E04 | [Capacity model](#capacity-model) | 2.5 | `TestStoreFullNeverEvicts` |
| E05 | [Capacity model](#capacity-model) | 2.5 | `TestCodeSlotReservedAtFlowCreation` |
| E06 | [Flow state machine](#flow-state-machine) | 2.5 | `TestLateResultDiscardedAndSecretsZeroed` |
| E07 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.4 | `TestConcurrentCodeExchangeSingleWinner` |
| E08 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.4 | `TestFailedExchangeStillConsumesCode` |
| E09 | [ADR-008](#adr-008-token-model-and-authorize-contract) | 2.6 | `TestCodeReplayDenyListRejectsUserinfo` |
| E10 | [Data lifecycle](#data-lifecycle) | 2.6 | `TestCookiesClearedOnEveryTerminalState` |
| E11 | [ADR-010](#adr-010-browser-binding) | 2.5 | `TestTwoTabsRunIndependentFlows` |
| E12 | [ADR-007](#adr-007-subject-and-key-management) | 3.4 | `TestCompromisedKeyDroppedImmediately` |
| E13 | [ADR-007](#adr-007-subject-and-key-management) | 2.4 | `TestRetiredKeysSurviveRestart` |
| E14 | [ADR-007](#adr-007-subject-and-key-management) | 2.4 | `TestSubKeyOrModeChangeNeedsMigration` |
| E15 | [Flow state machine](#flow-state-machine) | 2.8 | `TestIdentityMismatchFailsWithoutCode` |
| E16 | [Configuration invariants](#configuration-invariants) | 2.7 | `TestModeInvariantMatrix` |
| E17 | [Configuration invariants](#configuration-invariants) | 2.2 | `TestPinDisableRequiresAcknowledgement` |
| E18 | [Configuration invariants](#configuration-invariants) | 2.7 | `TestProxyTrustWarningWhenAllPeersPrivate` |
| E19 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestReadinessIgnoresTransientCapacity` |
| E20 | [ADR-009](#adr-009-capacity-and-availability) | 2.5 | `TestUnknownFlowHandleRedirectsAccessDenied` |
| E21 | [ADR-009](#adr-009-capacity-and-availability) | 2.6 | `TestTTLsUseMonotonicClock` |
| E22 | [ADR-007](#adr-007-subject-and-key-management) | 2.4 | `TestIDTokenAlgPerClient` |
| E23 | [ADR-010](#adr-010-browser-binding) | 4.1 | `TestRememberCookieIgnoredWhenMethodRemoved` |
| S01 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | — | `gate:adj-moved+word-budget` |
| S02 | [Threat and validation model](#threat-and-validation-model) | — | `gate:threat-first` |
| S03 | [Decision index](#decision-index) | — | `gate:decision-index` |
| S04 | [Context and boundaries](#context-and-boundaries) | — | `gate:constraints-list` |
| S05 | [ADR-008](#adr-008-token-model-and-authorize-contract) | — | `gate:adr-schema` |
| S06 | [Decision index](#decision-index) | — | `gate:adr-schema` |
| S07 | [ADR-005](#adr-005-release-evidence-operations-and-deviations) | — | `gate:ops-moved` |
| S08 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | — | `gate:dedupe` |
| S09 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | — | `gate:dedupe` |
| S10 | [ADR-001](#adr-001-validate-risky-access-before-building) | — | `gate:no-process-notes` |
| S11 | [Status and authority](#status-and-authority) | — | `gate:status-caveat` |
| S12 | [Data lifecycle](#data-lifecycle) | — | `gate:lifecycle-table` |
| S13 | [Context and boundaries](#context-and-boundaries) | — | `gate:layout-list` |
| S14 | [ADR-005](#adr-005-release-evidence-operations-and-deviations) | — | `gate:release-template` |
| S15 | [Glossary](#glossary) | — | `gate:glossary+links` |
| S16 | [Context and boundaries](#context-and-boundaries) | — | `gate:diagram-leadin+mermaid` |
| S17 | [ADR-003](#adr-003-trust-and-production-separation) | — | `gate:q02-preserved` |
| P01 | [Status and authority](#status-and-authority) | — | `gate:source-defined` |
| P02 | [Context and boundaries](#context-and-boundaries) | — | `gate:prose-rewrites` |
| P03 | [ADR-007](#adr-007-subject-and-key-management) | — | `gate:prose-rewrites` |
| P04 | [ADR-009](#adr-009-capacity-and-availability) | — | `gate:prose-rewrites` |
| P05 | [ADR-008](#adr-008-token-model-and-authorize-contract) | — | `gate:prose-rewrites` |
| P06 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | — | `gate:prose-rewrites` |
| P07 | [ADR-001](#adr-001-validate-risky-access-before-building) | — | `gate:prose-rewrites` |
| P08 | [ADR-001](#adr-001-validate-risky-access-before-building) | — | `gate:ambiguous` |
| P09 | [ADR-007](#adr-007-subject-and-key-management) | — | `gate:prose-rewrites` |
| P10 | [ADR-002](#adr-002-privacy-and-transient-state-lifecycle) | — | `gate:prose-rewrites` |
| P11 | [ADR-002](#adr-002-privacy-and-transient-state-lifecycle) | — | `gate:prose-rewrites` |
| P12 | [ADR-002](#adr-002-privacy-and-transient-state-lifecycle) | — | `gate:prose-rewrites` |
| P13 | [ADR-003](#adr-003-trust-and-production-separation) | — | `gate:ambiguous+prose-rewrites` |
| P14 | [ADR-004](#adr-004-oidc-boundary-and-dependency-hygiene) | — | `gate:prose-rewrites` |
| P15 | [ADR-004](#adr-004-oidc-boundary-and-dependency-hygiene) | — | `gate:prose-rewrites` |
| P16 | [ADR-005](#adr-005-release-evidence-operations-and-deviations) | — | `gate:prose-rewrites` |
| P17 | [ADR-008](#adr-008-token-model-and-authorize-contract) | — | `gate:ambiguous` |
| P18 | [ADR-006](#adr-006-future-method-gates-and-dependency-repairs) | — | `gate:prose-rewrites` |
| P19 | [ADR-005](#adr-005-release-evidence-operations-and-deviations) | — | `gate:ambiguous` |
| P20 | [ADR-007](#adr-007-subject-and-key-management) | — | `gate:prose-rewrites` |
| P21 | [ADR-004](#adr-004-oidc-boundary-and-dependency-hygiene) | — | `gate:spelling` |
| P22 | [Status and authority](#status-and-authority) | — | `gate:serial-comma` |
| P23 | [ADR-003](#adr-003-trust-and-production-separation) | — | `gate:code-literals` |
| P24 | [Status and authority](#status-and-authority) | — | `gate:status-caveat` |
| P25 | [Context and boundaries](#context-and-boundaries) | — | `gate:prose-rewrites` |

## Glossary

The [PRD glossary](prd.md#glossary) defines the terms bridge, method, flow, device-link, notification, and demo.

| Term | Meaning |
|---|---|
| ADJ | Adjacent wallet candidate ID in [source reconciliation](source-reconciliation.md) |
| AEAD | Authenticated encryption with associated data |
| acr, amr | OIDC authentication context class and authentication methods references |
| ARF | EUDI Architecture and Reference Framework |
| CSC | Cloud Signature Consortium remote-signing API |
| DPIA | Data protection impact assessment |
| HAIP | High Assurance Interoperability Profile for OpenID4VC |
| HMAC | Keyed hash message authentication code |
| JWKS | JSON Web Key Set published by the provider |
| KB-JWT | Key-binding JWT that proves holder possession of an SD-JWT credential |
| LoA | Level of assurance |
| LOTL, TL, LoTE | List of trusted lists, trusted list and list of trusted entities |
| MID | Mobile-ID, the Estonian mobile eID method |
| mdoc | ISO/IEC 18013-5 mobile document credential format |
| OIDF | OpenID Foundation, publisher of the OIDC conformance suites |
| PID | Person identification data credential in the EUDI Wallet |
| PKCE | Proof Key for Code Exchange (RFC 7636) |
| QSCD | Qualified signature creation device |
| QTSP | Qualified trust service provider |
| RoPA | Record of processing activities |
| RP | Relying party: here, eidbridge toward the scheme, and the OIDC client toward eidbridge |
| SD-JWT | Selective-disclosure JSON Web Token credential format |
| SPKI | Subject public key info, the object hashed for TLS pins |
| SSRF | Server-side request forgery |
| FR, NFR, Q | Functional requirement, non-functional requirement and open question IDs in the [PRD](prd.md) |
