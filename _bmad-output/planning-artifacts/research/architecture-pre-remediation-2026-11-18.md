---
title: eidbridge architecture and decision baseline
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# Architecture and decision baseline

## Status and authority

This is an architecture proposal derived from issues and source research, not an implementation survey. No application starter is installed or selected. Go single binary, standard-library-first dependencies and dual MIT/Apache-2.0 licensing are source constraints; choose exact runtime/library versions at implementation after reading their current documentation. Original detailed API sketches remain in [addendum](addendum.md). PRD Q-01–Q-05 remain implementation gates. Do not invent a framework starter or copy a competitor app.

## Context and boundaries

~~~mermaid
flowchart LR
  U[User browser and eID app] --> I[Integrator app or IdP]
  I --> O[eidbridge OIDC provider]
  O --> A[Verified identity method interface]
  A --> S[Smart-ID v3 RP API]
  O --> M[Bounded memory flow and code store]
  K[Operator keys and trust config] --> O
  K --> A
~~~

The OIDC client owns account provisioning/linking and long-lived user sessions. The bridge is an RP toward the scheme, not a scheme-certified identity provider. Code/config receive production RP credentials from the operator. No payment/billing/resale route, hosted deployment or project-author data collection is part of this design.

Proposed layout: cmd/eidbridge; internal/smartid; internal/authn and authntest; internal/oidc; internal/web; internal/config; internal/logx; internal/store; internal/tlspin; trust; examples; docs/spec-pins; test/e2e. These paths are implementation targets, not present source files. Registry of methods is internal until multiple implementations justify stabilizing it. OIDC and web receive a registry/contract, not a direct import of each backend. Browser-only middleware invokes protocol methods through server-owned flow handles.

## Public surface and identity contract

FR-006: GET discovery and JWKS, GET authorize, POST token, GET userinfo. Authorization code only, PKCE S256, state/nonce, exact redirects, static registered clients. Source requests client_secret_basic, client_secret_post and private_key_jwt; choose/library-test the actual supported set and disclose any deviation. No dynamic registration, refresh tokens, implicit/hybrid flow, logout or user database in initial scope.

Method states: created → pending → verified/refused/expired/failed. Identity exists only after cryptographic verification; status COMPLETE alone is not trusted. Polling honors cancellation, bounded retries and upstream limits. Account identity must match the requested identity in notification mode. Secrets and certificate material never pass to templates/loggers/metrics. Client-specific identity claims are allow-listed; personal_code is opt-in, not default. Public subject exposes linkability; pairwise mode must use a secret-backed stable construction, client/sector separation and documented salt/key backup/rotation. A raw hash of a guessable personal code is insufficient protection. Pairwise default is a proposed privacy choice to confirm, not an approved source default.

RS256 is source baseline (ES256 optional). Operator keys persist across restart, old public keys remain in JWKS through issued token expiry and clock-skew allowance. Private-key rotation/compromise recovery must be exercised. Token lifetime, clock skew, HTTP/request sizes and rate thresholds are explicit configuration decisions before FR-006/007 completion, not fabricated values. Healthz is local liveness; readiness describes local config/capacity. Upstream readiness diagnostics are opt-in/deferred under FR-026 and cannot make every health probe perform a network request.

Assurance: never equate a method name, QUALIFIED certificate-level string or source sketch LoA='high' to legally established assurance automatically. Keep acr=demo in demo, publish evidence-backed production mapping and the selected policy/profile with status-check responsibilities (Q-02). Conflicting/unverified policy means do not assert the higher level. Future amr/acr method selection must preserve this rule.

## ADR-001: validate risky access before building

Status: proposed execution gate. Implement the six-hour synthetic/demo spike after minimal scaffold and safe logging. Record protocol/profile, device-link behavior, signature/chain results, demo registration requirements and scriptable-test availability. Use no production identities and redact console output; retain demo fixture material only under testdata.

Original spike says print subject fields and offers Mobile-ID then Web eID fallbacks. Preserve that source but apply privacy guards from the start. Notification may be measured as fallback without changing the product wedge. A blocked public demo or contract/payment requirement is a stop/replan finding. MID/Web eID are not automatic low-cost substitutes; Web eID alone is estimated 80–100 hours and needs hardware/security review. No fictional successful spike ADR is written by this planning task.

## ADR-002: privacy and transient state lifecycle

Status: retained default; lifecycle resolution proposed. Personal flow data stays in memory, capacity bounded (source default 10,000). Unfinished upstream flows expire at timeout+30s. Authorization codes have a separate maximum 60s TTL and one-time use. On verified upstream success, destroy challenge/certificate/session secrets once verification is complete; retain only the minimal encrypted-in-transit claim set needed for one code exchange. Remove pending-flow entries on failure/refusal/expiry and claim/code data at exchange or code expiry. Clear bridge cookies at completion. Replay tests ensure terminal states cannot reappear.

This reconciles #10's 'delete on completion' with #13's 'until code exchange': authentication success is not completion of OIDC delivery. Access tokens for userinfo need an explicit bounded lifecycle: proposal is short-lived signed JWTs with only client-authorized claims, no raw personal code embedded in bearer tokens unless explicitly necessary/allow-listed. Reconcile token revocation and userinfo scope before implementation; do not promise that deleting bridge state retracts tokens already held by clients. Explicit expiry and access control must cover every result endpoint.

Signing keys/trust files/config and synthetic fixtures are not retention of user flow history. Production signing key must not be silently regenerated; demo named volume stores only that key, never identity/session data. No database/shared store in v1. Single-replica/process restart loses pending flows; retry fresh and document this instead of claiming HA. Sticky sessions are at most future deployment advice, not a shared-state implementation. Access logs default to no identity-bearing URL/query/body and document IP/user-agent handling; reverse-proxy logs are also operator responsibility.

No telemetry/update/crash beacons. Route outbound traffic through configured endpoint clients; egress-isolated tests prove no unrelated traffic. DNS/trust-status checks must be explicit in the selected profile and documented egress policy. Pull-only count/expiry metrics remain optional and deferred with FR-026. A source logger warning that DEBUG may contain PII does not permit raw identifiers; typed no-PII logging first, sink masking as backstop at all levels.

## ADR-003: trust and production separation

Status: retained source guardrail. TLS server identity uses normal chain/hostname verification plus configurable SPKI SHA256 current/next pins, TLS 1.2 minimum, no re-enabled legacy suites. Separate TLS server trust from authentication-signature CA roots. Demo and production endpoints/pins/CA groups must not mix. A configurable endpoint must not become an arbitrary browser/user-controlled SSRF target. Validate production HTTPS issuer and explicitly configured trusted reverse-proxy hops; ignore spoofed Forwarded/X-Forwarded headers by default.

Preserve #8's explicit TLS_PINS=disabled escape hatch, with a prominent warning and published deviation; it disables only the additional pin check, not CA/hostname verification. It does not make a passing hardened deployment claim. Production rejects demo UUID, known demo host, demo/mock CA and test keys even if another mode flag says production. Demo tokens carry acr=demo and eid_env=demo, and every production integration recipe rejects them. Default demo warning/banner repeats per source, without personal data.

Certificate verification follows pinned protocol rules: challenge binding, allow-listed algorithms, signature, root chain, validity, usage, certificate level and identity match. Issue #8 excludes Smart-ID OCSP/AIA work from its own scope; that does not prove status validation unnecessary in the operative protocol or RP agreement. Q-02 must resolve status responsibilities before claiming production sufficiency. Web eID separately requires origin/nonce and revocation handling.

## ADR-004: OIDC boundary and dependency hygiene

Status: proposed implementation choice. Prefer an appropriate maintained provider library over handwritten JWT/protocol mechanics, but do not invent a selection. Evaluate licence, dependency footprint, PKCE/client-auth support, key rotation, scope behavior and suite compatibility. Existing Go clients in oss_inventory are dated candidates, not proof that their v3 device-link support is adequate. Official permissive code can be reused with notice; no LGPL demo or unlicensed documentation copying. Spec pins store URLs/version/hash/license metadata, not harvested third-party text. Do not add an IdP Java SPI or second OIDC provider merely because adjacent wallet research suggests one.

## ADR-005: release evidence, operations and deviations

Status: accepted planning criterion, not executed release. Extend FR-001/013/017 with portable source-built artifacts, pinned inputs, checksums/SBOM, provenance/signature-verification instructions and a smoke test against the actual published artifact. Claim reproducibility only with independent rebuild evidence; otherwise disclose build variance. Do not inherit Rust/glibc/CPU constraints from adjacent wallet code.

Maintain per-release table: requirement/profile version; implemented/deviation/not-run; test/evidence path and commit; scope/risk; owner and next action. The OIDF Basic OP plan requested in #6 must be run, results recorded, and unsupported plan features explicitly reconciled. A valid discovery JSON or third-party token validation alone is not full conformance/certification. Failure cannot be hidden by labelling omitted source AC done.

Operator docs require field/purpose/source/location/lifetime/emission/logging table; code-to-doc claim-name check; Mermaid sequence; configurable claims/sub/access-log effects; deployer-completed DPIA/RoPA aids. Do not issue a completed legal assessment or universal role determination. Project authors have no intended data path; actual hosting/support can change roles. Operators evaluate agreements, sector duties and data protection obligations.

Production checklist: own RP agreement/identity, HTTPS/issuer/proxy trust, secret mounts/non-root/read-only runtime, correct trust groups, fresh keys, strict client redirects/claims, demo-negative tests, configured request/rate bounds, incident contacts and successful recovery drill. Incident reason-code matrix covers user refusal vs abuse vs upstream outage vs stale pin/CA vs key compromise; detect/contain/drain/rotate/recover/notify steps and evidence. Legal notification timing/applicability is reviewed by the operator, not prescribed from unverified source PDFs.

Nightly upstream-compatibility/auto-issue workflow appears in FR-017. This task records its acceptance requirement; it does not enable a cron, send messages or deploy an autonomous monitor. Implement/authorize separately with deduplication, bounded retries and sanitized reports. Support source policy: latest minor fixes; pin/CA fixes backported one minor if maintained. No paid SLA is inferred.

## ADR-006: future method gates and dependency repairs

Status: deferred. FR-020 chooser is built/tested with a fake second method after FR-005, then FR-019 Mobile-ID can depend on it. This removes the source prose loop 'chooser waits for second method' while MID depends on chooser. Activate the pair only when real MID demand exists; do not build dead chooser UI in the one-method release. Remember-method cookie remains opt-in, short-lived/non-identifying and needs updated data-flow/cookie docs.

Web eID FR-021: separate token validator, origin-bound one-use nonce, chain/usage/policy and correct status/responder validation; test hardware, parser fuzzing, public-library licence choice and external security review before release. Split its 80–100h work into reviewable stories before sprint commitment; no 'cheap fallback' assumption.

Wallet FR-022/023: exact OpenID4VP/HAIP/ARF and credential-format versions, available test wallet and actual RP demand are prerequisites. Compare native IdP support first. SD-JWT/KB-JWT and mdoc require issuer/holder/audience/nonce/transcript binding, disclosure/status verification and request ceilings; no cross-project green tests count here. Conformance harness after verified wallet method, core positive plus at least ten negative cases, pinned spec references and JUnit, no certification claim.

## Deferred adjacent wallet requirements and handoffs

These are extracted design candidates with explicit source homes, not new initial release promises. ADJ IDs refer to [source reconciliation](source-reconciliation.md).

| Candidate | Required behavior/evidence before activation | Dependencies and ownership |
|---|---|---|
| ADJ-01 signed verifier requests | Request-object typ/signature, access cert x5c, computed x509_hash, cert/key and SAN/response-host consistency; unsigned testing only explicit opt-in; strict-wallet negative/interop tests | FR-022; profile/security maintainer; source is eudi-wallet-poc proposal |
| ADJ-06 registration/export | Per-RP versioned registration/intended-use/request ceiling, deterministic registrar export and runtime-ceiling comparison; unverified national formats labelled; no live submission | FR-022; operator/legal applicability review |
| ADJ-14 PID formats | SD-JWT disclosures/KB-JWT and mdoc plain presentation verified for issuer, holder, status, audience, nonce and transcript; memory-only values and fail-closed negatives | FR-022; decide reuse vs cross-project adapter explicitly, no code copied implicitly |
| ADJ-15 trust refresh | Profile-appropriate signed LOTL/TL/LoTE where applicable, service/status filters, atomic signed update, freshness/rollback tests; separate static/imported trust | FR-022; LOTL is not assumed universal wallet trust |
| ADJ-12 multi-RP | Separate RP identity/certs/keys/registered ceilings, authenticated init/result, cross-tenant negative tests/rate limits; single-tenant default | Concrete multi-RP need and FR-022, no billing/onboarding UI |
| ADJ-11 predicate guide | Minimal age proof, same-device/QR, bounded polling and server-only results; not-proven is unknown, not underage; no stable identity inferred | Compatible attestation and demand; stable OIDC account semantics require separate decision |
| ADJ-13 OIDC adapter | One existing issuer, code/PKCE, nonce binding, scope-to-minimal-claims and key rotation; privacy-preserving subject policy, no refresh/PID release without verified support | FR-006/022; avoid duplicate server |
| ADJ-16 PKCS11 | Optional file/non-exportable key backend, SoftHSM and rotation tests; default static build stays free of CGO dependency | Concrete deployment requirement; key custodian/operator owns hardware |
| ADJ-05 metadata audit | Off by default, explicit field allow-list, no tokens/attributes/nonces/keys, configured lifetime/export/access; treat even pseudonymous timestamps/client/decision identifiers as linkable | Separate privacy ADR; hash chain detects edits, cannot prove truncation without external anchor |
| ADJ-18 external remote signing | Bind wallet-approved transaction hash to external CSC v2/QTSP signHash, refuse mismatch; qualified provider retains certificate/QSCD responsibility | Compatible sandbox, demand, legal/security review; separate from FR-028 digest relay |

ADJ-17 WooCommerce age checkout is a cross-project use case, not FR-030 WordPress login and not an eidbridge feature commitment. Nextcloud/Drupal/n8n also remain unrequested adjacent options. Qualified issuance, seals, wallet certification, remote QSCD custody, credential brokerage and hosting are outside this product. No claim is made that ordinary digest relay is categorically illegal without this project's own QTSP status; source rankings overstate that point. Signing remains deferred on scope, security, demand and legal-review grounds.

## Threat and validation model

| Threat | Control | Evidence required |
|---|---|---|
| Fake upstream success/identity substitution | Protocol signature/challenge/identity/chain/level checks | Offline mutation vectors and Verify coverage |
| Flow takeover/code replay/open redirect | Unguessable server-owned state, cookie/nonce/client/redirect/PKCE binding, one-use TTL | Browser/session swap, late callback, replay and redirect negatives |
| Push spam/enumeration/resource exhaustion | Opt-in notification, local input validation, per-IP/client limits and bounded store/polling | No-egress invalid inputs, rate/capacity tests |
| Demo identity in production | Startup configuration invariants and demo token rejection in clients | Mixed-environment matrix and production realm negatives |
| PII/secret leak | Typed logging plus non-disableable sink redaction; no default persistence/telemetry | DEBUG fixture log capture, filesystem/egress isolation, lifecycle assertions |
| Upstream trust drift | Separate rotating pins/CA groups, explicit status policy and runbook | Rotation, stale trust, expiry and recovery drill |
| False compliance/confidence | Scope/limits and versioned deviations | Release checklist separates pass/fail/not-run; no unsupported claims |

Apply actual implementation-specific security review before a production release. Planning/source coverage is not cryptographic review or evidence that any product test passes.
