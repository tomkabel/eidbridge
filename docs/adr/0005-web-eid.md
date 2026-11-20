# ADR 0005: ID-card login through Web eID

- Status: accepted (owner override 2026-11-20 activates Story 5.1 without its demand, hardware and external-review gates)
- Date: 2026-11-20
- Stories: 5.1 (children 5.1-a to 5.1-e); FR-021

## Specification pin

- Web eID system architecture document, https://github.com/web-eid/web-eid-system-architecture-doc, `README.md` sha256 `e1d66c7b95e83059773712d52060f803e40bfeacceae29f021b6250a9d252b45`, fetched 2026-11-20: sections "Authentication" and "Web eID authentication token specification" (formats `web-eid:1.0` and `web-eid:1.1`).
- Browser extension message protocol: as used by web-eid.js 2.1.0 (MIT, commit `7dca6ee07979b8b2bb75a18553fd23c378698018`, read 2026-11-20). The bridge does not vendor the library; `internal/web/static/webeid.js` is a small reimplementation of the `web-eid:authenticate` exchange (request, ack, success, failure).

## Decisions

- `internal/webeid` validates tokens and is a third `authn.Method` (`browser` flow) behind the one issuer.
- The origin signed over is derived only from the configured https public origin (ASCII serialization). The method is offered only when the issuer is https; configuration refuses `webeid` with an http issuer.
- Nonce: 32 random bytes, Base64 (44 characters), one per flow, consumed by the first token whether valid or not, expires after 5 minutes. The flow cookie and form token bind it to one browser (CSRF protection required by the specification).
- Validation order: validity period, client-authentication EKU and digitalSignature, disallowed policies (default: Mobile-ID and Smart-ID policies), chain to configured CAs (1.1 intermediates are untrusted candidates, at most four), signature over `hash(origin)+hash(nonce)` with the token algorithm (ES key curve must match; ECDSA as JWS raw `r||s`; RSA ≥ 2048 bits), subject identity, OCSP/CRL status with unknown failing closed.
- `unverifiedSigningCertificates` in 1.1 tokens are ignored: the bridge does not sign.
- Errors the extension reports (`ERR_WEBEID_USER_CANCELLED`, `ERR_WEBEID_USER_TIMEOUT`, others) end the flow as refused, expired or upstream error; they never carry an identity.
- Demo trust: TEST of ESTEID2018 and TEST of EE-GovCA2018 (SK test ID-cards). `EIDBRIDGE_WEBEID_ENV=mock` trusts a synthetic card CA for tests and the demo stack.

## Evidence and gaps

- Offline: Story 5.1 vectors and per-step negatives, mock OCSP responder, fuzzed parser, contract suite, bridge integration test, Chrome run of `webeid.js` with a stand-in extension (no extension, user cancel).
- NOT RUN: manual login with a test ID-card and the real Web eID extension (child 5.1-e, needs hardware), external security review (original gate). OCSP against SK's demo responder for test cards was not exercised without a card.
