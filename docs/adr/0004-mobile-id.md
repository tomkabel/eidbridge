# ADR 0004: Mobile-ID through the MID REST API

- Status: accepted (owner override 2026-11-20 activates Story 4.2 without the original demand gate)
- Date: 2026-11-20
- Stories: 4.1, 4.2; FR-019, FR-020

## Specification pin

- MID REST API: https://github.com/SK-EID/MID, `README.md` sha256 `27ea055d9c60c7e183726755434662c3ec6a2d4834f3237cffe820c4a49cb58a`, fetched 2026-11-20.
- Demo test numbers: MID wiki page "Test number for automated testing in DEMO", sha256 `956ca9137a7e3fb99740b84583aa8dd99ae3bf010c023b57ba5c0912cbf19790`, fetched 2026-11-20.
- No code was taken from SK's Java or PHP clients or demo applications; only the README's request and response descriptions.

## Decisions

- `internal/mobileid` is a second `authn.Method` behind the one issuer and login page. It reuses the Smart-ID package's `TrustStore`, `LoadCADir`, `StatusChecker` and `ParsePersonalCode`/`ValidPersonalCode` helpers, because both are SK PKI. No OIDC code lives there.
- Flow: `notification` only. The user types a phone number and personal code; the bridge validates both locally (E.164 `+372` or `+370`, personal-code checksum for the country of the phone prefix) and charges the per-target rate limit before any request.
- Hash: a fresh random SHA-256 value per session. The page shows the §2.4.1 verification code.
- Verification order, failing closed: result `OK`; signature and certificate present; algorithm prefix equals the requested hash and suffix matches the key type (EC raw `r||s` or ASN.1, RSA ≥ 2048 bits PKCS #1 v1.5); chain to configured CAs; leaf not a CA; policy `1.3.6.1.4.1.10015.18.1`; `digitalSignature` set and `nonRepudiation` clear; subject `PNO` identity equals the requested country and code; signature over the submitted hash; OCSP/CRL status.
- Demo trust: TEST of SK ID Solutions ROOT G1E and EID-Q 2021E. Demo numbers on the older "TEST of EID-SK 2016" chain are not trusted.
- Configuration mirrors Smart-ID with `EIDBRIDGE_MOBILEID_*` variables, read only when `mobileid` is enabled, with the same demo/production invariants (hosts, RP identity, CA fingerprints, status hosts, pins).

## Observed (live, 2026-11-20)

- `tsp.demo.sk.ee/mid-api` accepted anonymous requests with the public demo relying party. OK, USER_CANCELLED, NOT_MID_CLIENT, DELIVERY_ERROR and SIGNATURE_HASH_MISMATCH were captured into `internal/mobileid/testdata/live/` and replay as known-answer tests. A full bridge login (`TestLiveDemoBridgeMobileID`) passed.
- The demo EC certificate signs with `SHA256WithECEncryption`; the value is 64 bytes (raw `r||s`).
- The demo OCSP responder `aia.demo.sk.ee/eidq2021e` answers revoked, reason certificateHold, revocation time 1970-01-01 for the demo certificate: the RFC 6960 non-issued convention also seen for Smart-ID (ADR 0001). Demo mode therefore runs with `EIDBRIDGE_MOBILEID_CERT_STATUS=none`; `TestLiveDemoOCSPNonIssued` records the behaviour.

## Not done (gates disclosed)

- No production MID contract or production run; pins are NOT RUN (the build sandbox intercepts TLS). No external security review of the method.
