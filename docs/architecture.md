# eidbridge implementation architecture

This page describes the code as built. The planning baseline with all decisions is [architecture.md in the planning set](../_bmad-output/planning-artifacts/architecture.md); implementation-time decisions are ADRs in [docs/adr](adr/).

## Packages

| Package | Role |
|---|---|
| `cmd/eidbridge` | Binary: configuration, method registry, OIDC provider, web server, `doctor`, `trust show` |
| `cmd/sidspike` | Story 1.4 spike against the public demo |
| `internal/authn` | Method-neutral contract (below) and registry |
| `internal/authn/authntest` | Contract suite every method passes; fake method |
| `internal/smartid` | Smart-ID RP API v3 client, verification and `authn.Method` adapter |
| `internal/smartid/smartidtest` | Synthetic PKI and fixture upstream (tests, demo fixture mode, `eidmock`) |
| `internal/tlspin` | Outbound TLS: CA and hostname checks plus SPKI pins |
| `internal/revocation` | OCSP with CRL fallback, allow-listed hosts only |
| `internal/logx` | Redacting log handler, the only logger |

Later methods (`internal/mobileid`, `internal/webeid`, `internal/eudi`, `internal/smartid/v2`) plug into the same contract. OIDC and web code import `internal/authn`, never a method package; a test enforces this.

## The `authn` contract

> **Versioning note.** `internal/authn` is internal and may change before v1.0. It is not a public Go API or plugin ABI.

- `Method` has a `Name`, the `Flows` it offers (`qr`, `same-device`, `notification`, `browser`), a `Demo` flag and `Start(ctx, StartRequest) (Pending, error)`.
- `Pending` exposes `UI(now)` (QR payload, app link, verification code or browser challenge; never secrets), `Poll(ctx)` (one bounded server-side upstream poll), `Callback(ctx, query, body)` (browser return: Smart-ID Web2App callback, Web eID token, wallet response) and `Destroy()`.
- A `Result` is `Done` with either a verified `Identity` or a typed `Error` carrying a reason code from the flow state machine (`refused`, `expired`, `wrong_code`, `account_unusable`, `upstream_error`, `verification_failed`, `identity_mismatch`, `unknown_end_result`, `status_unavailable`, `retries_exhausted`, `invalid_input`, `cancelled`). Retryable upstream errors are not done; the caller applies the retry budget.
- `Identity` carries method, `amr`, identifier type, country, code, verified names, the method's own level label (evidence, not legal assurance) and allow-listed extra attributes.
- A method that has produced a success never returns a second identity. Late results for destroyed or terminal pendings are discarded.

`authntest.Run(t, harness)` checks start, success, refusal, timeout, verification failure and the no-success-after-destroy rule for every flow a method offers.
