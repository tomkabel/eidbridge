# Security

Unofficial, pre-release software. **No external security review has been done**; one is required before production use (architecture "Status and authority"). Report vulnerabilities privately: [SECURITY.md](../SECURITY.md). Personal-data handling: [data flow](data-flow.md).

## Threat model summary

| Threat | Control in the code | Evidence |
|---|---|---|
| Fake upstream success or identity substitution | Every response-verification step of the pinned RP API (callback digest, state and endResult, protocol, user challenge, chain to configured CAs only, policy OIDs, purpose, level, identity match, RSASSA-PSS signature over the rebuilt payload, offered flow type), then OCSP/CRL; unknown status fails | `internal/smartid` negative tests per step, live demo replay, mutation testing |
| Flow takeover, code replay, open redirect | Per-flow `__Host-` cookie with constant-time binding; one-use 60 s codes held as SHA-256; failed exchanges consume the code; replay revokes the token family; exact redirect URI match; error page before redirect validation | `internal/web`, `internal/oidc`, `internal/store` tests; red-team report |
| Push spam, enumeration, exhaustion | Notification is opt-in; local checksum validation before any request; per-IP, per-client and per-target buckets; bounded flow and code stores; 503 with `Retry-After`, never eviction | Capacity and bucket tests |
| QR relay phishing | QR regenerated per request (elapsed seconds), refreshed every second; same-device callbacks need the original browser cookie | Disclosed residual risk: a relayed QR can still be scanned |
| UI injection and framing | Strict CSP without inline script or style, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, template autoescaping, no third-party resources | Header tests on every page |
| Mix-up | RFC 9207 `iss` in every authorization response | Authorize tests |
| Token theft | Opaque AES-256-GCM sealed access tokens, ≤ 5 minutes, bound to process epoch and monotonic deadline; userinfo header-only | Seal and lifetime tests |
| Demo identities in production | Mode required; production refuses demo hosts, RP identity, CAs, keys and the demo client secret; demo tokens carry `acr=demo`, `eid_env=demo`, `/demo` issuer, `demo-` kid | Configuration invariant tests |
| Personal data in logs | Typed logging plus sink redaction that cannot be disabled | DEBUG log capture of full logins |

Residual risks: account existence is observable in notification mode; cross-device QR relay; Go's garbage collector may keep copies of secrets briefly (secrets are held as byte slices and cleared, best effort); restart loses pending flows.

## What is logged at each level

Logs are JSON. Every record passes the redacting handler in `internal/logx`, which masks identity codes, document numbers, phone numbers, PEM blocks, long base64 values (certificates, signatures, tokens, codes) and values under sensitive keys. Structs, maps and byte slices are never rendered. **DEBUG gets exactly the same redaction**; there is no setting to turn it off.

| Level | Events |
|---|---|
| ERROR | Startup refusal reasons, template failures |
| WARN | Demo-mode notice (start and every 10 minutes), disabled pins, disabled certificate status (demo only), deviation records, missing `trusted_proxies` behind private peers (once) |
| INFO | Start (version, mode, issuer, methods), flow finished (state, reason code, method), access log (method and route template, status, duration), drain start and stop |
| DEBUG | Flow started (method, flow type, language), each upstream poll (done, waiting, reason detail) |

Never logged at any level: personal codes, names, phone numbers, certificates, signatures, challenges, session secrets, callback values, flow IDs, authorization codes, tokens, client secrets, client IP addresses, raw paths or query strings.

## TLS pins and trust anchors

Two separate trust inputs:

1. **TLS to the RP API**: the system CA store and hostname verification always apply (TLS 1.2 minimum). On top, `EIDBRIDGE_SMARTID_TLS_PINS` lists SPKI SHA-256 pins (current and next). Any certificate of a verified chain may match.
2. **Authentication certificates**: only the CAs in `EIDBRIDGE_SMARTID_AUTH_CA_DIR` are trusted; the system store is never used. Demo and production CA sets never mix.

### Update pins after an RP API certificate renewal

1. From a network without TLS interception, compute the new pin: `scripts/pin-check.sh production` prints the observed pin on mismatch, or run `openssl s_client -connect rp-api.smart-id.com:443 -servername rp-api.smart-id.com </dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
2. Verify the new certificate chain and validity yourself; compare with the scheme operator's announcement.
3. Set `EIDBRIDGE_SMARTID_TLS_PINS=sha256/<current>,sha256/<new>` and restart. Both are accepted, so you can stage the change before the renewal.
4. After the renewal, drop the old pin.
5. `eidbridge trust show` prints the active pins and CA subjects.

`EIDBRIDGE_SMARTID_TLS_PINS=disabled` skips only the pin check. In production it also needs `EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK=I_UNDERSTAND`, logs a warning and a deviation record, and the deployment cannot claim to be hardened.

### Update authentication CA bundles

1. Download the new CA certificate from the scheme operator's repository and check its fingerprint against a second channel.
2. Add the PEM file to the CA directory; keep the old CA until certificates it issued have expired.
3. Restart and check `eidbridge trust show`. Production refuses to start if a demo CA is in the directory.

## Keys

- Signing keys persist in `EIDBRIDGE_KEY_DIR` (`keys.json` manifest, files at mode 0600). RSA keys are at least 2,048 bits (3,072 generated), ES256 uses P-256, production `kid` is the JWK thumbprint, demo `kid` is `demo-` plus the thumbprint.
- Planned rotation: `eidbridge keys rotate RS256`, restart. The retired key stays in JWKS until the longest token lifetime plus skew, also across restarts.
- Emergency revocation: `eidbridge keys revoke <kid>`, restart immediately. The key leaves JWKS at once; the restart replaces the in-memory sealing key, so all access tokens die and clients must re-authenticate. Clients with a cached JWKS may accept the old key until they refresh.
- `K_sub` (subject key) is versioned in `EIDBRIDGE_SUB_KEY_FILE` and never rotated in place. A rotation is a migration (`EIDBRIDGE_SUB_MIGRATION`, `previous_sub`). Losing it changes every user's `sub`.
- The full procedures and the drill are in the [maintenance runbook](api-tracking.md).

## Deployment hardening

- Run behind a TLS-terminating reverse proxy, or serve TLS directly with `EIDBRIDGE_TLS_CERT_FILE`/`EIDBRIDGE_TLS_KEY_FILE`.
- Configure `EIDBRIDGE_TRUSTED_PROXIES`; without it forwarding headers are ignored and per-IP limits see the proxy.
- Keep query strings out of proxy access logs (they carry codes and callback values).
- Container: non-root user 65532, read-only root filesystem, only the key directory writable, secrets mounted as files.
- Core dumps are disabled by the binary; disable swap or use `mlock`-capable hosts where possible.
- Single replica: a restart loses pending flows (users start again) and invalidates access tokens. There is no shared store and no high-availability claim.
- Readiness (`/readyz`) covers configuration and key load only; saturation returns per-request 503. On SIGTERM readiness fails, new logins stop, and the process drains until issued codes expire or `EIDBRIDGE_GRACE_PERIOD` ends.

## Retention

Zero persistent personal data by default. Signing keys, trust files, configuration and the subject lock file (`subject-config.json`, client settings only) are operator state. See the [data flow](data-flow.md) lifetimes.
