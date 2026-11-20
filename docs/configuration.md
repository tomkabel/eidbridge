# Configuration

Generated from `internal/config` (`go run ./cmd/eidbridge config docs`); CI fails when this file and the code differ.

Mode has no default. Demo mode uses the demo defaults below; production requires every variable marked required to be set explicitly. Startup fails on any invariant violation (architecture ADR-003 configuration invariants).

| Variable | Demo default | Required in production | Bounds | Description |
|---|---|---|---|---|
| `EIDBRIDGE_MODE` | — | no | demo or production | Required, no default. `--demo` sets demo. |
| `EIDBRIDGE_LISTEN` | `:8080` | no |  | Listen address. |
| `EIDBRIDGE_ISSUER` | `http://localhost:8080` | yes | production: https; demo: https or http://localhost | Public base URL. Demo appends `/demo` to form the issuer. |
| `EIDBRIDGE_METHODS` | `smartid` | no | smartid, mobileid, webeid, eudi, smartid-v2 | Enabled methods, comma-separated, in chooser order. |
| `EIDBRIDGE_CLIENTS_FILE` | — | yes |  | JSON file with static OIDC clients. Demo without it registers the sample client `demo-rp`. |
| `EIDBRIDGE_DEMO_CLIENT_SECRET` | `demo-client-secret-not-for-production-use` | no | demo only | Secret of the built-in demo client. |
| `EIDBRIDGE_DEMO_REDIRECT_URIS` | `http://localhost:8081/callback` | no | demo only | Redirect URIs of the built-in demo client. |
| `EIDBRIDGE_KEY_DIR` | `./data/demo-keys` | yes | mode 0700, key files 0600 | Signing-key directory (keys.json manifest). Demo generates a `demo-` key when empty. |
| `EIDBRIDGE_SUB_KEY_FILE` | — | yes | 32-byte keys | JSON `{"current":N,"keys":{"N":"<base64>"}}` with versioned K_sub. Demo uses a random in-memory key. |
| `EIDBRIDGE_SUB_MIGRATION` | — | no | days 1–90 | JSON migration declaration `{"from":1,"to":2,"started":"2026-11-20T00:00:00Z","days":30,"clients":{"id":"c:id"}}`. |
| `EIDBRIDGE_DEMO_KEY_DENYLIST` | — | no | hex SHA-256 SPKI fingerprints | Comma-separated key fingerprints production must refuse. |
| `EIDBRIDGE_METHOD_ACR` | — | no | JSON map | Operator-backed acr per method, e.g. `{"smartid":"urn:example:loa:high"}` (ADR 0003). |
| `EIDBRIDGE_FLOW_TTL` | `120s` | yes | ≥ long poll + 30 s, ≤ 300 s | Flow timeout; the absolute flow deadline adds 30 s. |
| `EIDBRIDGE_ACCESS_TOKEN_LIFETIME` | `300s` | yes | 1–300 s | Sealed access-token lifetime; ID tokens use the same. |
| `EIDBRIDGE_CLOCK_SKEW` | `30s` | yes | 0–120 s | Allowed clock skew for client assertions. |
| `EIDBRIDGE_RETRY_BUDGET` | `3` | yes | 1–10 | Upstream poll retries for transient errors. |
| `EIDBRIDGE_RETRY_BASE` | `500ms` | yes | 50 ms–10 s | First retry backoff (doubles). |
| `EIDBRIDGE_GRACE_PERIOD` | `60s` | yes | 10–300 s | SIGTERM drain limit. |
| `EIDBRIDGE_MAX_FLOWS` | `10000` | yes | 1–1,000,000 | Pending-flow ceiling (NFR-003). |
| `EIDBRIDGE_CODE_STORE_CAP` | `20000` | yes | ≥ MAX_FLOWS | Code store slots: reservations, codes and tombstones. |
| `EIDBRIDGE_POLL_SLOTS` | `1000` | yes | 1–MAX_FLOWS | Upstream concurrency (one long poll per pending flow). |
| `EIDBRIDGE_UPSTREAM_RATE` | `50` | yes | requests/s | Global upstream request rate. |
| `EIDBRIDGE_PER_IP_BURST` | `20` | yes |  | Per-IP (IPv4 or IPv6 /64) burst for new flows. |
| `EIDBRIDGE_PER_IP_RATE` | `1` | yes | per second | Per-IP refill rate. |
| `EIDBRIDGE_PER_CLIENT_BURST` | `1000` | yes |  | Per-client burst. |
| `EIDBRIDGE_PER_CLIENT_RATE` | `50` | yes | per second | Per-client refill rate. |
| `EIDBRIDGE_PER_TARGET_BURST` | `3` | yes |  | Per notification target (person) burst. |
| `EIDBRIDGE_PER_TARGET_RATE` | `0.01` | yes | per second | Per-target refill rate. |
| `EIDBRIDGE_BUCKET_CAP` | `100000` | yes |  | Maximum tracked rate-limit keys per bucket map. |
| `EIDBRIDGE_TRUSTED_PROXIES` | — | no | CIDRs | Proxy hops whose X-Forwarded-For is trusted. Empty: forwarding headers are ignored. |
| `EIDBRIDGE_DEFAULT_LOCALE` | `en` | no | en, et, lv, lt, ru | Fallback locale. |
| `EIDBRIDGE_REMEMBER_METHOD` | `false` | no | true or false | Offer an opt-in method preference cookie (chooser only). |
| `EIDBRIDGE_LOG_LEVEL` | `info` | no | info or debug | Redaction applies at every level. |
| `EIDBRIDGE_TLS_CERT_FILE` | — | no | PEM | Serve HTTPS directly (otherwise terminate TLS at a proxy). |
| `EIDBRIDGE_TLS_KEY_FILE` | — | no | PEM, mode 0600 | Key for EIDBRIDGE_TLS_CERT_FILE. |
| `EIDBRIDGE_MOCK_DOCUMENT` | `PNOEE-40404040009-MOCK-Q` | no | mock env only | Test document the fixture upstream uses to auto-complete device-link sessions; `manual` waits for the mock interface. |
| `EIDBRIDGE_MOCK_LISTEN` | `127.0.0.1:0` | no | loopback only, mock env | Address of the built-in fixture upstream (RP API and automated testing interface). |
| `EIDBRIDGE_SMARTID_ENV` | `demo` | yes | demo, production, mock | Must agree with mode; mock (fixture upstream) is demo-only. |
| `EIDBRIDGE_SMARTID_BASE_URL` | `https://sid.demo.sk.ee/smart-id-rp` | yes |  | RP API base URL (without /v3). |
| `EIDBRIDGE_RP_UUID` | `00000000-0000-4000-8000-000000000000` | yes |  | Relying-party UUID from your agreement. |
| `EIDBRIDGE_RP_NAME` | `DEMO` | yes |  | Registered relying-party name, byte-exact. |
| `EIDBRIDGE_SMARTID_TLS_PINS` | `disabled` | yes | sha256/<b64>[,…] or disabled | SPKI pins (current and next). |
| `EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK` | — | no | I_UNDERSTAND | Production acknowledgement for disabled pins. |
| `EIDBRIDGE_SMARTID_AUTH_CA_DIR` | `trust/demo/smartid-auth-ca` | yes |  | Authentication CA certificates (separate from TLS trust). |
| `EIDBRIDGE_SMARTID_POLICY_OIDS` | `1.3.6.1.4.1.10015.17.2` | yes | dotted OIDs | Certificate policies the end-entity certificate must carry (Q-02). |
| `EIDBRIDGE_SMARTID_CERT_LEVEL` | `QUALIFIED` | no | ADVANCED or QUALIFIED | Minimum certificate level. |
| `EIDBRIDGE_SMARTID_FLOWS` | `device-link` | no | device-link, notification | device-link offers QR and same-device; notification is opt-in. |
| `EIDBRIDGE_SMARTID_CERT_STATUS` | `ocsp` | yes | ocsp or none (demo only) | Certificate status checking. |
| `EIDBRIDGE_SMARTID_STATUS_HOSTS` | `aia.demo.sk.ee,c.sk.ee` | yes | host[:port] list | Allow-listed OCSP/CRL hosts. |
| `EIDBRIDGE_SMARTID_DISPLAY_TEXT` | `Log in to the service` | no | ≤ 60 characters | Text shown on the device; per-client overrides in the clients file. |

Method-specific variables for Mobile-ID, Web eID, the EUDI Wallet and RP API v2 are listed in their guides under [docs/methods](methods/).
