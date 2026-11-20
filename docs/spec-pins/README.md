# Specification pins

Metadata only: URL, version, retrieval date, hash and license terms. No specification text is stored here (see [legal stance](../legal.md)). `scripts/check_spec_pins.py` enforces this in CI.

| Protocol | Implemented version | Pin ids |
|---|---|---|
| Smart-ID RP API | v3, docs site 3.2.8 (OpenAPI `info.version` 3.1) | `smartid-rp-api-v3-*`, `smartid-environments` |
| OAuth 2.0 / OIDC | RFC 6749, RFC 7636, RFC 9207, RFC 9700, RFC 8725, OIDC Core 1.0 | `rfc*`, `openid-connect-core-1_0` |

Pins for later methods (Mobile-ID, Web eID, OpenID4VP, SD-JWT VC) are added to `spec-pins.json` when those methods are implemented.
