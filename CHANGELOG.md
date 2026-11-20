# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: semantic, from the first tagged release. Each release has an "Upstream compatibility" section.

## [Unreleased]

### Added

- Smart-ID RP API v3 client with full response verification (device-link QR and Web2App, opt-in notification), OCSP/CRL status checks, pinned TLS.
- OpenID Connect provider: authorization code with PKCE S256, static clients (`client_secret_basic`, `client_secret_post`, `private_key_jwt`), sealed access tokens, HMAC subjects, key rotation and emergency revocation.
- Login pages in en, et, lv, lt and ru (non-English catalogs await native-speaker review); demo banner and unofficial-project notice.
- Bounded in-memory flow and code stores; no telemetry; redacting logger.
- Demo/production startup invariants; `config docs`, `trust show`, `keys` commands.

### Upstream compatibility

- Smart-ID RP API v3, documentation 3.2.8 (OpenAPI `info.version` 3.1), retrieved 2026-11-18 and 2026-11-20.
- Demo authentication CAs: TEST of SK ID Solutions ROOT G1E, TEST of SK ID Solutions EID-Q 2024E (fingerprints in `trust/demo/README.md`).
- Observed on the live demo (2026-11-20): QR sessions must omit `initialCallbackUrl`; signed payloads use scheme name `smart-id-demo`; demo OCSP reports mock-account certificates as non-issued.
