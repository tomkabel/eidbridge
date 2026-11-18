---
title: eidbridge source and technical addendum
status: draft
created: 2026-11-18
updated: 2026-11-18
inputDocuments:
  - research/github-issues-2026-11-18.json
  - research/source-manifest.json
---

# Source and technical addendum

The complete GitHub bodies remain in the issue snapshot. This addendum preserves source proposals and notes too detailed for the PRD. The proposed functionality is not implemented. Estimates exclude unmeasured review/setup/maintenance. Reconciled architecture decisions take precedence over conflicting source suggestions.

## Issue #1: Scaffold Go module with CI, licence checks and release automation

FR-001; Story 1.2. Original proposal:

Layout:
```
cmd/eidbridge/        main binary
internal/smartid/     RP API v3 client
internal/oidc/        OIDC provider surface
internal/authn/       method-neutral authenticator interface
docs/spec-pins/       pinned copies/links of the protocol versions implemented
examples/             IdP and app integration examples
scripts/              e2e helpers
```
- `go.mod` (current stable Go), `LICENSE-MIT` + `LICENSE-APACHE` (dual licence; Apache-2.0 for the explicit patent grant), `NOTICE`, `README.md` skeleton.
- `.github/workflows/ci.yml`: `gofmt -l` (fail on output), `go vet ./...`, `go test -race ./...`, build matrix `linux/amd64`, `linux/arm64`, `go-licenses report ./...` with a deny-list for non-permissive licences.
- `.github/dependabot.yml` for `gomod`, `github-actions` and `docker`.
- `.goreleaser.yaml`: static binaries (`CGO_ENABLED=0`) for linux/darwin amd64/arm64, `checksums.txt`, SBOM, multi-arch image `ghcr.io/tomkabel/eidbridge:<tag>` built from a distroless/scratch `Dockerfile` (target < 20 MB).
- `.github/workflows/release.yml` triggered on `v*` tags.
- `docs/spec-pins/README.md` records the Smart-ID RP API version implemented (3.2.x) with links to the public spec; no vendored third-party doc text.

**Original exclusions**

- Application logic, Docker Compose demo (separate issue)
- Publishing to any registry other than GitHub Releases and GHCR

**Original notes and activation gate**

Effort: ~4 h. No dependencies. Keep dependencies to stdlib plus a minimal, permissively licensed set; every addition must appear in the `go-licenses` report.

## Issue #2: Spike Smart-ID v3 device-link login against the public demo env

FR-002; Story 1.4. Original proposal:

`cmd/sidspike/main.go` (deleted or moved to `internal/smartid` tests after the spike):
1. Generate a random challenge, create an anonymous device-link authentication session.
2. Build the dynamic device link from the returned session token/secret, render it as a QR in the terminal, refresh per the spec's timing rules.
3. Poll session status until `COMPLETE`.
4. Verify the returned signature over the challenge and validate the authentication certificate chain against the demo CA.
5. Print `AUTHENTICATED` plus subject fields; exit 0.

Fallback ladder, decided up front:
1. Device-link rejected for the demo RP → use the v3 notification-based flow; device-link goes behind a flag.
2. Demo env refuses anonymous access → use the Mobile-ID REST demo as the first method, Smart-ID behind the authenticator interface.
3. Both fail → build against recorded fixtures and Web eID only; publish the finding.

Write the result to `docs/adr/0001-spike-outcome.md`.

**Original exclusions**

- OIDC, web UI, configuration, production endpoints

**Original notes and activation gate**

Effort: 6 h hard cap. Depends on: "Scaffold Go module with CI, licence checks and release automation". Implement clean-room from the published protocol spec; do not copy from LGPL-licensed demo applications or unlicensed documentation repositories. If demo account registration requires a contract or payment, stop and write a post-mortem instead.

## Issue #3: Implement Smart-ID RP API v3 client with signature verification

FR-003; Story 2.1. Original proposal:

```go
package smartid

type Config struct {
    BaseURL        string // demo or production RP API v3 URL
    RPUUID, RPName string
    TrustAnchors   *x509.CertPool // CA roots for auth certs
    HTTPClient     *http.Client   // TLS settings from the pinning issue
    CertLevel      string         // QUALIFIED | ADVANCED
}

func (c *Client) StartDeviceLink(ctx context.Context, req AuthRequest) (*Session, error)
func (s *Session) DeviceLink(now time.Time) (string, error) // dynamic link / QR payload
func (c *Client) Poll(ctx context.Context, sessionID string) (*Status, error)
func (c *Client) Verify(st *Status, challenge []byte) (*Identity, error)

type Identity struct {
    Country, IDCode, GivenName, Surname string
    Cert *x509.Certificate
}
```
- Challenge: crypto/rand, length per spec; never reused.
- `Verify`: check signature algorithm allow-list, signature over the protocol-defined payload, certificate chain to `TrustAnchors`, validity period, key usage, certificate level >= requested, and that the identity in the cert matches the response.
- Long-poll with `timeoutMs`, context cancellation, bounded retries on 5xx only.
- Typed errors for user refusal, timeout, wrong VC, account problems, so the UI can show specific messages.

**Original exclusions**

- Notification-based flow (separate issue), signing sessions, RP API v1/v2

**Original notes and activation gate**

Effort: ~4 h. Depends on: "Spike Smart-ID v3 device-link login against the public demo env". Pin the implemented protocol version in `docs/spec-pins/`. Official MIT-licensed clients may be consulted and reused with the licence notice kept in `NOTICE`.

## Issue #4: Support Smart-ID v3 notification-based authentication flow

FR-004; Story 2.8. Original proposal:

- `internal/smartid`: `StartNotification(ctx, NotificationRequest)` where the request carries a semantics identifier (`PNOEE-...`, `PNOLV-...`, `PNOLT-...`) or document number, the challenge, and interaction parameters (display text, verification-code choice).
- Return the verification code derived from the challenge so the login page can display it; the user compares it on the phone.
- Same `Poll` / `Verify` path as device-link; `Verify` additionally checks the returned identity matches the requested one.
- Login page: optional "Enter personal code" form, shown only when `EIDBRIDGE_SMARTID_FLOWS` includes `notification`.
- Input validation: country prefix allow-list, identity code checksum validation before any outbound call.

```
EIDBRIDGE_SMARTID_FLOWS=device-link,notification   # default: device-link
```

**Original exclusions**

- Signing sessions, Mobile-ID

**Original notes and activation gate**

Effort: ~3 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification", "Redact personal identity codes at the log sink". Notification flow accepts a user-typed identifier, so rate limiting per client IP on the login form is required to avoid push spam to arbitrary users.

## Issue #5: Define a method-neutral authenticator interface for eID backends

FR-005; Story 2.3. Original proposal:

```go
package authn

type Method interface {
    Name() string                                  // "smartid", "mobileid", "webeid", ...
    Start(ctx context.Context, r StartRequest) (*Pending, error)
    Poll(ctx context.Context, p *Pending) (Result, error)
}

type Pending struct {
    ID        string
    UI        UIHint   // QR payload, verification code, or browser-side challenge
    ExpiresAt time.Time
}

type Result struct {
    Done     bool
    Identity *Identity // set only after full cryptographic verification
    Err      error     // typed: ErrUserRefused, ErrTimeout, ...
}

type Identity struct {
    Method, Country, IDCode, GivenName, Surname string
    LoA       string            // "high" | "substantial"
    Extra     map[string]string // method-specific, mapped to claims only if allow-listed
}
```
- Registry built from config: `EIDBRIDGE_METHODS=smartid`.
- `Identity` is produced only by the method after verification; the OIDC layer treats it as trusted input.
- Contract test suite in `internal/authn/authntest` that every method must pass (start, poll to completion, refusal, timeout, verification failure).

**Original exclusions**

- Implementing additional methods (separate deferred issues)
- Exposing the interface as a public Go API or plugin ABI

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Keep it internal until at least two real methods exist; the second implementation will reveal what the interface got wrong.

## Issue #6: Expose eID logins as a standard OpenID Connect provider

FR-006; Story 2.4. Original proposal:

**Reconciliation:** Current contract: ADR-007/008 govern mode-aware key IDs, retained atomic consumed-code tombstones and monotonic token deadlines. Startup key generation below is demo-only; production requires fresh operator-supplied keys.

Endpoints:
```
GET  /.well-known/openid-configuration
GET  /jwks.json
GET  /authorize      code flow only; state, nonce, PKCE S256 required
POST /token          client_secret_basic / client_secret_post / private_key_jwt
GET  /userinfo
```
- Signing: RS256 (ES256 optional), key from file or generated at start; `kid` rotation by keeping old keys in JWKS until expiry.
- Clients from static config:
```yaml
clients:
  - id: keycloak
    secret_file: /run/secrets/keycloak
    redirect_uris: [https://kc.example/realms/main/broker/eid/endpoint]
```
- Claims: `sub` = `base64url(HMAC-SHA256(K_sub[v], "eidbridge-sub-v1" ‖ 0x00 ‖ sector ‖ 0x00 ‖ type ‖ 0x00 ‖ country ‖ 0x00 ‖ code))` with a versioned server secret, never the raw or plainly hashed ID code (configurable `sub_mode: public|pairwise`; public uses one global sector, pairwise one sector per client; see [architecture ADR-007](architecture.md#adr-007-subject-and-key-management)), `given_name`, `family_name`, `country`, `eid_method`, `acr` (LoA), optional `personal_code` only if the client is allow-listed for it.
- Authorization codes single-use, 60 s TTL, bound to client, redirect URI and PKCE verifier; in-memory store.
- Exact-match redirect URI validation; no implicit or hybrid flow.

**Original exclusions**

- Dynamic client registration, refresh tokens, logout endpoints, user database

**Original notes and activation gate**

Effort: ~3-4 h. Depends on: "Define a method-neutral authenticator interface for eID backends". Prefer a small, audited OIDC library over hand-rolled JWT code if one fits without pulling in a large dependency tree.

## Issue #7: Wire eidbridge binary with login page, QR and Web2App flows

FR-007; Story 2.5. Original proposal:

- `cmd/eidbridge/main.go`: parse config, build `authn` registry, mount `internal/oidc`, serve `internal/web`.
- `internal/web`: server-rendered HTML (`html/template`, embedded via `embed`), no JS framework. Small JS only to refresh the dynamic QR and poll `/flow/{id}/status`.
- Same-device detection by user agent hint plus an explicit "Open on this device" button.
- Show verification code / error states from typed `authn` errors.
- Strict headers: CSP without `unsafe-inline`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Flow state in memory, keyed by an unguessable ID, bound to the OIDC authorize request; expires with the session.

Configuration (env, or `--config file.yaml`):
```
EIDBRIDGE_LISTEN=:8080
EIDBRIDGE_ISSUER=https://eid.example.com
EIDBRIDGE_METHODS=smartid
EIDBRIDGE_SMARTID_ENV=demo|production
EIDBRIDGE_RP_UUID=...            # required in production
EIDBRIDGE_RP_NAME=...
EIDBRIDGE_SIGNING_KEY_FILE=/run/secrets/oidc.pem
```
`--demo` sets demo endpoints and the public demo relying party. Health endpoints: `/healthz`, `/readyz`.

Reconciled 2026-11-18 ([architecture ADR-003](architecture.md#configuration-invariants)): the mode (`EIDBRIDGE_MODE` or `--demo`) is required and has no default, and `EIDBRIDGE_SMARTID_ENV` must agree with it or startup fails.
`docs/configuration.md` lists every option with defaults.

**Original exclusions**

- Branding/theming beyond a CSS override file
- No vendor logos or UI imitating any eID app

**Original notes and activation gate**

Effort: ~3 h. Depends on: "Expose eID logins as a standard OpenID Connect provider", "Implement Smart-ID RP API v3 client with signature verification".

## Issue #8: Pin RP API TLS certificates and make trust anchors configurable

FR-008; Story 2.2. Original proposal:

- `internal/tlspin`: builds an `*http.Client` whose `tls.Config.VerifyPeerCertificate` checks SPKI SHA-256 pins in addition to normal chain validation.
- Pins and CA bundles shipped in `trust/` for demo and production, overridable:
```
EIDBRIDGE_SMARTID_TLS_PINS=sha256/AAA...,sha256/BBB...   # current + next
EIDBRIDGE_SMARTID_AUTH_CA_DIR=/etc/eidbridge/trust/smartid
```
- `tls.Config{MinVersion: tls.VersionTLS12}` with Go's default modern suites; no legacy suites re-enabled.
- Startup self-check: one TLS handshake to the configured endpoint; on pin mismatch log an actionable error naming the expected and observed SPKI hashes (no personal data involved).
- `eidbridge trust show` subcommand prints the active pins and CA subjects.

**Original exclusions**

- OCSP/AIA checking of end-user authentication certificates (tracked with the Web eID work; Smart-ID responses are verified against trust anchors)

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Risk: pins in a release go stale on server cert renewal; the maintenance runbook issue covers tracking renewals and shipping patch releases.

## Issue #9: Redact personal identity codes at the log sink

FR-009; Story 1.3. Original proposal:

- Use `log/slog` everywhere; wrap the handler in `internal/logx.RedactingHandler`.
- Redaction rules applied to every attribute value and message string:
  - Semantics identifiers / personal codes (`PNOEE-38001085718`, bare 11-digit EE/LT codes, LV `DDMMYY-NNNNN`) → `PNOEE-****`.
  - PEM blocks and long base64 strings (> 64 chars) → `[redacted:base64 len=N]`.
  - Known sensitive keys (`sessionSecret`, `signature`, `cert`, `id_token`, `code`) → `[redacted]`.
- Typed `logx.Personal(string)` value implementing `slog.LogValuer` for intentional references; always renders masked.
- No certificates, signatures or session hashes at INFO. DEBUG level prints a startup banner: "DEBUG logging may contain personal data".
- No config flag to turn redaction off.

**Original exclusions**

- Redacting data in the OIDC tokens themselves (claims are controlled by client allow-lists)

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Scaffold Go module with CI, licence checks and release automation". Regex masking is a backstop; the primary control is not passing identity data to the logger at all.

## Issue #10: Enforce no telemetry and zero data retention by default

FR-010; Story 2.6. Original proposal:

- No analytics, crash reporting, update checks or version beacons. Outbound HTTP only via clients built from configured method endpoints; a test asserts no other `http.Client` is constructed.
- `internal/store`: in-memory map with TTL (default = flow timeout + 30 s), deleted on completion, failure or expiry; no persistence, no database in v1. Memory bound: max pending flows (default 10 000) with 503 when exceeded.
- Cookies: only a single short-lived, `HttpOnly; Secure; SameSite=Lax` flow cookie; nothing persistent for end users.
- `SECURITY.md`: supported versions, private vulnerability reporting via GitHub Security Advisories, response targets.
- `docs/security.md`: threat model summary, retention = 0, what crosses the network, deployment hardening (run behind TLS-terminating proxy, read-only filesystem, non-root).
- README note: hosting this bridge for third parties makes the host a processor under GDPR with its own obligations.

**Original exclusions**

- Shared session store for multi-replica deployments (revisit only on demand; sticky sessions documented instead)

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". Prometheus metrics, if added later, must be pull-only, opt-in and contain counts only.

## Issue #11: Warn on demo environment use and block demo credentials in prod

FR-011; Story 2.7. Original proposal:

- Detect demo mode when `EIDBRIDGE_SMARTID_ENV=demo`, `--demo`, the RP UUID equals the public demo UUID `00000000-0000-4000-8000-000000000000`, or the base URL host is a known demo host (`sid.demo.sk.ee`, `tsp.demo.sk.ee`).
- Demo mode:
  - WARN log at startup and every 10 minutes: "DEMO ENVIRONMENT - identities are not real; do not use for production users".
  - Persistent banner on the login page.
  - ID tokens carry `acr: "demo"` and claim `eid_env: "demo"` so the IdP side can reject them.
- `EIDBRIDGE_MODE=production` plus any demo indicator → exit non-zero with an explanation.
- Production mode with a mixed config (prod endpoint, demo CA bundle or vice versa) → exit non-zero.

**Original exclusions**

- Testing against restricted account types that require arrangements with the service operator

**Original notes and activation gate**

Effort: ~1 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". Known demo hosts live in one table in `internal/config/demo.go`; update it when endpoints change.

## Issue #12: Add unofficial-project notice, trademark policy and clean-room rules

FR-012; Story 1.1. Original proposal:

- README and login page footer: "Unofficial, community-maintained software. Not affiliated with, endorsed by or certified by the operators of Smart-ID, Mobile-ID, the Estonian ID-card or any EUDI Wallet."
- `docs/legal.md`:
  - Scheme names are used only to describe compatibility ("compatible with Smart-ID RP API v3"); no logos, brand colours or UI imitating scheme apps; scheme names never in package, image or module names.
  - Production use requires the integrator's own relying-party agreement with the scheme operator; the project ships no production credentials and does not broker, resell or meter transactions.
  - Toward the scheme the bridge is an ordinary relying party; toward the integrator's apps it is an OIDC provider. It is not a scheme-certified identity provider.
  - No claims of eIDAS or EUDI compliance for the integrator's service.
- `CONTRIBUTING.md` clean-room rules: implement from published protocol specifications; MIT-licensed official client code may be reused with its notice preserved in `NOTICE`; never copy from LGPL-licensed demo apps or from unlicensed documentation repositories (link, do not vendor); DCO sign-off required.
- `NOTICE` file maintained for any reused MIT code.

**Original exclusions**

- Formal legal opinion; flag material questions for qualified Estonian counsel

**Original notes and activation gate**

Effort: ~1.5 h. No code dependencies. If a trademark complaint arrives, comply first (rename/rewording), discuss later.

## Issue #13: Document end-to-end personal data flow for integrator DPIAs

FR-013; Story 3.1. Original proposal:

`docs/data-flow.md` containing:
- Sequence diagram (Mermaid): browser → IdP → eidbridge → eID service → eidbridge → IdP.
- Table per field:

| Field | Source | Held where | Retention | Leaves bridge to | Logged |
|---|---|---|---|---|---|
| Given name, surname | auth cert / API response | memory (flow) | until code exchange | IdP via ID token | no |
| Personal identity code | API response / user input (notification flow) | memory (flow) | until code exchange | IdP only if client allow-listed | masked |
| Authentication certificate | API response | memory | verification only | never | never |
| Client IP, user agent | HTTP request | memory | request | never | access log, configurable |

- Roles: integrator = controller; eID service operator processes under its own agreement with the integrator; project authors receive nothing (no telemetry).
- Note that operating the bridge on behalf of third parties makes the operator a processor requiring a DPA.
- Configuration knobs that change the flow (`sub_mode`, claim allow-lists, access log) and their effect.

**Original exclusions**

- Legal advice or template DPIA text for a specific sector

**Original notes and activation gate**

Effort: ~1.5 h. Depends on: "Expose eID logins as a standard OpenID Connect provider", "Redact personal identity codes at the log sink", "Enforce no telemetry and zero data retention by default". Update the table whenever a method is added.

## Issue #14: Ship a zero-config docker compose demo with a sample relying party

FR-014; Story 3.2. Original proposal:

**Reconciliation:** Current contract: the HTTP localhost sample uses the exact static demo-only redirect exception in ADR-008. Production callbacks require HTTPS.

- `docker-compose.yml`:
  - `eidbridge` (image from GHCR or local build) with `--demo`, issuer `http://localhost:8081`.
  - `demo-rp`: minimal Go OIDC client in `examples/demo-rp/` on `http://localhost:8080` that redirects to the bridge and renders the decoded ID token claims.
- Signing key generated on first start into a named volume; client secret pre-set for the demo client only.
- `scripts/e2e-demo.sh`: brings the stack up, drives the flow with recorded fixtures through a mock upstream (`EIDBRIDGE_SMARTID_BASE_URL` override), asserts claims page content, tears down.
- README "Quick start":
```
git clone https://github.com/tomkabel/eidbridge && cd eidbridge
docker compose up
# open http://localhost:8080, scan the QR with the Smart-ID demo app
```
plus single-binary instructions from GitHub Releases.
- README screenshot of a completed demo login (no real personal data).

**Original exclusions**

- Production deployment manifests (Helm, systemd) until requested

**Original notes and activation gate**

Effort: ~3 h. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows", "Warn on demo environment use and block demo credentials in prod", "Scaffold Go module with CI, licence checks and release automation". The live demo-app check stays manual unless the demo environment offers a scriptable test endpoint (see spike ADR).

## Issue #15: Add config-only IdP integration guides with e2e tests per IdP

FR-015; Story 3.5. Original proposal:

- `docs/idp/keycloak.md`, `authentik.md`, `zitadel.md`, `ory.md`: exact UI steps and equivalent API/CLI/Terraform snippets, claim/attribute mappers (`given_name`, `family_name`, `country`, `acr`), first-login flow recommendations (link by stable `sub`, never by name), rejecting `acr=demo` in production realms.
- `examples/idp/<name>/docker-compose.yml`: IdP container + bridge (fixture upstream) + preconfigured realm/tenant import (e.g. Keycloak `realm-export.json`).
- `test/e2e/idp_test.go` (build tag `e2e`): Playwright-Go or chromedp drives IdP login page → "Sign in with eID" → bridge → fixture completion → asserts the IdP user exists with mapped attributes.
- CI matrix job `e2e-idp` across Keycloak (current + previous major), authentik, Zitadel, Ory; nightly plus on release tags.

**Original exclusions**

- Java SPI or IdP-native plugins (separate deferred issue)
- Submitting listings to IdP catalogues

**Original notes and activation gate**

Effort: ~6 h (Keycloak first at ~3 h, others ~1 h each). Depends on: "Expose eID logins as a standard OpenID Connect provider", "Ship a zero-config docker compose demo with a sample relying party". Risk: IdP UI churn; prefer API/import-based config in tests so docs drift is caught.

## Issue #16: Localize the login page for Estonian, Latvian, Lithuanian, English

FR-016; Story 3.3. Original proposal:

- `internal/web/i18n/{en,et,lv,lt,ru}.json` message catalogs; lookup via `golang.org/x/text/language` matcher.
- Locale precedence: `ui_locales` from the authorize request → `Accept-Language` → `EIDBRIDGE_DEFAULT_LOCALE` (default `en`).
- Pass the chosen language to method interaction parameters where supported (display text language for Smart-ID).
- Custom display text per OIDC client (`clients[].display_text`), length-validated against protocol limits.
- Language switcher links on the page; `lang` attribute set on `<html>`.

**Original exclusions**

- Right-to-left layouts, per-tenant theming

**Original notes and activation gate**

Effort: ~2 h plus translation review. Depends on: "Wire eidbridge binary with login page, QR and Web2App flows". README may also get an Estonian translation later; keep the English README authoritative.

## Issue #17: Add a maintenance runbook for upstream API, TLS and key changes

FR-017; Story 3.4. Original proposal:

`docs/api-tracking.md` covering:
- Sources to watch: RP API changelog and spec repo releases, scheme operator technical announcements, demo environment pages, CA repository for new issuing CAs.
- Per change type: what breaks, how to detect (failing nightly live test, pin mismatch error), which files to update (`docs/spec-pins/`, `trust/`, `internal/smartid`), release type (patch for pins/CA, minor for API changes).
- Nightly GitHub Actions job `live-demo.yml`: handshake + pin check against demo endpoints, and the live demo test when a scriptable path exists; opens an issue on failure.
- `CHANGELOG.md` (Keep a Changelog) with an "Upstream compatibility" section per release.
- Support policy: latest minor gets fixes; pins and CA updates back-ported one minor.

**Original exclusions**

- A hosted monitoring service (see deferred health-check issue)

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Pin RP API TLS certificates and make trust anchors configurable", "Scaffold Go module with CI, licence checks and release automation".

## Issue #18: Add Django and FastAPI examples that log in through the bridge

FR-018; Story 3.6. Original proposal:

- `examples/django/`: `mozilla-django-oidc` configured for the bridge issuer; user created/linked by `sub`; template shows `given_name`, `family_name`, `country`, `acr`.
- `examples/fastapi/`: `authlib` Starlette integration, same claims.
- Each with `docker-compose.yml` reusing the bridge fixture service, and `README.md` with the five config values to change for production.
- `examples/test_examples.py` (pytest): spins up the stack, drives the login through the fixture upstream with `httpx` following redirects, asserts the claims page.
- CI job `examples` running pytest on changes under `examples/` or `internal/oidc/`.

**Original exclusions**

- A Python package for the eID protocol itself (separate deferred issue)
- Other frameworks (Rails, Laravel, Spring) until requested

**Original notes and activation gate**

Effort: ~2 h. Depends on: "Ship a zero-config docker compose demo with a sample relying party".

## Issue #19: Add Mobile-ID authentication via the MID REST API

FR-019; Story 4.2. Original proposal:

```go
package mobileid
type Config struct {
    BaseURL, RPUUID, RPName string
    TrustAnchors *x509.CertPool
    HTTPClient   *http.Client // pinned, via internal/tlspin
}
func (c *Client) Start(ctx, phone, idCode string, hash []byte, lang string) (*Session, error)
func (c *Client) Poll(ctx, sessionID string) (*Status, error)
func (c *Client) Verify(st *Status, hash []byte) (*authn.Identity, error)
```
- Verification code computed from the hash and shown on the login page.
- Input form for phone number (E.164, country allow-list) and personal code with checksum validation; rate-limited per IP and per phone number.
- Demo environment support with the public demo relying party; demo-guard rules extended to the MID demo host.
- Passes the `authntest` contract suite.

**Original exclusions**

- Mobile-ID signing

**Original notes and activation gate**

Effort: ~8-10 h. Depends on: "Define a method-neutral authenticator interface for eID backends", "Let users choose among multiple enabled eID methods". Deferred: v1 is one method done well; start once the Smart-ID path is stable and at least a few deployments ask for it. Note the demo environment rotates its keys/certs occasionally; covered by the maintenance runbook.

## Issue #20: Let users choose among multiple enabled eID methods

FR-020; Story 4.1. Original proposal:

- Login page renders one tab/button per enabled method, remembering the last choice in a short-lived, first-party, non-identifying cookie (opt-in via `EIDBRIDGE_REMEMBER_METHOD=true`).
- Client control:
  - `acr_values` (e.g. `urn:eidbridge:loa:high`) filters methods by LoA.
  - `login_hint=method:smartid` preselects and skips the chooser.
  - Per-client `allowed_methods` in config.
- ID token: `amr` (e.g. `["smartid"]`), `acr` per actual method LoA.
- Discovery document advertises `acr_values_supported`.

**Original exclusions**

- Step-up authentication within an existing IdP session

**Original notes and activation gate**

Effort: ~3 h. Depends on: "Define a method-neutral authenticator interface for eID backends". Deferred until a second method exists (Mobile-ID or Web eID); with one method this is dead code.

## Issue #21: Add ID-card login via Web eID token validation in Go

FR-021; Story 5.1. Original proposal:

- `pkg/webeid` (public Go package, usable standalone):
```go
type Validator struct {
    TrustedCAs   *x509.CertPool
    SiteOrigin   string
    OCSP         OCSPConfig // AIA or designated responder, timeout, cache
    AllowedPolicies []asn1.ObjectIdentifier
}
func (v *Validator) Validate(tok AuthToken, nonce []byte) (*x509.Certificate, error)
```
- Nonce endpoint: crypto/rand, single-use, bound to the flow, short TTL.
- Checks: token format version, origin binding, signature over origin+nonce hash, chain to configured CAs, validity, key usage and certificate policies, OCSP status with nonce, responder cert validation.
- Login page loads the Web eID JS library (vendored, MIT) to obtain the token.
- `internal/webeid` adapts the validator to `authn.Method`.

**Original exclusions**

- Signing with ID-card, trusted list (TSL) parsing for all EU CAs in the first iteration

**Original notes and activation gate**

Effort: ~80-100 h (spec stack, OCSP and trust-chain handling). Deferred: exceeds the initial scope by far; unblock when the Smart-ID path is stable and there is a concrete deployment needing ID-card. Depends on: "Let users choose among multiple enabled eID methods". Security-critical: request an external review before release.

## Issue #22: Accept EUDI Wallet presentations via OpenID4VP as a login method

FR-022; Story 6.1. Original proposal:

- `internal/eudi`: verifier role per OpenID4VP (same-device and cross-device QR), presentation definition / DCQL query for PID attributes (given name, family name, birth date, nationality, personal identifier where available).
- Credential formats: SD-JWT VC first, mdoc (ISO 18013-5) second.
- Verification: issuer signature against configured trust lists, holder binding (key binding JWT / device auth), nonce and audience, status list revocation.
- Verifier identity: relying-party access certificate / client_id scheme configured per deployment.
- Claim mapping table in config; `amr: ["eudi_pid"]`.
- Interop testing against the EU reference wallet and verifier test environments.

**Original exclusions**

- Issuing credentials, wallet-side features, QEAA attestations

**Original notes and activation gate**

Effort: 60+ h and ongoing spec tracking. Deferred: OpenID4VP, HAIP and the ARF are still moving, wallet acceptance obligations for private relying parties are not yet in force, and mainstream IdPs may add native support. Unblock when the reference specs stabilise and a national wallet is available for testing. Depends on: "Let users choose among multiple enabled eID methods".

## Issue #23: Build an EUDI Wallet relying-party conformance test harness

FR-023; Story 6.2. Original proposal:

- Simulated wallet that produces valid and deliberately malformed presentations (SD-JWT VC, mdoc): wrong nonce, bad key binding, expired/revoked credentials, unexpected disclosures.
- Test catalog as data (`conformance/cases/*.yaml`) referencing spec sections by version.
- Runner targets an OpenID4VP verifier endpoint, collects results, emits JUnit XML and a Markdown report.
- Version matrix: one test catalog per pinned spec version.

**Original exclusions**

- Certification claims of any kind; wallet-side conformance

**Original notes and activation gate**

Effort: well over 60 h plus continuous spec tracking. Deferred: a half-finished harness against a moving spec is worse than none. Unblock only after "Accept EUDI Wallet presentations via OpenID4VP as a login method" ships and the specs are stable enough to pin.

## Issue #24: Provide a native Keycloak identity provider SPI for eidbridge

FR-024; Story 7.1. Original proposal:

- `keycloak-spi/` Maven project, Apache-2.0, targeting the current Keycloak LTS-like major.
- `EidbridgeIdentityProviderFactory` extending the OIDC provider with fixed defaults (PKCE, `acr` checks) and an "eID" admin page.
- Mappers: country, LoA, personal code (opt-in).
- Testcontainers-based integration test with the bridge fixture stack.
- Published as a release jar; compatibility table per Keycloak version.

**Original exclusions**

- SPIs for other IdPs

**Original notes and activation gate**

Effort: 20+ h (Java/Keycloak ramp) plus per-release upkeep. Deferred: the config-only guide covers the use case and previous SPI-based eID plugins went unmaintained after Keycloak API changes. Unblock if at least three users request it with a concrete gap the OIDC guide cannot close. Depends on: "Add config-only IdP integration guides with e2e tests per IdP".

## Issue #25: Publish a minimal Python client for Smart-ID RP API v3

FR-025; Story 7.2. Original proposal:

- Package name without scheme trademarks in the distribution name (e.g. `eidbridge-rp`), module `eidbridge_rp`.
- API:
```python
client = RPClient(base_url, rp_uuid, rp_name, trust_anchors, pins)
session = client.start_device_link(challenge=..., cert_level="QUALIFIED")
link = session.device_link(now)
status = client.poll(session.id)
identity = client.verify(status, challenge)
```
- Deps: `httpx`, `cryptography` only. Typed, `py.typed`.
- Shares `internal/smartid/testdata/` fixtures; CI runs both Go and Python against them.
- Same log-redaction and no-telemetry rules as the bridge.

**Original exclusions**

- Django/Flask integration packages (the OIDC examples cover frameworks)
- Node client (a maintained third-party one exists; link it from README)

**Original notes and activation gate**

Effort: ~4-6 h initial, ongoing upkeep per API change. Deferred: two codebases double protocol maintenance; the OIDC path already serves Python apps. Unblock when at least two users ask for a direct library. Depends on: "Implement Smart-ID RP API v3 client with signature verification".

## Issue #26: Add an eidbridge doctor command for upstream connectivity checks

FR-026; Story 7.3. Original proposal:

```
$ eidbridge doctor
smartid  demo  sid.demo.sk.ee  tls1.3 TLS_AES_128_GCM_SHA256  pin OK  cert expires in 212d  rtt 41ms  OK
trust    smartid CA bundle: 3 certs, earliest expiry 2029-01-02                                       OK
```
- Exit code non-zero on any failure; `--json` output.
- `EIDBRIDGE_READYZ_UPSTREAM=true` is superseded: readiness covers configuration and key load only ([architecture ADR-009](architecture.md#adr-009-capacity-and-availability), NFR-014); upstream checks belong to the opt-in doctor command (FR-026).
- Warns when a pinned cert expires within 30 days.
- Optional Prometheus gauge for cert expiry days (pull-only, opt-in, no personal data).

**Original exclusions**

- A hosted monitoring service or status page

**Original notes and activation gate**

Effort: ~4 h. Deferred: no operator has asked yet; the pin-mismatch startup error and nightly CI check cover the basics. Unblock on the first user report of an upstream-change outage that the existing error messages did not explain. Depends on: "Pin RP API TLS certificates and make trust anchors configurable".

## Issue #27: Ship a mock RP API server and test identities for offline testing

FR-027; Story 7.4. Original proposal:

- Implements the subset of RP API v3 endpoints the bridge uses; responses signed with a test CA generated at start (`--ca-out` writes the trust bundle).
- Control API: `POST /_mock/sessions/{id}/complete|refuse|timeout`, or scripted scenarios via `--scenario scenarios.yaml` keyed by test identity.
- Synthetic identities with valid-checksum personal codes in a reserved fake range, clearly marked as test data.
- Container image `ghcr.io/tomkabel/eidbridge-mock`.
- Bridge flag `EIDBRIDGE_SMARTID_ENV=mock` trusts only the mock CA and forces demo-guard behaviour.

**Original exclusions**

- Simulating real identities or real CA certificates

**Original notes and activation gate**

Effort: ~6 h. Deferred: the initial e2e work uses recorded fixtures; promote to a standalone tool when external users ask for offline testing. Depends on: "Implement Smart-ID RP API v3 client with signature verification". Implement from the published spec only.

## Issue #28: Support document signing sessions alongside authentication

FR-028; Story 8.1. Original proposal:

- New authenticated API (client credentials, separate from OIDC login):
```
POST /api/v1/sign        {method, user_ref, digest_alg, digest}
GET  /api/v1/sign/{id}   -> {state, signature, signer_cert}
```
- Bridge signs nothing itself; it relays the digest and verifies the returned signature against the signer certificate.
- Container building left to existing libraries (e.g. DigiDoc libraries), documented in `docs/signing.md` with an example.
- Same redaction, retention-0 and demo-guard rules.

**Original exclusions**

- Qualified signature creation devices, timestamping, long-term validation, any claim of qualified-signature status

**Original notes and activation gate**

Effort: 40+ h including container example and validation. Deferred: legally heavier than authentication, and authentication-only keeps scope and liability small. Unblock after v1 authentication is stable and a deployment needs signing. Depends on: "Implement Smart-ID RP API v3 client with signature verification".

## Issue #29: Support legacy Smart-ID RP API v2 for existing relying parties

FR-029; Story 7.5. Original proposal:

- `internal/smartid/v2` with its own fixtures; shares verification helpers where the signature scheme matches.
- Login page uses the identity-code form (no device-link in v2).
- Startup warning that v2 is legacy and v3 is recommended.

**Original exclusions**

- RP API v1

**Original notes and activation gate**

Effort: ~6 h plus doubled protocol maintenance. Deferred: v3 is current and building for legacy versions doubles upkeep for a shrinking user base. Unblock only if a concrete deployment cannot use v3. Depends on: "Define a method-neutral authenticator interface for eID backends".

## Issue #30: Document or ship a WordPress login integration via the bridge

FR-030; Story 7.6. Original proposal:

1. `docs/apps/wordpress.md`: configure a maintained OpenID Connect client plugin against the bridge; claim mapping to WP user fields; user matching by `sub`; rejecting `acr=demo`.
2. `examples/wordpress/docker-compose.yml` (WordPress + DB + bridge mock) with a scripted login test.
3. Only if needed: a minimal plugin adding defaults and an "eID login" button; GPL-compatible licence.

**Original exclusions**

- WooCommerce checkout integration, signing

**Original notes and activation gate**

Effort: ~3 h for the guide; 15+ h for a maintained plugin. Deferred: no demonstrated demand yet, and WordPress plugin maintenance is costly. Unblock when WordPress users ask. Depends on: "Ship a mock RP API server and test identities for offline testing".
