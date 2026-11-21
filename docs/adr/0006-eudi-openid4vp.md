# ADR 0006: EUDI Wallet login through OpenID4VP with SD-JWT VC

- Status: accepted (owner override 2026-11-20 activates Stories 6.1 and 6.2 without the spec-stability and wallet-availability gates)
- Date: 2026-11-20
- Stories: 6.1 (children 6.1-a, 6.1-b, 6.1-d; 6.1-c mdoc not done), 6.2; FR-022, FR-023

## Specification pins (fetched 2026-11-20)

| Specification | Version | sha256 of the fetched document |
|---|---|---|
| OpenID for Verifiable Presentations | 1.0 (openid.net/specs/openid-4-verifiable-presentations-1_0.html) | `e4f0abc689afd0a4f6c41b83954d7f970c5263a26143ad861216aea9918993bb` |
| Selective Disclosure for JWTs | RFC 9901 (rfc-editor.org text) | `fd4cb79184162fa7ef95f4f63abab8ee6d03c9a04c19b8f83758946464b284eb` |
| SD-JWT-based Verifiable Digital Credentials | draft-ietf-oauth-sd-jwt-vc-27 (datatracker page) | `2c47ce2f32877ff2d58f83986db7f91064770f1aababe59f1ed285bd201a9626` |
| Token Status List | draft-ietf-oauth-status-list-21 (datatracker page) | `c07c46d6236b31f280369ca917815afdd96c0ba40325a076ee3435263fef5491` |

## Decisions

- Verifier: signed request object by reference (`request_uri`, typ `oauth-authz-req+jwt`, `x5c`), client identifier prefix `x509_hash`, `response_mode=direct_post`, DCQL query for one `dc+sd-jwt` credential with `vct` from configuration and five claims: `given_name`, `family_name`, `birthdate`, `personal_administrative_number`, `issuing_country`. Invocation link `openid4vp://?client_id=…&request_uri=…` as QR (cross-device) or link (same-device).
- The bridge accepts only ES256/ES384/ES512 for issuer, key-binding and status-list JWTs. A presentation without a key-binding JWT is refused.
- Claim ceiling: only the five requested claims can reach an identity; `birthdate` reaches tokens only with the `profile` scope. The subject is the HMAC of `PNO`, `issuing_country` and `personal_administrative_number`; a PID without them cannot log in.
- Status: credentials that reference a Token Status List are checked against an allow-listed host, with the list token signed by a certificate under the configured PID provider trust; unknown status fails closed. `EIDBRIDGE_EUDI_REQUIRE_STATUS=true` refuses credentials without a reference.
- `mock` mode uses `internal/eudi/walletsim` (simulated PID provider and wallet). Demo mode with a real test wallet needs the operator to configure the test PID provider's CAs; the bridge ships none.

## Not done (gates disclosed)

- mdoc (ISO/IEC 18013-5) presentations (child 6.1-c).
- `direct_post.jwt` (encrypted responses, required by HAIP) and the Digital Credentials API.
- Session-fixation protection for same-device flows with a `redirect_uri` and response code (OpenID4VP §14.2): the response endpoint answers `{}`; the browser continues by polling. Cross-device relay is the same residual risk as Smart-ID QR.
- Interop with the EU reference wallet or a national wallet: NOT RUN. The original activation gate (stable specs, available wallet, obligations in force) is unmet.
