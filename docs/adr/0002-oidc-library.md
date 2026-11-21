# ADR 0002: Handwritten narrow OIDC provider on the standard library

- Status: accepted (architecture recommendation applied under the 2026-11-20 owner override; Q-03 owner confirmation pending)
- Date: 2026-11-20
- Story: 2.4 (FR-006); architecture ADR-004, ADR-008

## Decision

`internal/oidc` and `internal/jose` are handwritten on the Go standard library. No OIDC provider library is a runtime dependency. `github.com/coreos/go-oidc/v3` (Apache-2.0) is a **test-only** dependency used to prove that issued ID tokens validate in a third-party client.

`private_key_jwt` ships in v1 with inline static client JWKS only; `jwks_uri` is rejected.

## Why

ADR-004 lets a library qualify only if it passes the ADR-008 behavior tests through store and hook interfaces. The ADR-008 contract needs: a code store with reserved slots, familyless and family tombstones and replay revocation without allocation; sealed opaque access tokens bound to a process epoch and a monotonic deadline; RFC 9207 `iss` on every response; error pages before redirect validation; and HMAC subjects. The two maintained Go candidates (`zitadel/oidc`, `ory/fosite`, both Apache-2.0) bring large dependency trees and their own storage and token models; adapting them would put the code store, sealing and deny-list outside the library anyway, which ADR-004 then requires to be declared handwritten. The narrow surface (authorization code + PKCE S256, three client authentication methods, RS256/ES256) is small enough to own.

The library comparison was done from the candidates' documented features, not by running them against the ADR-008 tests; that evaluation is **NOT RUN**.

## Consequences

- JOSE is limited to RS256 and ES256 with an algorithm allow-list, key/algorithm pairing, minimum key sizes and no `none`, HMAC or `crit` (RFC 8725). An RFC 7638 thumbprint vector is tested.
- Every ADR-008 rule has a named test in `internal/oidc` and `internal/store`.
- The OpenID Foundation conformance suite is the outside judge for protocol behavior (see `docs/conformance.md`).
- An external security review of `internal/oidc` and `internal/jose` remains required before production use.
