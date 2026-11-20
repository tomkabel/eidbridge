# EUDI verifier conformance report

Run 2026-11-20T13:04:30Z. 17 of 17 cases passed. Not a certification.

| Case | Expect | Observed | Result | Specification |
|---|---|---|---|---|
| `valid-pid` Valid PID presentation with key binding | accept | HTTP 200, client got code | PASS | [OpenID4VP 1.0 8.1 Response Parameters](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1); [RFC 9901 7 Verification and Processing](https://www.rfc-editor.org/rfc/rfc9901#section-7) |
| `wrong-nonce` Key-binding JWT carries a nonce from another request (replay) | reject | HTTP 400, client got error=server_error | PASS | [OpenID4VP 1.0 B.3.6 Presentation Response (nonce)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) |
| `wrong-audience` Key-binding aud is another verifier's client identifier | reject | HTTP 400, client got error=server_error | PASS | [OpenID4VP 1.0 B.3.6 Presentation Response (aud)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) |
| `no-key-binding` Presentation without a key-binding JWT | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 4.3 Key Binding JWT](https://www.rfc-editor.org/rfc/rfc9901#section-4.3) |
| `kb-other-key` Key-binding JWT signed by a key other than cnf.jwk (holder-binding bypass) | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 7.3 Verification by the Verifier](https://www.rfc-editor.org/rfc/rfc9901#section-7.3) |
| `sd-hash-mismatch` sd_hash does not cover the presented SD-JWT | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 4.3.1 Binding to an SD-JWT](https://www.rfc-editor.org/rfc/rfc9901#section-4.3.1) |
| `expired-credential` Credential past its exp | reject | HTTP 400, client got error=server_error | PASS | [SD-JWT VC -27 Registered JWT claims (exp)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-27) |
| `untrusted-issuer` Credential issued by a PID provider outside the verifier's trust | reject | HTTP 400, client got error=server_error | PASS | [SD-JWT VC -27 Issuer-signed JWT verification (x5c)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-27) |
| `wrong-vct` Credential type other than the requested vct | reject | HTTP 400, client got error=server_error | PASS | [OpenID4VP 1.0 B.3.5 Parameter in the meta parameter (vct_values)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5) |
| `injected-disclosure` Extra disclosure not referenced by the issuer JWT | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 7.1 Verification of the SD-JWT (step 5)](https://www.rfc-editor.org/rfc/rfc9901#section-7.1) |
| `duplicate-disclosure` The same disclosure presented twice | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 7.1 Verification of the SD-JWT](https://www.rfc-editor.org/rfc/rfc9901#section-7.1) |
| `revoked-status` Credential revoked in its Token Status List | reject | HTTP 400, client got error=server_error | PASS | [Token Status List -21 Status types (INVALID)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21) |
| `stale-key-binding` Key-binding JWT iat older than the verifier's window | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 4.3.1 Binding to an SD-JWT (iat)](https://www.rfc-editor.org/rfc/rfc9901#section-4.3.1) |
| `tampered-issuer-jwt` Issuer-signed JWT payload changed after signing | reject | HTTP 400, client got error=server_error | PASS | [RFC 9901 7.1 Verification of the SD-JWT (signature)](https://www.rfc-editor.org/rfc/rfc9901#section-7.1) |
| `replay-into-new-request` A presentation accepted once is replayed into a new request | reject | HTTP 400, client got error=server_error | PASS | [OpenID4VP 1.0 14.1 Preventing Replay of Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1) |
| `wrong-state` Response carries a state the verifier did not issue | reject | HTTP 400, flow pending | PASS | [OpenID4VP 1.0 5.2 Existing Parameters (state)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2) |
| `issuer-typ` Issuer-signed JWT typ is not dc+sd-jwt | reject | HTTP 400, client got error=server_error | PASS | [SD-JWT VC -27 Media type (typ header)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-27) |
