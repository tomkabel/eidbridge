# OpenID conformance results

Run locally against the bridge in demo mode with the built-in fixture upstream. These are not certification results: nothing was submitted to the OpenID Foundation.

| Item | Value |
|---|---|
| Date | 2026-11-20 |
| Suite | OpenID Foundation conformance suite, image `registry.gitlab.com/openid/conformance-suite:latest`, digest `sha256:e55f64fa67ebce5cb4e7de83803225a48524fe8e4441e3d7b447f062c878b57e`, commit `1bbcbc3722f8cca5f75e5df36856dc41a5285695` (closest tag `release-v5.3.4`) |
| Profile | `oidcc-config-certification-test-plan`; `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` |
| Target | eidbridge demo mode, HTTPS, `EIDBRIDGE_SMARTID_ENV=mock`, two static `client_secret_basic` clients, browser automation clicks the QR button and the fixture approves |
| Runner | `scripts/run-test-plan.py --no-parallel` from the same commit, `CONFORMANCE_MAX_CONSECUTIVE_FAILURES=100` |

## Results

| Plan | PASSED | FAILED | WARNING | SKIPPED |
|---|---|---|---|---|
| Config (discovery) | 1 | 0 | 0 | 0 |
| Basic OP | 2 | 27 | 0 | 6 |

The Basic plan's passes are `oidcc-response-type-missing` and `oidcc-ensure-request-with-valid-pkce-succeeds`: the one Basic module that sends PKCE completes a full login, code exchange, ID-token checks and userinfo with no failure or warning.

Why the 27 fail:

- 24 modules send no `code_challenge`. The bridge requires S256 PKCE from every client (ADR 0002, RFC 9700 §2.1.1), so the authorization endpoint answers `invalid_request` (23 fail at `CheckIfAuthorizationEndpointError`; `oidcc-prompt-none-not-logged-in` gets `invalid_request` before the prompt check – with PKCE the bridge answers `login_required`, see the red-team evidence).
- 2 modules (`oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri`) expect a screenshot of the OP's error page for review; the run had no screenshot step, so the browser automation timed out. The bridge shows the error page and does not redirect (red-team test 3).
- 1 module (`oidcc-server-client-secret-post`) needs a `client_secret_post` client in the test configuration; the bridge clients are `client_secret_basic` only.

SKIPPED: email, address, phone and "all" scopes, the alternate happy flow and unsigned request objects – the bridge supports none of them.

Mandatory PKCE is deliberate and stays. A certification run would need the suite's PKCE-sending profile or an operator decision recorded in an ADR.
