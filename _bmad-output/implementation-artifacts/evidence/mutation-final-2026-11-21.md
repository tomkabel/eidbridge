# Mutation testing, final pass (2026-11-20/21)

Tool: gremlins (`~/go/bin/gremlins unleash --timeout-coefficient 3 ./internal/<pkg>`), then hand-applied mutants for every survivor in verification code (`/tmp/mut/hand.sh FILE LINE FROM TO`: apply one textual mutation, run the package tests, restore). A hand mutant counts as killed only when the unmutated package passed first. Mobile-ID and Web eID were done earlier: `mutation-mobileid-2026-11-20.md` (99.01 %), `mutation-webeid-2026-11-20.md` (98.90 %).

## gremlins runs (before the new tests)

| Package | Killed | Lived | Test efficacy | Mutator coverage |
|---|---|---|---|---|
| internal/smartid (incl. sign.go; v2 mutants also listed) | 386 | 32 | 92.34 % | 69.32 % |
| internal/signapi | 35 | 6 | 85.37 % | 71.93 % |
| internal/smartid/v2 | 77 | 11 | 87.50 % | 73.33 % |
| internal/eudi (first run) | 165 | 38 | 81.28 % | 71.23 % |
| internal/eudi (second run, after the status/sdjwt tests) | – | 17 | 92.06 % | 70.63 % |
| internal/smartid/v2 (second run, after its tests) | – | 3 | 96.63 % | 73.55 % |
| internal/oidc | 258 | 51 | 83.50 % | 97.17 % |
| internal/web | 102 | 52 | not reported – the run was cut off when the cloud environment restarted | – |

"NOT COVERED" mutants are code no test reaches; gremlins does not count them in efficacy. They were not all triaged; the gaps are mostly rendering, defaults and error branches.

## Survivors killed with new tests (hand-verified)

Test files: `internal/smartid/mutation_sign_test.go`, `internal/signapi/signapi_test.go` (tail), `internal/smartid/v2/mutation_gaps_test.go`, `internal/eudi/mutation_gaps_test.go`, `internal/oidc/mutation_gaps_test.go`, `internal/web/mutation_gaps_test.go`.

- smartid: sign.go 123, 204, 230, 254; verify.go 118; status.go 56, 123; trust.go 32, 81 (×3); method.go 63, 137; client.go 371 (`s <= 600`) – 15 killed.
- signapi: 82, 242, 279, 294, 345 – 5 killed. The 345 mutant also exposed a real defect: the signing job retried a failing upstream in a tight loop. Fixed with backoff (TestFailingUpstreamIsNotHammered).
- smartid/v2: method.go 82; v2.go 71, 88, 119, 172, 225, 293, 294 – 8 killed.
- eudi: jws.go 117; sdjwt.go 79, 102, 251, 294, 332, 345, 349, 370; status.go 49, 63, 64, 101 (×3), 117, 118, 121; method.go 73, 74, 76, 218, 223, 263, 304 – 25 killed.
- oidc: clients.go 74, 110, 112, 164, 169, 208, 267, 281, 289 (×3); keys.go 69, 72, 100, 228, 269, 277; provider.go 93, 99, 102, 105 (×2), 261, 264, 347, 382 (×2), 532, 593 (×2), 640, 660; sealed.go 107, 130 (×2), 133 (×2); subject.go 39, 49 (×2) – 41 killed. The clients.go 208/267 survivors were real gaps: no test showed that a body `client_id` that differs from the authenticated client is refused.
- web: cookie.go 29, 34, 46; flow.go 105; limits.go 38, 52, 63, 68, 97; web.go 91 – 10 killed.

## Remaining survivors, each justified

| Location | Mutant | Why it survives |
|---|---|---|
| smartid client.go:371 `s >= 0` → `s > 0` | boundary | Equivalent: Retry-After 0 gives a zero delay either way. |
| smartid errors.go:32 | negation | Only changes the error message text, not the outcome. |
| smartid session.go:92 `el < 0` | boundary | Equivalent: at 0 both branches yield 0 elapsed seconds. |
| smartid method.go:45 | arithmetic on the default long-poll | Timing default only; no verification effect. |
| smartid method.go:81 | default UI language | Cosmetic. |
| smartid method.go:218 `len(verifier) > 256` | boundary | A 256-byte Web2App verifier is never produced (43-byte values); the cap is a DoS guard. |
| smartid recorder.go:75, 96 | HTTP timeout arithmetic | Capture tooling for live fixtures, not on the login path. |
| smartid/v2 method.go:29 | default long-poll | Timing default only. |
| smartid/v2 method.go:126 | Destroy sets a final result | Equivalent: the destroyed session already makes Poll fail (TestDestroyBeforeResult passes either way). |
| smartid/v2 v2.go:285 | Content-Type header only when a body exists | The fixture ignores the header; no verification effect. |
| eudi jws.go:45, sdjwt.go:63, status.go:112/113 | size-cap boundaries (one byte) | No valid JWS or presentation can be padded to exactly the cap; the caps are DoS guards. The status-token cap boundary is pinned by TestStatusSchemeAndSizeCap. |
| eudi status.go:56 | default status client timeout | Timing default only. |
| eudi method.go:280 | MaxPresentation boundary | As above. |
| eudi method.go:335 (×4) | validity of the self-signed demo verifier certificate | Demo-only identity generation; the wallet simulator does not check it. |
| oidc provider.go:400 (×2) `maxAge := -1` | value never read | Equivalent: max_age is always met, so the value is unused. |
| oidc provider.go:445 | error page without a frontend | Fallback rendering branch; the real wiring always sets a frontend. |
| oidc provider.go:667 `len(h) > 7` | boundary | Equivalent: a header of exactly "Bearer " leaves an empty token, which is refused. |
| oidc sealed.go:66 `s.current++` | ++ → -- | Equivalent: any new version differs from the old one, and the key map is replaced. |
| oidc sealed.go:103 `len(tok) > 8192` | boundary | DoS cap; genuine tokens are far shorter. |
| oidc subject.go:118 | migration declaration negation | Not triaged in time. Migration is a startup-time operator declaration, covered by the existing migration tests; listed as open. |
| web limits.go:64 `>` → `>=` | clamp at Burst | Equivalent: clamping an equal value changes nothing. |
| web access.go, render.go, other web.go lines | drain grace timing, QR image drawing, locale links, chooser defaults | UI rendering and timing, not verification. web.go:262 (`startBy` = now + 60 s, the start window) was not triaged and is listed as open. |

## Open (disclosed, not justified as equivalent)

- Closed on feat/final-pass: oidc subject.go:118 (TestSubjectLockMigrationMustMatch, 4 hand mutants killed) and web web.go:262 (TestCreatedFlowStartWindow, 2 killed).
- The internal/web gremlins run did not finish, so web survivors after web.go:286 are unknown.
- Not run on internal/mobileid or internal/webeid in this pass; their earlier results are in the files linked at the top.
