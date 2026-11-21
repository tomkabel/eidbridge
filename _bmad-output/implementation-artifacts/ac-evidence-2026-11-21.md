# Acceptance-criteria evidence matrix (2026-11-21)

Branch `feat/final-pass`, HEAD `a3be708`. Source: `_bmad-output/planning-artifacts/epics.md` (30 stories, 8 epics, plus the "Child-story decomposition (owner override 2026-11-20)" for 5.1, 6.1, 6.2, 8.1). Gate IDs come from `_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-20.md`.

## Method and limits

- Scored: every bullet or Given/When/Then criterion under each story, including the "Architecture remediation AC" and "RV resolution AC" lists and the child-story "done when" conditions. The prose line "And – reconciliation and safety" is guidance, not scored (items from it are named only where a test or doc clearly answers it).
- Evidence was read, not just listed. Tests were located with `grep` and their bodies read. Only three things were executed: `python3 scripts/check_spec_pins.py` (PASS), `python3 tools/check-arch-trace --skip-mermaid` (PASS), and one narrow `go test -count=1 -run '<smartid verify tests>' -coverprofile ./internal/smartid` (ok; `Verify` and `VerifyContext` 100.0 % covered by that subset). The full suite was not run (a fuzzer is using the CPU). "Passes in CI" rests on GitHub Actions results read-only through `gh run list` / `gh run view --log` / `gh api` on 2026-11-21: CI on `main` (870a4c4) and on `feat/full-build` (a3ae156) is green in every job. The four local commits after that (2d5ea37, b0bc46e, ce093ba, a3be708) are not pushed and have no CI run.
- Classes: MET (evidence read and it checks the criterion), GATE (needs something in the sprint-change proposal's unmet-gate tables), PARTIAL (some evidence, named gap), MISSING (none found).
- "Named test absent" means the AC names a test function that does not exist. Where the criterion is checked inside another test (a comment labels the section), the row is MET and says so; where the behaviour is not fully checked the row is PARTIAL.
- Observed changes against the proposal (read-only GitHub API, 2026-11-21): private vulnerability reporting is enabled (gate H-10 was recorded as unmet); Dependabot has opened PRs #38–#45 (part of H-01); `main` has no branch protection and no rulesets (H-12 stays open); no tags exist (H-01 tagging stays open); `live-demo.yml` has never run (H-17 stays open). `sprint-status.yaml` still shows every story as `backlog` (last updated 2026-11-18), which contradicts the proposal's tracking rule.

## 1.1 Add unofficial-project notice, trademark policy and clean-room rules

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Disclaimer in README, login page template, image labels | MET | `README.md:7`; `internal/web/templates/layout.html:21` + `internal/web/i18n/en.json` `footer.unofficial`, checked by `internal/web/web_test.go:TestDemoBannerOnLoginPage` ("Not affiliated with"); `Dockerfile:16` and `Dockerfile.goreleaser:12` set `org.opencontainers.image.description`; `internal/docscheck/docs_test.go:TestRequiredDocsLinked` checks the README notice. Commit aee3db0. |
| 2 | `docs/legal.md` and `CONTRIBUTING.md` merged and linked from README | MET | Files exist (41 and 23 lines); `README.md:13`; `internal/docscheck/docs_test.go:TestRequiredDocsLinked` |
| 3 | DCO check enabled on PRs | GATE (H-12) | `.github/workflows/dco.yml` exists and ran green on PRs (Dependabot PRs); `main` has no branch protection or ruleset, so it is not a required check. Legal review is also open (H-12). |
| 4 | CI check: no copied spec text under `docs/spec-pins/` | MET | `scripts/check_spec_pins.py` (key whitelist, 600-char value cap, 240-char README lines; run here: PASS); `.github/workflows/ci.yml` job `spec-pins` (green on main) |

Verdict: MET-EXCEPT-GATES (item 3: H-12).

## 1.2 Scaffold Go module with CI, licence checks and release automation

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `go build/vet/test` pass locally and in CI | MET | `ci.yml` jobs `lint` (vet), `test` (`go test -race ./...`), `build` (4 targets): all success on main 870a4c4 and feat/full-build a3ae156 (`gh run view`). Not re-run locally here. Last 4 local commits have no CI run. |
| 2 | CI fails on unformatted code and on a disallowed licence | MET | `ci.yml` `lint` step `gofmt -l` exits 1 on output; job `licenses` runs `go-licenses check ./... --disallowed_types=forbidden,restricted,reciprocal,unknown` (green). Failure path read in config, not demonstrated with a bad input. |
| 3 | Tag `v0.0.1-rc1` produces Release binaries, `checksums.txt`, pullable GHCR image | GATE (H-01) | `.github/workflows/release.yml` and `.goreleaser.yaml` exist; local snapshot in `_bmad-output/implementation-artifacts/evidence/release-local-2026-11-20.md` (archives, `checksums.txt`, SPDX SBOMs). No tags exist; tagging and GHCR publication are owner actions. |
| 4 | Image < 20 MB, non-root | MET | `ci.yml` job `docker` (size gate 20000000 bytes, root check; green on main); `release-local-2026-11-20.md` (14303474 B, user 65532) |
| 5 | Dependabot opens a PR on a pinned dependency bump | MET | `.github/dependabot.yml`; `gh api repos/tomkabel/eidbridge/pulls` shows PRs #38–#45 by `dependabot[bot]` (gomod, actions, pip) on 2026-11-21. Gate H-01 lists this as unmet; it now appears closed. |
| 6 | README CI badge | MET | `README.md:3` |
| A16 | `tools/check-arch-trace` fails CI on an open finding | MET | `ci.yml` job `arch-trace` (green on main); `python3 tools/check-arch-trace --skip-mermaid` run here: all PASS |

Verdict: MET-EXCEPT-GATES (item 3: H-01).

## 1.3 Redact personal identity codes at the log sink

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Table-driven tests per identifier format and PEM/base64 | MET | `internal/logx/logx_test.go:TestRedactsIdentifierFormatsInMessages` and `:TestRedactsIdentifierFormatsInAttrValues` over `leakCases` (EE/LV/passport/IDC semantics ids, document number, bare EE/LT/LV codes, E.164, PEM, long base64, base64url, JWT); `:FuzzRedactNeverLeaksDigitsRuns`; `:TestWrappedErrorsRedacted`; `:TestDebugLevelGetsSameRedaction` |
| 2 | Full fixture login at DEBUG; logs contain no personal code, cert or signature | MET | `cmd/eidbridge/integration_test.go:TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData` (QR and notification, checks personal code, cert slices, signature, code, tokens against captured logs); also `:TestWebEIDLoginThroughBridge` log check |
| 3 | CI `grep` step reviewed: no raw logging calls | MET | `ci.yml` job `pii-logging-grep` (fails if hits appear in `slog.`/`log.` calls; green on main) |
| 4 | `docs/security.md` documents what is logged per level | MET | `docs/security.md` section "What is logged at each level" (ERROR/WARN/INFO/DEBUG table and the never-logged list) |

Verdict: ALL-MET.

## 1.4 Spike Smart-ID v3 device-link login against the public demo env

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `go run ./cmd/sidspike` exits 0 with `AUTHENTICATED` and verified cert, or ADR documents fallback | MET | `docs/adr/0001-spike-outcome.md` records the observed run (`AUTHENTICATED ... chain=verified signature=verified`) against `sid.demo.sk.ee` through SK's automated testing interface; `cmd/sidspike/main.go` uses `logx` at DEBUG; commit b58aaad. The phone step was simulated; a human demo-app run is NOT RUN (gate G-R0 stays open for that). Not re-run here (network). |
| 2 | Captured request/response pairs saved under `internal/smartid/testdata/` | MET | `internal/smartid/testdata/live/{qr-ok,qr-refused,web2app-ok,notification-ok,notification-refused,notification-wrong-vc}`; `internal/smartid/replay_test.go:TestReplayLiveFixturesVerifyOffline`, `:TestReplayTamperedLiveResponsesFail` |
| 3 | ADR states whether the demo env has a scriptable CI endpoint | MET | `docs/adr/0001-spike-outcome.md` table row "Scriptable CI endpoint: Yes" |

Verdict: ALL-MET (live-evidence disclosure under G-R0: no human demo-app run, poll quota, `TIMEOUT` duration and callback replay not measured, per the ADR).

## 2.1 Implement Smart-ID RP API v3 client with signature verification

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `go test ./internal/smartid/` passes on recorded fixtures, no network | MET | `internal/smartid/replay_test.go:TestReplayLiveFixturesVerifyOffline`, `:TestReplayAuthCodeKnownAnswer`; `internal/smartid/verify_test.go:TestSyntheticPositiveAllFlows`; package green in CI |
| 2 | Negatives: tampered signature, wrong challenge, expired cert, untrusted chain, lower level | MET | `internal/smartid/verify_test.go:TestVerifyNegativePerStep` (rows "s9 tampered signature", "s9 wrong challenge", "s4 expired cert", "s4 untrusted chain", "s7 level advanced/unknown/missing"); `internal/smartid/pr31_level_test.go:TestPR31V3CertificateLevelBoundToPolicies` |
| 3 | Live test only when `EIDBRIDGE_LIVE=1` | MET | `internal/smartid/live_test.go:TestLiveDemoQRAuthentication` (skips unless `EIDBRIDGE_LIVE=1`, line 20) |
| 4 | Fuzz test for response JSON parsing | MET | `internal/smartid/verify_test.go:FuzzParseStatus` (also asserts a fuzzed body never verifies) |
| 5 | Coverage of `Verify` >= 90 % | MET | Spot check run here: `internal/smartid/verify.go` `Verify` 100.0 %, `VerifyContext` 100.0 % (subset of tests, `-coverprofile`) |
| E02a | `endResult` table: refusal→refused, timeout→expired, other→failed | MET | `internal/smartid/verify_test.go:TestEndResultMappingExhaustive` |
| E02b | Unknown/stale/unreachable revocation → `failed(status_unavailable)`; no fetch to unlisted host | MET | `internal/smartid/verify_test.go:TestRevocationUnavailableFailsFlow`; `internal/revocation/revocation_test.go:TestOnlyAllowListedHostsContacted`, `:TestStaleWrongSignerAndHTTPFailuresFail`; `internal/revocation/pr31_test.go:TestPR31UnknownIsTerminal` |
| E02c | RSASSA-PSS SHA-256+, EKU profiles, `shareMdClientIpAddress=false`, poll/OCSP/CRL timeout, size, no-redirect, allow-list | PARTIAL | Named test `TestVerificationParametersAndStatusFetchLimits` is absent. Covered: PSS and SHA-3/PKCS1 rejection and EKU rows in `verify_test.go:TestVerifyNegativePerStep`; poll limits in `internal/smartid/client_test.go:TestHTTPErrorMappingAndLimits` (redirect, 70 KiB body, timeoutMs clamp); OCSP/CRL size and timeout in `internal/revocation/revocation_test.go:TestSizeCapAndTimeout`. Missing: no test asserts `shareMdClientIpAddress=false` is sent (set in `internal/smartid/client.go:184` and `sign.go:138`); no redirect test on the OCSP/CRL fetch path. |

Verdict: GAPS – E02c: named test absent, `shareMdClientIpAddress=false` untested, no no-redirect test for OCSP/CRL fetches.

## 2.2 Pin RP API TLS certificates and make trust anchors configurable

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `httptest` TLS server: matching pin passes, mismatching fails | MET | `internal/tlspin/tlspin_test.go:TestMatchingPinSucceedsMismatchFails` (also checks error names the observed pin) |
| 2 | Two pins, either accepted | MET | `internal/tlspin/tlspin_test.go:TestPinRotationEitherAccepted` |
| 3 | Production refuses empty pin set unless `disabled` set explicitly, with warning | MET | `internal/tlspin/tlspin_test.go:TestTLSPinsInvalidValuesFail` (production `""` rejected; demo `disabled` warns); `internal/config/config_test.go:TestPinPolicyThroughConfig` |
| 4 | `docs/security.md` documents pin and CA bundle updates | MET | `docs/security.md` sections "Update pins after an RP API certificate renewal" and "Update authentication CA bundles" |
| E17a | Production `disabled` without ack fails; with ack starts with warning and deviation record | MET | `internal/tlspin/tlspin_test.go:TestPinDisableRequiresAcknowledgement`; `internal/config/config_test.go:TestPinPolicyThroughConfig` (Deviations and Warnings set) |
| E17b | Supersede: production `disabled` alone fails | MET | same tests |
| E17c | Unset/empty/unparsable/no current pin fails in both modes; demo `disabled` warns | MET | `internal/tlspin/tlspin_test.go:TestTLSPinsInvalidValuesFail`; `:TestDisabledPinsKeepCAAndHostnameValidation` (disable never skips CA or hostname checks) |

Verdict: ALL-MET.

## 2.3 Define a method-neutral authenticator interface for eID backends

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Smart-ID wrapped as `authn.Method`; OIDC imports only `internal/authn` | MET | `internal/smartid/method.go` (adapter); `cmd/eidbridge/integration_test.go:TestOIDCAndWebImportOnlyAuthn` (`go list -deps` of `internal/oidc` and `internal/web` against smartid/mobileid/webeid/eudi) |
| 2 | `authntest.Run(t, method)` passes for Smart-ID with fixtures | MET | `internal/smartid/method_test.go:TestSmartIDMethodContract` |
| 3 | Fake method proves a second backend needs no OIDC changes | MET | `internal/authn/authn_test.go:TestRegistryContractFakeMethod`; `internal/oidc/methods_test.go:TestMethodsFilteredByACRValuesAndClient` (two-method env) |
| 4 | Interface documented in `docs/architecture.md` with versioning note | MET | `docs/architecture.md:23` ("internal and may change before v1.0") |
| R | Registry contract with fake method (supersedes chooser sentence) | MET | `internal/authn/authn_test.go:TestRegistryContractFakeMethod` (duplicate and empty registry rejected) |

Verdict: ALL-MET.

## 2.4 Expose eID logins as a standard OpenID Connect provider

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Tests cover discovery, code exchange, PKCE failure, replay, wrong redirect URI, expired code | MET | `internal/oidc/flow_test.go:TestDiscoveryDocument`, `:TestCodeExchangeAndGoOIDCValidation`, `:TestPKCEFailure`, `:TestCodeReplayAndUserinfoRevocation`, `:TestWrongRedirectURIAndExpiredCode` |
| 2 | ID token validates with `coreos/go-oidc` | MET | `internal/oidc/flow_test.go:TestCodeExchangeAndGoOIDCValidation` (imports `go-oidc/v3`, verifies per client) |
| 3 | Discovery document valid over the real binary | MET | `cmd/eidbridge/integration_test.go:TestDiscoveryOverRealWiring` (required fields present) |
| 4 | OIDF "Basic OP" plan run locally; results in `docs/conformance.md` | MET | `docs/conformance.md` (suite digest/commit pinned, config plan 1 PASSED; Basic 2 PASSED, 27 FAILED, 6 SKIPPED) and `_bmad-output/implementation-artifacts/evidence/conformance-2026-11-20.md`. The criterion asks for run and record; the failures (mandatory PKCE, no screenshot step, `client_secret_post`) are disclosed there. Not a certification. |
| A02a | Userinfo from AEAD-sealed token, no claim cache | MET | `internal/oidc/adr_test.go:TestUserinfoFromSealedAccessToken` |
| A03a | `sub` is HMAC-SHA256(K_sub…), never raw/plain-hashed code | MET | `internal/oidc/adr_test.go:TestSubIsKeyedHMACNotPersonalCode` (fixed vectors) |
| A04 | K_sub rotation: `sub` and `previous_sub`, versioned | MET | `internal/oidc/adr_test.go:TestSubKeyVersionMigration` |
| A06a | `private_key_jwt` with `jwks_uri` rejected, no fetch | MET | `internal/oidc/adr_test.go:TestPrivateKeyJWTRejectsJWKSURI` (registration rejected; no fetch code path read in `clients.go`) |
| A07a | Unprovable `acr_values` → `unmet_authentication_requirements` | MET | `internal/oidc/adr_test.go:TestAuthorizeUnprovableACRFails` |
| E07a | Concurrent exchange: exactly one winner | MET | `internal/oidc/flow_test.go:TestConcurrentCodeExchangeSingleWinner`; `internal/store/codes_test.go:TestConcurrentCodeExchangeSingleWinner` |
| E08a | Failed PKCE/client/redirect still consumes code | MET | `internal/oidc/flow_test.go:TestFailedExchangeStillConsumesCode`; `internal/store/codes_test.go:TestFailedExchangeStillConsumesCode` |
| E13a | Retired key persisted and in JWKS after restart | MET | `internal/oidc/adr_test.go:TestRetiredKeysSurviveRestart` |
| E14a | `sub_mode`/`sector_id`/K_sub change rejected without migration | MET | `internal/oidc/adr_test.go:TestSubKeyOrModeChangeNeedsMigration`; `internal/oidc/mutation_gaps_test.go:TestSubjectLockMigrationMustMatch` |
| E22 | RS256/ES256 per client; unsupported alg fails startup | MET | `internal/oidc/adr_test.go:TestIDTokenAlgPerClient` |
| A07b | `iss` on every authorization response; discovery flag | MET | `internal/oidc/adr_test.go:TestAuthorizeResponseCarriesIss`; `internal/oidc/flow_test.go:TestDiscoveryDocument` (`authorization_response_iss_parameter_supported`) |
| A07c | `prompt=none`→`login_required`; `max_age`→`auth_time`; `claims`/`request`/`request_uri` rejected | MET | `internal/oidc/adr_test.go:TestAuthorizePromptAndMaxAge` |
| A07d | Unregistered client/redirect → error page, no redirect; 303 after POST | MET | `internal/oidc/adr_test.go:TestInvalidClientRendersErrorPageAnd303` (400, no Location); 303 after POST asserted in `internal/web/web_test.go:TestUnknownFlowHandleRedirectsAccessDenied` and `:TestWeb2AppCallbackBinding` |
| A02b | `Cache-Control: no-store`; userinfo header only | MET | `internal/oidc/adr_test.go:TestTokenAndUserinfoNoStoreHeaderOnly`; `internal/oidc/mutation_gaps_test.go:TestUserinfoRefusesTokenInBody` |
| E14b | Production without K_sub or version fails | MET | `internal/config/config_test.go:TestProductionFailsWithoutSubKey` |
| A02c | Scope→claims, missing `openid`→`invalid_scope`, names only when in cert | MET | `internal/oidc/adr_test.go:TestScopeToClaimsMapping` |
| A06b | `private_key_jwt` aud/iss/sub/exp/alg/jti rules, jti store bound | MET | `internal/oidc/adr_test.go:TestPrivateKeyJWTAssertionRules`; `internal/oidc/mutation_gaps_test.go:TestAssertionBounds`, `:TestJTIExpiryBoundaries` |
| A03b | Serial number parses only PNO/PAS/IDC, fixed vectors | MET | `internal/oidc/adr_test.go:TestSubParsesSerialNumberAndRejectsOtherForms` (vectors in `TestSubIsKeyedHMACNotPersonalCode`) |
| E08b | Wrong-then-correct leaves familyless tombstone; correct-then-wrong revokes family | MET | `internal/oidc/flow_test.go:TestFailedExchangeLeavesFamilylessTombstone`; `internal/store/codes_test.go:TestFailedExchangeLeavesFamilylessTombstone` |
| E08c | 256/128-bit values from `crypto/rand`; codes stored as SHA-256; constant-time compare | PARTIAL | Tested: code length 43 chars and epoch 22 chars in `internal/oidc/adr_test.go:TestRandomValueEntropyAndConstantTimeCompare`; `internal/store/codes_test.go:TestCodeEntropy`; SHA-256 keying in `:TestClaimSetKeyedByCodeHash`. Not tested: length/entropy of flow IDs, binding tokens, callback values, family IDs; constant-time comparison is code-inspection only (`ConstantTimeCompare` in 15 call sites), no test. |
| A07e | GET and POST validate identically; userinfo bearer in header only | MET | `internal/oidc/adr_test.go:TestAuthorizeAndUserinfoAcceptGetAndPost` |
| E07b | Loser deny-lists winner's family | MET | Named test absent as a function; checked as a labelled section of `internal/oidc/flow_test.go:TestConcurrentCodeExchangeSingleWinner` (winner's userinfo 401) and `internal/store/codes_test.go:TestConcurrentCodeExchangeSingleWinner` |
| A02d | Userinfo rejects `exp - iat` above max | MET | `internal/oidc/adr_test.go:TestUserinfoRejectsExpIatBeyondMaxLifetime`; `internal/oidc/mutation_gaps_test.go:TestCheckLifetimeBoundaries` |
| E13b | RSA ≥ 2048, ES256 P-256, kid rules, file mode 0600 | MET | `internal/oidc/adr_test.go:TestSigningKeyParametersAndFileMode` |
| A06c | One registered auth method; mixed → `invalid_client` | MET | `internal/oidc/adr_test.go:TestSingleRegisteredClientAuthMethod` |
| A07f | Parameter hygiene (repeats, redirect, response_type, state/nonce length, verifier length) | MET | `internal/oidc/adr_test.go:TestAuthorizeParameterHygiene`; `internal/oidc/mutation_gaps_test.go:TestStateNonceVerifierLengths` |
| RV1 | Replay at full capacity uses reserved tombstone | MET | `internal/store/codes_test.go:TestReplayAtFullCapacityUsesReservedTombstone` |
| RV2 | Concurrent client-assertion replay: exactly one insertion | MET | `internal/oidc/adr_test.go:TestConcurrentClientAssertionReplayRejected` |
| RV3 | Demo loopback redirect policy | MET | `internal/oidc/adr_test.go:TestDemoLoopbackRedirectPolicy` |
| RV4 | Sealed token epoch/version validation; restart rejects earlier tokens | MET | `internal/oidc/adr_test.go:TestSealedTokenEpochAndVersionValidation`; `:TestDenyListLifetimeSurvivesWallClockStep` (new sealer epoch rejects token) |

Verdict: GAPS – E08c: only code and epoch lengths tested; flow ID, binding token, callback value and family ID entropy and constant-time comparison have no test.

## 2.5 Wire eidbridge binary with login page, QR and Web2App flows

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `go run ./cmd/eidbridge --demo` serves QR on :8080 and completes login with the demo app | GATE (G-R0; H-14) | Fixture login: `internal/web/web_test.go:TestFullQRLoginAndCodeExchange`, `cmd/eidbridge/integration_test.go:TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData`, compose run in `release-local-2026-11-20.md` (login completed). Live through SK's automated testing interface: `cmd/eidbridge/live_test.go:TestLiveDemoBridgeLogin` (`EIDBRIDGE_LIVE=1`). A login with a human-approved Smart-ID demo app is NOT RUN. |
| 2 | Startup fails with clear error if production lacks RP UUID/name or signing key | MET | `cmd/eidbridge/integration_test.go:TestProductionDemoFlagExitsNonZero` (error names `EIDBRIDGE_RP_UUID`, `EIDBRIDGE_KEY_DIR`); `internal/config/config_test.go:TestProductionFailsWithoutRPIdentity` |
| 3 | axe-core: no serious violations | MET | `_bmad-output/implementation-artifacts/evidence/release-local-2026-11-20.md` "Accessibility" (`scripts/a11y.py`, axe 4.10.3, Chrome, all screens serious/critical = 0). Not run in CI. Screen-reader pass NOT RUN. |
| 4 | `docs/configuration.md` generated or checked in CI | MET | `ci.yml` job `docs` (`go run ./cmd/eidbridge config docs | diff`); `internal/config/config_test.go:TestConfigurationDocMatchesCode`; `cmd/eidbridge/integration_test.go:TestConfigDocsCommand` |
| A08a | Cap or bucket exhausted → 503 + `Retry-After`, no upstream session, no eviction | MET | `internal/web/web_test.go:TestOverflowReturns503WithRetryAfter` |
| A09a | One poller behind global semaphore; browser polls local state | MET | `internal/web/web_test.go:TestSinglePollerBoundsUpstreamConcurrency` |
| A10a | Cookie `__Host-eidb-<id>`, attributes, Max-Age from absolute deadline | MET | `internal/web/web_test.go:TestFlowCookieAttributes`; `internal/web/mutation_gaps_test.go:TestFlowCookieMaxAge` |
| A10b | Web2App callback binding (cookie, value, digest, verifier), restart page without cookie | MET | `internal/web/web_test.go:TestWeb2AppCallbackBinding`, `:TestWeb2AppTamperedCallbackFails`; `internal/smartid/replay_test.go:TestReplayAuthCodeKnownAnswer` |
| A11 | Strict CSP, `frame-ancestors 'none'`, no QR older than 3 s | MET | `internal/web/web_test.go:TestResponseHeadersAndQRRelay`; `cmd/eidbridge/redteam2_regression_test.go:TestBaseHeaders` |
| A13 | Readiness stays ready under saturation; not-ready only during drain | MET | `internal/web/web_test.go:TestReadinessIgnoresSaturation` |
| A14a | SIGTERM drain until code TTL or grace; flow verified 5 s before TTL still exchanges | MET | `internal/web/web_test.go:TestSigtermDrainsUntilCodeTTL` |
| E01a | `created` flow ends `failed`/`cancelled` on init failure or abandon, releases capacity | MET | `internal/web/web_test.go:TestCreatedFlowTerminatesOnInitFailOrAbandon`; `internal/web/mutation_gaps_test.go:TestCreatedFlowStartWindow` |
| E03 | Poll retries exhausted → `failed(retries_exhausted)`, later result never accepted | MET | `internal/web/web_test.go:TestPollRetryExhaustionFailsFlow` |
| E04 | Store full → 503, no eviction | MET | `internal/web/web_test.go:TestStoreFullNeverEvicts`; `internal/store/codes_test.go:TestStoreFullNeverEvicts` |
| E05a | Reserved code slot guarantees a code at cap | MET | `internal/web/web_test.go:TestCodeSlotReservedAtFlowCreation`; `internal/store/codes_test.go:TestCodeSlotReservedAtFlowCreation` |
| E06 | Late result discarded, secrets zeroed, flow not resurrected | MET | `internal/smartid/method_test.go:TestLateResultDiscardedAndSecretsZeroed`; `internal/smartid/mutation_sign_test.go:TestFinishZeroesSessionSecrets` |
| E11 | Two tabs, independent flows and cookies | MET | `internal/web/web_test.go:TestTwoTabsRunIndependentFlows` |
| E19 | Readiness ignores transient capacity | MET | Named test absent as a function; labelled section inside `internal/web/web_test.go:TestReadinessIgnoresSaturation` (200 while saturated) |
| E20 | Lost flow handle → error page and `access_denied` to cookie redirect_uri, revalidated | MET | `internal/web/web_test.go:TestUnknownFlowHandleRedirectsAccessDenied` (also checks forged cookie cannot redirect to an unregistered URI) |
| E05b | Tombstone cap → 503 at flow creation | MET | Named test absent as a function; labelled section in `internal/web/web_test.go:TestCodeSlotReservedAtFlowCreation` (second authorize gets 503 + `Retry-After` when the code store is full) |
| E10 | Terminal states carry return link (`access_denied`/`server_error`, `iss`, `state`) and clear cookie | MET | `internal/web/web_test.go:TestTerminalResponseReturnsErrorAndClearsCookie` (refused, expired, failed) |
| A10c | `flow.offered` stored before session creation; QR omits `initialCallbackUrl` | MET | `internal/web/web_test.go:TestFlowTypeChosenBeforeSessionCreation`; QR omission per `docs/adr/0001-spike-outcome.md` and live replay `internal/smartid/replay_test.go:TestReplayLiveFixturesVerifyOffline` |
| A10d | Fifth flow cancels oldest under lock | MET | `internal/web/web_test.go:TestFlowCookieCapFour` |
| A10e | Only the callback response redirects; other tab shows notice | MET | `internal/web/web_test.go:TestOnlyCallbackResponseRedirects` |
| E01b | Reload renders stored state; cancel needs POST with binding token | MET | `internal/web/web_test.go:TestReloadRendersStoredStateAndCancelNeedsBindingToken` |
| A09b | No free poll slot → 503, flow stays `created` | MET | `internal/web/web_test.go:TestNoPollSlotReturns503AndFlowStaysCreated` |
| A08b | Per-target-identity bucket; generic message for init errors | MET | `internal/web/web_test.go:TestPerTargetIdentityBucket` |
| A10f | Every flow-scoped endpoint without cookie → restart page, no state change | MET | `internal/web/web_test.go:TestEveryFlowScopedEndpointRequiresCookie` (page, qr.png, status, cancel, continue, start). The Web eID `/browser` endpoint is not in that list (see 5.1-b). |
| E06b | OK poll and callback in either order verify exactly once | MET | `internal/web/web_test.go:TestWeb2AppOKAndCallbackOrderEitherWay`; `internal/smartid/method_test.go:TestWeb2AppOKAndCallbackOrderEitherWay` |
| A09c | Concurrent QR loads create one session | MET | `internal/web/web_test.go:TestConcurrentQRPageLoadsCreateOneSession` |
| A14b | Drain keeps token and userinfo serving | MET | Named test absent as a function; labelled section in `internal/web/web_test.go:TestSigtermDrainsUntilCodeTTL` (token exchange succeeds during drain; userinfo during drain not asserted) |
| RV1 | `TestSessionInitTransportBounds`: init timeouts, oversized body, redirects fail the flow; uncertain init not retried | PARTIAL | Named test absent. Oversized body and no-redirect are asserted for status polling in `internal/smartid/client_test.go:TestHTTPErrorMappingAndLimits`; init failure ending the flow in `internal/web/web_test.go:TestCreatedFlowTerminatesOnInitFailOrAbandon`. Not tested: device-link and notification init timeouts, oversized/redirected init responses, "no blind retry of uncertain init". |
| RV2 | Target bucket full map and churn | MET | `internal/web/web_test.go:TestTargetBucketFullMapAndChurn`; `internal/web/mutation_gaps_test.go:TestBucketIdleEviction` |
| RV3 | `TestCodeCapacityUnderSustainedExchange`: measure reservations, codes, tombstones across retention window; index memory sizing | PARTIAL | Named test absent; nothing measures sustained exchange or index memory. Slot reclaim is covered by `internal/store/codes_test.go:TestTombstoneAndReservationExpiryFreeSlots` and `:TestSweeperDropsExpiredEntries`; full-capacity behaviour by `:TestReplayAtFullCapacityUsesReservedTombstone`; a 10,001-flow overload was run black-box in `_bmad-output/implementation-artifacts/evidence/redteam-1-2026-11-20.md` row 9. No sizing measurement. |
| RV4 | Callback-first retains verifier until signed result | MET | `internal/web/web_test.go:TestCallbackFirstRetainsVerifierUntilSignedResult` |
| RV5 | Retired binding cannot disrupt completion | MET | Named test absent as a function; labelled section in `internal/web/web_test.go:TestOnlyCallbackResponseRedirects` (old tab gets `other_tab`, cannot continue or cancel, state stays `verified`) |
| RV6 | Absolute flow deadline and eviction race | MET | `internal/web/web_test.go:TestAbsoluteFlowDeadlineAndEvictionRace`; `internal/web/mutation_gaps_test.go:TestFlowCeilingFreedOnTermination` |

Verdict: GAPS – item 1 is GATE (G-R0, H-14); RV1 (init transport bounds) and RV3 (sustained-exchange capacity measurement) are PARTIAL.

## 2.6 Enforce no telemetry and zero data retention by default

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | After login and after TTL expiry the store holds zero entries for the flow | MET | `internal/web/web_test.go:TestStoreZeroEntriesAfterLoginAndTTL`; `internal/store/codes_test.go:TestSweeperDropsExpiredEntries`; commit 6ce26d4 |
| 2 | CI network test: container with egress blocked except mock RP API completes a login, no other egress | MISSING | No test, script or CI job blocks egress. `grep` for egress/`--network none`/internal networks found only the Dockerised IdP harness (`--network host`) and the WordPress example. `scripts/e2e-demo.sh` runs against the fixture but does not block or observe other egress. `internal/smartid/method_test.go:TestNotificationInvalidInputNoEgress` only checks invalid input sends no request. |
| 3 | `SECURITY.md` and `docs/security.md` present and linked from README | MET | Both exist; `README.md:13-14`; `internal/docscheck/docs_test.go:TestRequiredDocsLinked` |
| 4 | GitHub private vulnerability reporting enabled | MET | `gh api repos/tomkabel/eidbridge/private-vulnerability-reporting` returned `{"enabled":true}` on 2026-11-21 (read-only). Gate H-10 was recorded as unmet on 2026-11-20; the proposal and `sprint-status.yaml` have not been updated to match. |
| A01a | Claim set held plaintext in memory keyed by code hash, lifecycle table says so | MET | `internal/store/codes_test.go:TestClaimSetKeyedByCodeHash`; `docs/data-flow.md` lifecycle table |
| E09 | Replay marks reserved family tombstone revoked, no allocation; userinfo rejects | MET | Named test absent as a function; labelled section in `internal/oidc/flow_test.go:TestCodeReplayAndUserinfoRevocation`; `internal/store/codes_test.go:TestReplayAtFullCapacityUsesReservedTombstone` |
| E10 | Cookie cleared on every terminal state | MET | `internal/web/web_test.go:TestCookiesClearedOnEveryTerminalState` (cancelled) and `:TestTerminalResponseReturnsErrorAndClearsCookie` (refused, expired, failed) |
| E21a | TTLs use monotonic clock | MET | `internal/store/codes_test.go:TestTTLsUseMonotonicClock`; `internal/web/clock_test.go` (fake clock) |
| E21b | Userinfo honours monotonic deadline after backward wall step; restart rejects | MET | `internal/oidc/adr_test.go:TestDenyListLifetimeSurvivesWallClockStep` |
| A01b | Access logs hold only method and route template | MET | `internal/web/web_test.go:TestAccessLogOmitsCallbackQueryAndFlowIDs` |

Verdict: GAPS – item 2 MISSING (no egress-blocked network test in CI or scripts).

## 2.7 Warn on demo environment use and block demo credentials in prod

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Unit tests for each detection rule | MET | `internal/config/config_test.go:TestProductionRefusesDemoHostVariants`, `:TestModeInvariantMatrix`, `:TestDemoModeNormalizesHost`; `internal/config/signing_test.go:TestProductionRefusesAllZeroRPUUID`, `:TestProductionRefusesDemoSigningCA` |
| 2 | `EIDBRIDGE_MODE=production ./eidbridge --demo` exits non-zero with clear message | MET | `cmd/eidbridge/integration_test.go:TestProductionDemoFlagExitsNonZero` |
| 3 | Demo banner on login page (template test) | MET | `internal/web/web_test.go:TestDemoBannerOnLoginPage` |
| 4 | Demo-mode ID tokens contain `acr=demo` | MET | `internal/oidc/adr_test.go:TestScopeToClaimsMapping`; `cmd/eidbridge/integration_test.go:TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData` (`acr`, `eid_env` = demo) |
| 5 | `docs/keycloak.md` shows how to reject `acr=demo` (now `docs/idp/keycloak.md`) | MET | `internal/docscheck/docs_test.go:TestKeycloakDocStubRejectsDemoACR`; `docs/idp/keycloak.md:75` (tested on both Keycloak majors) |
| A12 | Production rejects `demo-` kid / fingerprint / deny-list; demo tokens use `/demo` issuer | MET | `internal/oidc/adr_test.go:TestProductionRejectsDemoKeyFingerprint`; `internal/oidc/mutation_gaps_test.go:TestDenyListFingerprints` |
| E16a | Mode invariant matrix; `mode` has no default | MET | `internal/config/config_test.go:TestModeInvariantMatrix` |
| E18 | Warn once on private peers without `trusted_proxies`; per-IP key is resolved IP | MET | `internal/web/web_test.go:TestProxyTrustWarningWhenAllPeersPrivate`; `internal/web/clock_test.go:TestClientIPTrustedProxies` |
| E16b | `http` issuer off localhost and env/mode disagreement fail startup | MET | `internal/config/config_test.go:TestProductionRejectsHTTPIssuerAndEnvMismatch` (issuer cases) and `:TestModeInvariantMatrix` (`EIDBRIDGE_SMARTID_ENV` vs mode rows, lines 89–116) |

Verdict: ALL-MET.

## 2.8 Support Smart-ID v3 notification-based authentication flow

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Fixture tests for notification create/poll/verify | MET | `internal/smartid/client_test.go:TestFixtureUpstreamNotification`; `internal/smartid/verify_test.go:TestSyntheticPositiveAllFlows`; `internal/smartid/testdata/live/notification-ok` replay |
| 2 | Response for a different identity than requested is rejected | MET | `internal/smartid/verify_test.go:TestVerifyNegativePerStep` ("s8 notification other person", "s8 notification by document mismatch"); `internal/smartid/method_test.go:TestIdentityMismatchFailsWithoutCode` |
| 3 | Invalid identity codes rejected locally without outbound request | MET | `internal/smartid/client_test.go:TestInvalidIdentityRejectedLocallyWithoutRequest`; `internal/smartid/method_test.go:TestNotificationInvalidInputNoEgress` |
| 4 | Entered identity codes never logged unredacted | MET | `cmd/eidbridge/integration_test.go:TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData` (notification leg with the typed code `40404040009`) |
| 5 | Live demo test behind `EIDBRIDGE_LIVE=1` | MET | `internal/smartid/live_capture_test.go:TestLiveCaptureFixtures` (notification ok/refused/wrong-vc scenarios, skips without `EIDBRIDGE_LIVE=1` and `EIDBRIDGE_CAPTURE=1`); results in `docs/adr/0001-spike-outcome.md` |
| E15 | Different account identity → `failed(identity_mismatch)`, no code | MET | `internal/smartid/method_test.go:TestIdentityMismatchFailsWithoutCode` |

Verdict: ALL-MET.

## 3.1 Document end-to-end personal data flow for integrator DPIAs

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `docs/data-flow.md` merged and linked from README and `docs/security.md` | MET | File (123 lines); `internal/docscheck/docs_test.go:TestRequiredDocsLinked` |
| 2 | Every claim emitted by `internal/oidc` appears in the table (CI test) | MET | `internal/docscheck/docs_test.go:TestDataFlowClaimsMatchCode` (compares `oidc.ClaimNames()` with the "Claims emitted" table; runs in `go test ./...` in CI) |
| 3 | Mermaid diagram renders on GitHub | MET | `ci.yml` job `docs` step "diagrams render" (`scripts/check_mermaid.sh docs/data-flow.md`, green on main) |
| A15 | Diagram has front channel, eID app leg, trust-boundary groupings | MET | `internal/docscheck/docs_test.go:TestDataFlowDocDiagramEdges` |

Verdict: ALL-MET.

## 3.2 Ship a zero-config docker compose demo with a sample relying party

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Clean clone: `docker compose up` reaches a QR page, no extra steps | MET | `docker-compose.yml` (optional `extra_ca` defaults to `/dev/null`); `release-local-2026-11-20.md` "Clean clone to completed demo login" (fresh `git clone`, stack up in 43 s). Run on the `feat/full-build` branch, not on current HEAD. |
| 2 | Manual demo-app scan completes, claims shown, under 5 minutes | GATE (H-14) | A human with the Smart-ID demo app is needed; scripted fixture login took 0.52 s (`release-local-2026-11-20.md`). |
| 3 | `scripts/e2e-demo.sh` runs in CI against the fixture upstream and passes | PARTIAL | Script exists and passed locally (`release-local-2026-11-20.md`: 43.4 s clone to verified claims). `.github/workflows/ci.yml` has no job that runs it (`grep e2e-demo .github/workflows/*.yml` finds nothing). |
| 4 | Demo banner visible | MET | `internal/web/web_test.go:TestDemoBannerOnLoginPage`; `scripts/e2e-demo.py` checks `"acr": "demo"` and the production RP refusal |

Verdict: GAPS – item 3: e2e-demo is not wired into CI. Item 2 is GATE (H-14).

## 3.3 Localize the login page for Estonian, Latvian, Lithuanian, English

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Every `en.json` key exists in all catalogs; CI fails on missing | MET | `internal/web/clock_test.go:TestLocaleCatalogParity` (all five locales, extra keys too) |
| 2 | `ui_locales=et` renders Estonian; unknown falls back | MET | `internal/web/web_test.go:TestUILocalesSelectsCatalog` |
| 3 | Display text beyond protocol limits rejected at config load | MET | `internal/config/config_test.go:TestInteractionDisplayTextLimits` |
| 4 | Native-speaker review noted in PR per language | GATE (H-16; Q-05; G-R2) | Catalogs exist for en, et, lv, lt, ru under `internal/web/i18n/`; no native review recorded. |

Verdict: MET-EXCEPT-GATES (item 4: H-16).

## 3.4 Add a maintenance runbook for upstream API, TLS and key changes

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `docs/api-tracking.md` and `CHANGELOG.md` merged | MET | Both exist (62 and 19 lines); commit baf3222 |
| 2 | Nightly workflow runs and auto-opens an issue on simulated pin mismatch | GATE (H-17) | `.github/workflows/live-demo.yml` (cron, `bogus_pin` dispatch input, issue create/comment step) and `scripts/pin-check.sh` are committed; the workflow has never run on GitHub (no run in `gh run list`). Also, demo pins are unverified (`docs/adr/0001-spike-outcome.md`). |
| 3 | Release checklist template `.github/ISSUE_TEMPLATE/upstream-change.md` | MET | File exists with change-type checklist |
| A05a | Emergency revocation drops key from JWKS, rotates sealing key, clients re-authenticate | MET | `internal/oidc/adr_test.go:TestEmergencyRevocationDropsKeyFromJWKS` (replacement key active, token from revoked key no longer verifies); drill steps in `docs/api-tracking.md:51` |
| E12 | Compromised key dropped immediately | MET | Named test absent as a function; labelled section in `internal/oidc/adr_test.go:TestEmergencyRevocationDropsKeyFromJWKS` |
| A05b | K_sub compromise: new version, `previous_sub` window, retire old version, notify clients | PARTIAL | `internal/oidc/adr_test.go:TestKSubCompromiseAndReplacementKey` only calls `TestSubKeyVersionMigration` (new version, `previous_sub`, window end). Retiring the old K_sub version and the "emergency revocation first activates a replacement" ordering for K_sub are not tested; client notification is a documented procedure only. |

Verdict: GAPS – A05b PARTIAL. Item 2 is GATE (H-17).

## 3.5 Add config-only IdP integration guides with e2e tests per IdP

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Keycloak guide on fresh container logs a user in via the demo env, verified manually once, screenshot in doc | GATE (H-15) | `docs/idp/keycloak.md` is verified by `test/e2e/keycloak_test.go:TestKeycloak` against the fixture upstream (green in CI on 26.8.2 and 25.0.6); no human demo-app run, no screenshot. |
| 2 | `go test -tags e2e ./test/e2e/...` passes for all four IdPs in CI with fixture upstream | PARTIAL | CI log of `idp-e2e` on main (run 44884732113): `TestKeycloak` PASS (two majors), `TestAuthentik` PASS, `TestZitadel` PASS, `TestOryKratos` SKIP. `test/e2e/ory_test.go:62-68` calls `t.Skip("e2e: NOT RUN ...")`: Kratos v26.2.0 never sends `nonce`, which the bridge requires. Ory is therefore not verified end to end. |
| 3 | Each guide lists the IdP version tested and the date | MET | `docs/idp/keycloak.md`, `authentik.md`, `zitadel.md` (image tags and digests, 2026-11-20); `docs/idp/ory.md` lists Kratos v26.2.0 and marks the e2e NOT RUN |
| 4 | README links each guide | MET | `README.md:16`; `internal/docscheck/docs_test.go:TestRequiredDocsLinked` |

Verdict: GAPS – item 2: Ory Kratos e2e is skipped in CI (NOT RUN, bridge requires `nonce`). Item 1 is GATE (H-15).

## 3.6 Add Django and FastAPI examples that log in through the bridge

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `pytest examples/` passes locally and in CI | MET | `examples/django/test_django_rp.py` and `examples/fastapi/test_fastapi_rp.py` (`test_full_login`, `test_state_tampering`, `test_issuer_mixup_refused_before_exchange`); `ci.yml` job `python` (green on main) |
| 2 | No eID-protocol code, only OIDC client configuration | MET | `grep -i 'smart-id|smartid|rp-api|ocsp|x509|signature'` over `examples/django/django_rp.py` and `examples/fastapi/*.py` finds none (outside tests) |
| 3 | Examples reject `acr=demo` when `PRODUCTION=1` | MET | `examples/django/test_django_rp.py:test_production_refuses_demo`; `examples/fastapi/test_fastapi_rp.py:test_production_refuses_demo` |

Verdict: ALL-MET.

## 4.1 Let users choose among multiple enabled eID methods

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Tests: `acr_values` filtering, `login_hint` preselect, per-client restriction, `amr` in token | MET | `internal/oidc/methods_test.go:TestMethodsFilteredByACRValuesAndClient` (acr filter and `only-mid` client), `:TestTokenCarriesAMRAndACRFromUsedMethod`; `internal/web/chooser_test.go:TestChooserAndLoginHint`, `:TestStartRefusesMethodNotOffered` |
| 2 | Single enabled method still skips the chooser | MET | `internal/web/chooser_test.go:TestNoChooserWithSingleMethod` |
| 3 | Accessible keyboard navigation across method choices | MET | `release-local-2026-11-20.md` "Rerun with two methods" (`scripts/a11y.py`: all 9 controls in main reachable by Tab, axe serious/critical 0). Not run in CI. |
| A17 | No chooser with exactly one method | MET | `internal/web/chooser_test.go:TestNoChooserWithSingleMethod` |
| E23 | Remember cookie naming a removed method is ignored | MET | `internal/web/chooser_test.go:TestRememberCookieIgnoredWhenMethodRemoved` |

Verdict: ALL-MET (gate G-20, demand, stays disclosed).

## 4.2 Add Mobile-ID authentication via the MID REST API

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `go test ./internal/mobileid/` with recorded fixtures incl. tampered signature and identity mismatch | MET | `internal/mobileid/replay_test.go:TestReplayLiveTamperedSignature`, `:TestReplayLiveIdentityMismatch`, `:TestReplayLiveOK`; `internal/mobileid/verify_test.go:TestVerifyNegatives` ("8 tampered signature", "7 other person"); `internal/mobileid/testdata/live/*.json`. Mutation efficacy 99.01 % (`evidence/mutation-mobileid-2026-11-20.md`). |
| 2 | `authntest.Run` passes | MET | `internal/mobileid/method_test.go:TestMethodContract` |
| 3 | `EIDBRIDGE_METHODS=smartid,mobileid` serves both on one login page | MET | `cmd/eidbridge/integration_test.go:TestSmartIDAndMobileIDOnOneLoginPage` |
| 4 | Data-flow doc updated with phone number field | MET | `docs/data-flow.md:53` (Phone number and personal code row), `:101` |

Verdict: ALL-MET (gate G-19: no live Mobile-ID demo run recorded for a human phone; `internal/mobileid/live_test.go` and `cmd/eidbridge/live_test.go:TestLiveDemoBridgeMobileID` are opt-in).

## 5.1 Add ID-card login via Web eID token validation in Go

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Vectors: valid, wrong origin, replayed nonce, expired cert, revoked (mock OCSP), untrusted CA | MET | `internal/webeid/validate_test.go:TestValidTokens`, `:TestValidationNegatives` (rows "wrong origin", "expired certificate", "revoked (mock OCSP)", "untrusted CA"), `:TestStatusUnknownFailsClosed`; `internal/webeid/method_test.go:TestReplayedNonce`, `:TestFailedTokenConsumesNonce` |
| 2 | Fuzz tests on token parsing | MET | `internal/webeid/validate_test.go:FuzzParseToken`; `:TestParseTokenRejects`; `internal/webeid/mutation_test.go:TestParserBoundaries` |
| 3 | Manual login with a test ID-card and Web eID extension documented | GATE (G-21) | `docs/adr/0005-web-eid.md` records it as NOT RUN (needs hardware). Stand-in extension Chrome run only: `scripts/webeid_browser_check.py`. |
| 4 | `authntest.Run` passes | MET | `internal/webeid/method_test.go:TestMethodContract` |
| 5.1-a | Strict parse, cert time/purpose/policy/chain, signature over `hash(origin)+hash(nonce)` for ES/PS/RS; each step has a negative test | MET | `internal/webeid/validate_test.go:TestValidationNegatives` (per-step rows), `:TestValidTokens`, `:TestParseTokenRejects`, `:TestASCIIOrigin`; `internal/webeid/mutation_test.go:TestTwoCertificateChain` (1.1 intermediates); mutation efficacy 98.90 % (`evidence/mutation-webeid-2026-11-20.md`) |
| 5.1-b | ≥ 256-bit single-use short-TTL nonce bound to the flow cookie; origin from config; wrong origin, replayed, expired nonce and other-browser submission fail | PARTIAL | Nonce length, uniqueness, https-origin requirement: `internal/webeid/method_test.go:TestNonceProperties`; TTL: `internal/webeid/mutation_test.go:TestNonceTTLBoundary`; wrong origin and replay: items above and `cmd/eidbridge/integration_test.go:TestWebEIDLoginThroughBridge`. Missing: no automated test posts a token to `/flow/{id}/browser` from a browser that lacks the flow cookie (`TestEveryFlowScopedEndpointRequiresCookie` does not list `/browser`; code in `internal/web/web.go:907` checks `lookup`/`accessCurrent`). Black-box coverage only: `evidence/redteam-2-2026-11-20.md` row 8 ("other flow id, CSRF"). |
| 5.1-c | OCSP via `internal/revocation`, unknown fails closed; revoked fails, good passes | MET | `internal/webeid/validate_test.go:TestValidationNegatives` ("revoked (mock OCSP)"), `:TestValidTokens` (good), `:TestStatusUnknownFailsClosed`; `internal/revocation/revocation_test.go:TestOCSPGoodRevokedUnknown`, `internal/revocation/pr31_test.go:TestPR31UnknownIsTerminal` |
| 5.1-d | `authn.Method` `browser` flow, contract suite, vendored MIT `web-eid.js`, CSP-compatible script, CSRF via form token | PARTIAL | Met: contract suite (`TestMethodContract`), CSP-compatible static script, form-token CSRF (`internal/web/web.go:910`, `cmd/eidbridge/integration_test.go:TestWebEIDLoginThroughBridge`). Not met: `web-eid.js` is not vendored. `docs/adr/0005-web-eid.md` and `internal/web/static/webeid.js` say a small reimplementation of the `postMessage` protocol is used instead (disclosed deviation). |
| 5.1-e | Hardware interop and external review (human) | GATE (G-21) | Recorded NOT RUN in `docs/adr/0005-web-eid.md`; no external security review (G-21, G-SEC). |

Verdict: GAPS – 5.1-b (no automated other-browser `/browser` test); 5.1-d (`web-eid.js` not vendored, reimplemented). Items 3 and 5.1-e are GATE (G-21).

## 6.1 Accept EUDI Wallet presentations via OpenID4VP as a login method

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Presentation from the EU reference wallet verified end to end in a test environment | GATE (G-22) | `docs/adr/0006-eudi-openid4vp.md:29` records interop with the reference or a national wallet as NOT RUN. Only the wallet simulator `internal/eudi/walletsim` was used (`cmd/eidbridge/integration_test.go:TestEUDIWalletLoginThroughBridge`). |
| 2 | Negatives: wrong nonce, revoked credential, untrusted issuer, missing key binding | MET | `internal/eudi/verify_test.go:TestVerifyNegatives` (rows "5 wrong nonce (replay)", "6 revoked (status list)", "2 untrusted issuer CA", "1 no key binding"); `internal/eudi/method_test.go:TestResponseNegatives` |
| 3 | `authntest.Run` passes | MET | `internal/eudi/method_test.go:TestMethodContract` |
| 4 | Docs state the bridge confers no regulatory compliance | MET | `docs/legal.md:20` |
| 6.1-a | Signed request object by reference, DCQL, nonce/state per flow, same-device link and QR, `direct_post` bound to flow; each parameter tested | MET | `internal/eudi/method_test.go:TestRequestObject` (response_mode, response_uri, 43-char nonce and state, claims list, `openid4vp://` payload with `request_uri`), `:TestSameDeviceNeedsResponseCode`, `:TestJunkResponsesDoNotEndFlow`; `cmd/eidbridge/redteam2_regression_test.go:TestEUDISameDeviceBoundToBrowser`, `:TestWalletResponseCannotEndOtherFlows` |
| 6.1-b | SD-JWT VC: issuer signature, disclosure digests, key-binding JWT, expiry, status list, claim ceilings; negative per step; parser fuzzed | MET | `internal/eudi/verify_test.go:TestVerifyNegatives` (steps 1–6), `:TestVerifyValidPresentation`, `:FuzzVerifyPresentation`, `:TestStatusRequiredAndMissingChecker`; `internal/eudi/mutation_gaps_test.go` (status widths, key usage, nesting, undisclosed array elements); `internal/eudi/status_freshness_test.go:TestStatusTimeClaims`, `internal/eudi/pr31_test.go:TestPR31StatusFreshness`; `TestIdentityMapping` for claim ceiling |
| 6.1-c | mdoc ISO 18013-5 verification (or recorded as not implemented with the gate) | PARTIAL | Not implemented. Recorded as not done in `docs/adr/0006-eudi-openid4vp.md:5,26` (the child story permits this outcome; the capability is absent). |
| 6.1-d | `authn.Method` (`same-device`, `qr`), config invariants, data-flow PID update, `amr` `eudi_pid`; contract suite and fixture wallet login | MET | `internal/eudi/method_test.go:TestMethodContract`; `internal/eudi/method.go:307` (`AMR: eudi_pid`); `internal/config/config_test.go:TestEUDIModeInvariants`, `:TestEUDIProductionLoads`; `cmd/eidbridge/integration_test.go:TestEUDIWalletLoginThroughBridge`; `docs/data-flow.md` PID rows |

Verdict: GAPS – 6.1-c mdoc not implemented (recorded). Item 1 is GATE (G-22).

## 6.2 Build an EUDI Wallet relying-party conformance test harness

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Runs against the bridge's EUDI method in CI and produces a JUnit report | PARTIAL | `cmd/eudi-conformance/main_test.go:TestHarnessAgainstBridge` builds and starts the bridge and runs every case; it runs in CI inside `go test -race ./...`. The JUnit report is only written when `-junit` is passed (`cmd/eudi-conformance/main.go:63`); no CI step passes it or uploads it. Reports exist as committed evidence from a local run: `_bmad-output/implementation-artifacts/evidence/eudi-conformance-junit.xml`, `eudi-conformance-report.md`, `eudi-conformance-run.txt` (all 17 cases PASS). |
| 2 | Core positive flow plus ≥ 10 negative cases | MET | `cmd/eudi-conformance/main_test.go:TestCatalog` (≥ 1 positive, ≥ 10 negative); `conformance/cases/001..017` = 1 positive and 16 negative |
| 3 | Each case links the spec section and version | MET | `cmd/eudi-conformance/main_test.go:TestCatalog` (every spec reference has `url` and `section`; `doc` carries the version, e.g. "OpenID4VP 1.0") |
| 6.2-a | Simulator and catalog (1 positive, ≥ 10 negative) | MET | `internal/eudi/walletsim/walletsim.go`; `conformance/cases/*.yaml`; `TestCatalog` |
| 6.2-b | Runner, JUnit XML and Markdown; every negative case rejected | MET | `evidence/eudi-conformance-run.txt`, `eudi-conformance-junit.xml`, `eudi-conformance-report.md`; `TestHarnessAgainstBridge` fails if any case does not match its expectation |

Verdict: GAPS – item 1: the JUnit report is not produced or published by CI. Gate G-23 (no real wallet) stays disclosed; the harness checks this project's reading of the pinned specs and is not certification.

## 7.1 Provide a native Keycloak identity provider SPI for eidbridge

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Jar deploys into `providers/`; provider appears in admin console | MET | `test/e2e/keycloak_spi_test.go:TestKeycloakSPI` mounts the jar at `/opt/keycloak/providers/` and asserts `/admin/realms` `serverinfo` `identityProviders` contains `eidbridge`; green in CI (26.8.2 and 25.0.6) |
| 2 | Testcontainers e2e login passes for the two latest Keycloak majors | MET | Same test: full login, one broker-created user, federated identity, `sub` mapping, `eid_acr` attribute, per-version subtests PASS in CI run 44884732113. Uses the repo's Docker harness (`test/e2e/harness_test.go`), not the Testcontainers library. |
| 3 | Docs explain when the plain OIDC guide is enough | MET | `docs/idp/keycloak-spi.md:63` ("When the plain OIDC guide is enough") |

Verdict: ALL-MET (gate G-24: no three user requests and no maintenance budget decision stay disclosed).

## 7.2 Publish a minimal Python client for Smart-ID RP API v3

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `pip install` from built wheel; `import eidbridge_rp` works | MET | `ci.yml` job `python` runs `pip install ./python` (builds a wheel) then `pytest python`; `python/tests/test_vectors.py` imports the package; `release.yml` `pypi` job runs `python -m build`. No explicit `python -c "import eidbridge_rp"` step. |
| 2 | pytest against shared fixtures incl. negative cases | MET | `python/tests/test_vectors.py:test_live_ok`, `:test_auth_code_known_answer`, `:test_shared_negative_vectors`, `:test_web2app_callback_checks`, `:test_expired_and_untrusted`, `:test_identity_mismatch_for_notification`; Go side `internal/smartid/replay_test.go:TestSharedNegativeVectors` |
| 3 | Release workflow publishes to PyPI via trusted publishing | GATE (G-25) | `.github/workflows/release.yml` job `pypi` (`id-token: write`, `pypa/gh-action-pypi-publish`, environment `pypi`) is committed; it runs only on an owner-pushed `v*` tag and needs the owner's PyPI project. Publication is out of scope (G-25, H-01). |

Verdict: MET-EXCEPT-GATES (item 3: G-25).

## 7.3 Add an eidbridge doctor command for upstream connectivity checks

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | `httptest` TLS servers for pin mismatch, expiring cert, unreachable host | MET | `internal/doctor/doctor_test.go:TestPinMismatchFails`, `:TestExpiringCertWarns`, `:TestUnreachableAndUntrustedFail`, `:TestPinsDisabledWarns`, `:TestTrustBundles`; `cmd/eidbridge/integration_test.go:TestDoctorJSON` |
| 2 | `--json` schema documented | MET | `docs/doctor.md` section "JSON schema (`--json`, version 1)"; `internal/doctor/doctor_test.go:TestJSONFieldNames` |
| 3 | No outbound calls beyond configured endpoints | MET | `internal/doctor/doctor_test.go:TestUpstreamOKAndOnlyConfiguredEndpoint` (exactly one `HEAD` to the configured host); `internal/doctor/pr31_test.go:TestPR31DiagnosticRedaction` |
| RV | Upstream outage makes doctor fail while readiness stays local | PARTIAL | Named test `TestDoctorNeverControlsReadiness` is absent. Design statements only: `docs/doctor.md:3` and `internal/doctor/doctor.go:3`. Readiness independence from upstream is not asserted by any test (`internal/web/web_test.go:TestReadinessIgnoresSaturation` covers saturation and drain, not upstream outage). |

Verdict: GAPS – RV: `TestDoctorNeverControlsReadiness` absent, no test ties doctor failure to unchanged readiness. Gate G-26 (no outage report) stays disclosed.

## 7.4 Ship a mock RP API server and test identities for offline testing

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Bridge e2e and IdP e2e suites run against the mock in CI with no external network | PARTIAL | `cmd/eidbridge/integration_test.go:TestBridgeAgainstExternalMock` runs the bridge against an external HTTP fixture server (the `smartidtest` server that `cmd/eidbridge-mock` also serves) started in-process, not the standalone `eidbridge-mock` binary. The IdP suites (`test/e2e/harness_test.go:startBridge`) use `eidbridge serve --demo` with its built-in fixture (`EIDBRIDGE_SMARTID_ENV=mock`), not `cmd/eidbridge-mock`. `examples/signing-asice/run.sh` does use the standalone binary but is not in CI. |
| 2 | Each scenario (complete, refuse, timeout, wrong VC) has a test | MET | `cmd/eidbridge-mock/main_test.go:TestControlScenarios` (complete, refuse, timeout, wrong-vc through the control API with verification), `:TestScenarioFile` |
| 3 | Refuses non-loopback bind unless `--allow-remote` | MET | `cmd/eidbridge-mock/main_test.go:TestRefusesRemoteListen`; `docs/mock.md` |

Verdict: GAPS – item 1: no CI suite runs the IdP or bridge e2e against the standalone `eidbridge-mock` process. Gate G-27 (external demand) stays disclosed.

## 7.5 Support legacy Smart-ID RP API v2 for existing relying parties

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Fixture tests for v2 create/poll/verify incl. negatives | MET | `internal/smartid/v2/v2_test.go:TestVerifyOK`, `:TestVerifyNegatives`, `:TestVerifyStatusAndInput`, `:TestVerificationCode`; `internal/smartid/v2/live_test.go:TestReplayLiveV2` (recorded exchanges); `internal/smartid/v2/pr31_test.go:TestPR31V2RejectsUnsignedLevelUpgrade` |
| 2 | `authntest.Run` passes for v2 | MET | `internal/smartid/v2/v2_test.go:TestMethodContract` |
| 3 | Docs explain migration v2 to v3 | MET | `docs/smartid-v2-migration.md`; `cmd/eidbridge/integration_test.go:TestSmartIDV2LoginThroughBridge` |

Verdict: ALL-MET (gate G-29: no deployment that cannot use v3; live v2 run only through the opt-in `TestLiveDemoV2`).

## 7.6 Document or ship a WordPress login integration via the bridge

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Guide on fresh WordPress container logs a user in via the mock upstream | MET | `docs/idp/wordpress.md` (plugin 3.11.5, e2e PASSED 2026-11-20); `examples/wordpress/run-e2e.sh` and `e2e.py` (asserts PKCE S256, nonce, state, redirect URI, logged-in user, production demo refusal); upstream is the bridge's built-in fixture (`EIDBRIDGE_SMARTID_ENV: "mock"` in `examples/wordpress/docker-compose.yml`). Commit 519e0e0. |
| 2 | Example compose stack has an automated login test | MET | `examples/wordpress/e2e.py` driven by `run-e2e.sh`. Not run in CI (no WordPress job in `ci.yml`). |

Verdict: ALL-MET (gate G-30: no WordPress user requests; WordPress.org publication out of scope).

## 8.1 Support document signing sessions alongside authentication

| # | criterion (short) | class | evidence |
|---|---|---|---|
| 1 | Fixture tests for signing session create/poll/verify | MET | `internal/smartid/sign_test.go:TestSignPositive`, `:TestCertificateChoiceNegative`, `:TestCertificateChoiceRevoked`, `:TestSignNegativePerStep`, `:TestSignRevokedAtSigning`; `internal/signapi/signapi_test.go:TestSignRoundTrip`; `cmd/eidbridge/signing_integration_test.go:TestSigningRelayThroughBridge` |
| 2 | Example produces a valid ASiC-E container verified by an independent validator | GATE (G-28) | `examples/signing-asice` builds the container with EU DSS and validates with DSS itself (same library, not independent); `check_container.py` is a structural second implementation, not a full XAdES validator. `docs/signing.md` "Limits of the example validation" says so; DSS default policy gives INDETERMINATE (no revocation data). No qualified-status claim. |
| 3 | API requires client authentication; unauthenticated requests rejected | MET | `internal/signapi/signapi_test.go:TestUnauthenticatedRejected` (401 on every route, no upstream session created); `internal/oidc/signing_test.go:TestAuthenticateSigningClient` |
| 8.1-a | Client-credentials `POST /api/v1/sign`, `GET /api/v1/sign/{id}`; rate-limited, no persistence; unauthenticated, wrong-client, replayed fail | MET | `internal/signapi/signapi_test.go:TestUnauthenticatedRejected`, `:TestWrongClientCannotUseJobs`, `:TestReplayedSignRejected`, `:TestRateLimitAndCapacity`, `:TestJobsExpire`, `:TestExpiredJobsSweptInBackground`, `:TestFailingUpstreamIsNotHammered` |
| 8.1-b | Digest relay; verify signature against signer cert; tampered signature, wrong digest, authentication-cert cases fail | MET | `internal/smartid/sign_test.go:TestSignNegativePerStep` (rows "tampered signature", "wrong digest", "authentication certificate"), `:TestCertificateChoiceNegative` ("authentication certificate"); `internal/signapi/signapi_test.go:TestVerificationFailureReported`, `:TestPendingCertificateCannotSign` |
| 8.1-c | `docs/signing.md` with a container example run against the fixture | MET | `docs/signing.md` (run record with Go, JDK, Maven, DSS versions); `examples/signing-asice/run.sh`; commit 5f68293 |

Verdict: MET-EXCEPT-GATES (item 2: G-28). Gate G-28 also lists legal/scope review and live signing run, which are not criteria here.

## Summary

| Story | Title | Verdict |
|---|---|---|
| 1.1 | Unofficial-project notice, trademark policy, clean-room rules | MET-EXCEPT-GATES (H-12) |
| 1.2 | Go module scaffold, CI, licence checks, release automation | MET-EXCEPT-GATES (H-01) |
| 1.3 | Redact personal identity codes at the log sink | ALL-MET |
| 1.4 | Spike Smart-ID v3 device-link login | ALL-MET |
| 2.1 | Smart-ID RP API v3 client with signature verification | GAPS |
| 2.2 | Pin RP API TLS certificates, configurable trust anchors | ALL-MET |
| 2.3 | Method-neutral authenticator interface | ALL-MET |
| 2.4 | Standard OpenID Connect provider | GAPS |
| 2.5 | Binary with login page, QR and Web2App flows | GAPS |
| 2.6 | No telemetry and zero data retention | GAPS |
| 2.7 | Warn on demo use, block demo credentials in prod | ALL-MET |
| 2.8 | Smart-ID v3 notification flow | ALL-MET |
| 3.1 | Personal data flow document | ALL-MET |
| 3.2 | Zero-config docker compose demo | GAPS |
| 3.3 | Localize the login page | MET-EXCEPT-GATES (H-16) |
| 3.4 | Maintenance runbook | GAPS |
| 3.5 | Config-only IdP guides with e2e per IdP | GAPS |
| 3.6 | Django and FastAPI examples | ALL-MET |
| 4.1 | Method chooser | ALL-MET |
| 4.2 | Mobile-ID | ALL-MET |
| 5.1 | ID-card login via Web eID | GAPS |
| 6.1 | EUDI Wallet via OpenID4VP | GAPS |
| 6.2 | EUDI conformance harness | GAPS |
| 7.1 | Keycloak SPI | ALL-MET |
| 7.2 | Python client | MET-EXCEPT-GATES (G-25) |
| 7.3 | `eidbridge doctor` | GAPS |
| 7.4 | Mock RP API server | GAPS |
| 7.5 | Smart-ID RP API v2 | ALL-MET |
| 7.6 | WordPress integration | ALL-MET |
| 8.1 | Signing sessions | MET-EXCEPT-GATES (G-28) |

Totals: ALL-MET 13, MET-EXCEPT-GATES 5, GAPS 12. Stories that also contain GATE items but are classed GAPS: 2.5 (G-R0, H-14), 3.2 (H-14), 3.4 (H-17), 3.5 (H-15), 5.1 (G-21), 6.1 (G-22).

## PARTIAL and MISSING items

| Story | Item | Class | What is missing |
|---|---|---|---|
| 2.1 | E02c verification parameters and fetch limits | PARTIAL | `TestVerificationParametersAndStatusFetchLimits` absent; no test that `shareMdClientIpAddress=false` is sent; no no-redirect test on OCSP/CRL fetches |
| 2.4 | E08c random value lengths, SHA-256 storage, constant-time compare | PARTIAL | Only code and epoch lengths tested; flow IDs, binding tokens, callback values, family IDs and constant-time compare untested |
| 2.5 | RV `TestSessionInitTransportBounds` | PARTIAL | Named test absent; init timeouts, oversized or redirected init responses and "no blind retry of uncertain init" untested |
| 2.5 | RV `TestCodeCapacityUnderSustainedExchange` | PARTIAL | Named test absent; no measurement of reservations, codes and tombstones over the retention window or of index memory |
| 2.6 | Egress-blocked CI network test | MISSING | No container, script or test blocks egress and completes a login with only the mock upstream reachable |
| 3.2 | `scripts/e2e-demo.sh` in CI | PARTIAL | Script passes locally; no CI job runs it |
| 3.4 | A05b K_sub compromise drill | PARTIAL | `TestKSubCompromiseAndReplacementKey` only calls `TestSubKeyVersionMigration`; retiring the old K_sub version is untested |
| 3.5 | e2e passes for all four IdPs in CI | PARTIAL | `TestOryKratos` is skipped in CI (NOT RUN; Kratos v26.2.0 sends no `nonce`) |
| 5.1 | 5.1-b other-browser submission | PARTIAL | No automated test posts to `/flow/{id}/browser` without the flow cookie |
| 5.1 | 5.1-d vendored `web-eid.js` | PARTIAL | Not vendored; a reimplementation is used (ADR 0005) |
| 6.1 | 6.1-c mdoc verification | PARTIAL | Not implemented; recorded as such in ADR 0006 |
| 6.2 | JUnit report produced in CI | PARTIAL | Harness test runs in CI but no CI step writes or uploads the JUnit XML |
| 7.3 | RV `TestDoctorNeverControlsReadiness` | PARTIAL | Named test absent; readiness independence from upstream outage is documented, not tested |
| 7.4 | Bridge and IdP e2e against the mock in CI | PARTIAL | IdP e2e use the built-in fixture, not the standalone `eidbridge-mock`; bridge e2e uses the same fixture server in-process |

## GATE items by gate ID

| Gate | Stories and criteria |
|---|---|
| H-12 | 1.1 item 3 (DCO as required check; no branch protection) |
| H-01 | 1.2 item 3 (tag, release assets, GHCR image) |
| G-R0, H-14 | 2.5 item 1 (login with a human-approved demo app) |
| H-14 | 3.2 item 2 (manual five-minute scan) |
| H-16 | 3.3 item 4 (native-speaker review) |
| H-17 | 3.4 item 2 (nightly workflow run and auto-issue) |
| H-15 | 3.5 item 1 (manual Keycloak run and screenshot) |
| G-21 | 5.1 item 3 and child 5.1-e (test card, extension, external review) |
| G-22 | 6.1 item 1 (reference wallet) |
| G-25 | 7.2 item 3 (PyPI publication) |
| G-28 | 8.1 item 2 (independent ASiC-E validator) |

## Update after closing the gaps (2026-11-21, branch feat/final-pass)

The matrix above was produced before these commits. Each PARTIAL or MISSING item and what closed it:

| Story / item | Now | Evidence |
|---|---|---|
| 2.1 E02c (no redirects on status fetches) | MET | `internal/revocation/redirect_test.go:TestStatusFetchesRefuseRedirects` (hand mutant on CheckRedirect killed). `shareMdClientIpAddress=false` is set in `internal/smartid/client.go:184` and `sign.go`; not separately tested (inspection). |
| 2.4 E08c (entropy, constant time) | MET except constant time by inspection | `internal/web/mutation_gaps_test.go:TestRandomValueLengths`, `internal/store/codes_test.go:TestFamilyIDLengthAndHashedCodes`; constant-time compares use `hmac.Equal` / `subtle.ConstantTimeCompare` (inspection only). |
| 2.5 RV TestSessionInitTransportBounds | MET | `internal/web/init_transport_test.go` (redirect, oversized, 500, timeout; QR and notification; one attempt; reservation and slot released; timed-out init cancelled upstream). |
| 2.5 RV TestCodeCapacityUnderSustainedExchange | MET | `internal/store/codes_test.go` (2 logins/s over two retention windows at cap 400). |
| 2.6 egress-blocked test | MET | `scripts/egress-blocked.sh` (local run: 14 login tests PASS in a loopback-only namespace) and CI job `egress-blocked`. |
| 3.2 CI run of the demo stack | MET once CI runs | CI job `demo-e2e` runs `scripts/e2e-demo.sh`. |
| 3.4 A05b K_sub retirement | MET | `internal/oidc/adr_test.go:TestKSubCompromiseAndReplacementKey` now runs the full drill. |
| 3.5 Ory Kratos | Still NOT RUN | Kratos v26.2.0 sends no `nonce`; the bridge requires it (NFR-005). Disclosed. |
| 5.1-b cookie-less browser post | MET | `cmd/eidbridge/redteam2_regression_test.go:TestWebEIDTokenNeedsFlowCookie`. |
| 5.1-d web-eid.js | Deviation, disclosed | Reimplemented extension message protocol (ADR 0005). |
| 6.1-c mdoc | Deferred as the child story allows | ADR 0006. |
| 6.2 JUnit in CI | MET once CI runs | CI job `eudi-conformance` writes and uploads JUnit and Markdown (local run 17/17). |
| 7.3 RV TestDoctorNeverControlsReadiness | MET | `cmd/eidbridge/redteam2_regression_test.go:TestDoctorNeverControlsReadiness`. |
| 7.4 standalone mock | MET | `cmd/eidbridge/redteam2_regression_test.go:TestBridgeAgainstStandaloneMockBinary`. |

Sprint statuses (`sprint-status.yaml`): `done` for 1.3, 2.3, 2.6, 2.7, 2.8, 3.1, 3.6 (criteria evidenced, no overridden gate); `done-with-disclosure` for every other story, because an overridden gate in the sprint-change proposal still lacks evidence (or, for 3.5 and 5.1, the disclosed items above).
