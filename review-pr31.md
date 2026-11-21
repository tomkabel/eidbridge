# PR #31 review (feat/full-build vs main), 2026-11-21

Draft only, not posted to GitHub.

## Method

- 19 slices, one reviewer each, with the per-slice checklists from the brief. One fresh verifier per finding of medium or higher, told to refute it.
- Reviewers read a scratch worktree with 6 seeded canaries, squashed into one commit. The regression tests that would have exposed the canaries were deleted.
- Each repro test was rerun on a clean worktree of feat/full-build (`ad3a6de`). A finding that disappears on clean is a canary match.
- **Models (deviates from the brief).** Haiku was not reachable: the Workflow/Agent tools returned 404 `model_not_found`, and OpenLux Haiku 4.5 returned HTTP 429 "upstream load is saturated".
  - Sonnet 5.5 via `openlux -p` ran slices 1a, 1b, 2b, 2c, 3 and 4. Then the OpenLux quota ran out (HTTP 403).
  - Codex `gpt-6.1-terra` with `model_reasoning_effort=high` ran the other 13 slices and all 14 verifiers. A first codex pass at medium effort produced shallow reviews and was discarded.
- **Contamination caveat.** The Sonnet prompts contained a guard line naming a `CANARIES.md` path. That told those six reviewers that seeded bugs existed. Slice 1a (Sonnet) found C3, C5 and C6, so its recall may be biased upward. The codex prompts did not contain the line.

## Real findings (repro fails on clean feat/full-build, or the code path is confirmed)

Ranked by severity. The verifier verdict for every finding in this section was CONFIRMED.

### 1. HIGH: PyPI publish runs a mutable action with OIDC publishing rights
- **Where:** `.github/workflows/release.yml:52`
  - `uses: pypa/gh-action-pypi-publish@release/v1` runs in a job with `id-token: write`.
  - `actions/checkout@v4`, `actions/setup-python@v5` and the other workflows are tag-pinned too.
- **Attack:** if the `release/v1` tag is moved or compromised, the PyPI trusted-publishing identity publishes a malicious `eidbridge-rp`, which every RP then installs.
- **Repro:** `TestReview11SupplyChainPins` (appendix A4) fails on clean, listing every non-SHA `uses:`.
- **Fix direction:** pin every action by full commit SHA with a version comment, and let dependabot (already configured) bump them.

### 2. HIGH: the Django example ships a fixed `SECRET_KEY` with signed-cookie sessions
- **Where:** `examples/django/django_settings.py:1`
  - `SECRET_KEY = "example-only-not-a-secret"` together with `SESSION_ENGINE = ...signed_cookies`.
- **Attack:** a user who copies the example ships the published key. Anyone can then sign a session cookie with any `sub`, and `/me` treats that session as logged in. That is a login as the wrong person in the RP.
- **Repro:** `test_checked_in_django_secret_allows_forged_authenticated_session` (appendix A5) passes on clean. The test's polarity is inverted: passing means the forgery works.
- **Fix direction:** read `SECRET_KEY` from the environment and refuse to start without it, or generate one per run. Use a server-side session engine in the example.

### 3. MEDIUM-HIGH: EUDI status list is accepted without freshness, so a stale "valid" list hides a revocation
- **Where:** `internal/eudi/status.go:95` calls `timeClaims(c, now, time.Minute, false)`.
  - `timeClaims` in `internal/eudi/sdjwt.go:230-248` treats a missing `iat`/`exp` as OK when `needExp` is false.
- **Attack:** whoever can serve or replay a once-valid, issuer-signed status-list JWT without `exp` keeps a revoked PID usable indefinitely.
- **Repro:** `TestReview5RejectStatusListWithoutFreshnessClaims` (appendix A2) fails on clean. Found independently by slice 5 and slice 13b, merged here.
- **Fix direction:** require `iat` and `exp` on status-list tokens, as the Token Status List draft says the verifier should. Enforce a maximum age or `ttl`, and fail closed.

### 4. MEDIUM: Web eID revocation turns an OCSP "unknown" into a pass through the CRL fallback
- **Where:** `internal/revocation/revocation.go:88-94`. `CRLFallback` is enabled in production wiring (`cmd/eidbridge/webeid.go`, `serve.go`).
  - Any non-revoked OCSP error, including a signed `unknown` (`revocation.go:179-185`), falls through to the CRL.
  - A CRL that merely omits the serial then returns nil.
- **Attack:** a certificate unknown to the issuer's OCSP responder is accepted, for example one mis-issued or issued outside the CA's database. ADR 0005 says "unknown failing closed".
- **Repro:** `TestZZReview4OCSPUnknownBypassedByCRLFallback` (appendix A1) fails on clean.
- **Fix direction:** use the CRL only when OCSP is unreachable or its response is malformed (transport errors). Treat a signed `unknown` as final and reject.

### 5. MEDIUM: Supply chain: base images pinned by tag, not digest
- **Where:** `Dockerfile:2` (`golang:1.24-alpine`) and `Dockerfile.goreleaser:6` (`alpine:3.20`, which supplies the CA bundle in the release image).
- **Attack:** a moved tag changes the compiler or the trusted CA bundle in released images with no source change.
- **Repro:** `TestReview11SupplyChainPins`, the same test as finding 1.
- **Fix direction:** use `FROM image:tag@sha256:...`, and let dependabot's docker ecosystem keep the pins current.

### 6. MEDIUM, limited reach: Smart-ID v3 `certificateLevel` is taken from unsigned JSON
- **Where:** `internal/smartid/verify.go:135` checks `st.Cert.CertificateLevel` against `MinCertLevel`, and `:171` copies it into `Identity.CertLevel`.
  - The ACSP_V2 signature does not cover this field. The level is not derived from the certificate's policy OIDs.
- **Attack:** a modified status response raises ADVANCED to QUALIFIED. That defeats a QUALIFIED-only `MinCertLevel` configuration.
- **Reach:**
  - The response comes over the pinned TLS connection to SK, so the attacker must be the API or break the pin.
  - The OIDC `acr` is derived from the method, not `CertLevel` (`provider.go:513`), so the id_token `acr` is unaffected.
  - The finding violates the checklist rule "nothing trusted before the response signature".
- **Repro:** `TestReview2AUnsignedCertificateLevelCanBeRaised` (appendix A3) passes on clean. The polarity is inverted: passing means the modified level was accepted.
- **Fix direction:** derive the level from the verified leaf certificate's policy OIDs and reject a mismatch with the JSON field.

### Low (not sent to verifiers under the ≥medium rule; repro fails on clean)
- **L1** `internal/doctor/doctor.go:90`: on a failed probe, `doctor` puts the raw upstream URL, query string included, into its text and JSON detail. A credential in the query string (`?api_key=`) is exposed. Repro A6.
- **L2** `internal/smartid/recorder.go:66`: the guard that keeps the demo-only `MockSubmit` on loopback is a string-prefix check. `http://127.0.0.1.attacker.invalid` and `http://127.0.0.1@attacker.invalid` pass it and receive the session token and auth code. Demo and spike code only. Repro A7.

## Calibration (outside judge)

| Canary | Planted change | Found by | Verdict | Repro on clean | Counted |
|---|---|---|---|---|---|
| C1 | `serve.go:93` `Codes.StartSweeper` call and method removed (reverts 6ce26d4) | 7 store, 13a | low, not verified | store-level test still fails, but clean wires the sweeper at `cmd/eidbridge/serve.go:93` | found, **not CONFIRMED** |
| C2 | `config.go` `checkSigningCA` removed (reverts fbaf9ae, red-team #2 F2) | 8a, 13a | CONFIRMED ×2 | passes (gone) | ✅ |
| C3 | `provider.go:584` client_id binding check removed at /token | 1a, 13a | CONFIRMED ×2 | passes (gone) | ✅ |
| C4 | `provider.go:381` state/nonce charset and length check removed | none | – | – | ❌ missed |
| C5 | `clients.go:240` `subtle.ConstantTimeCompare` replaced with `!=` | 1a | CONFIRMED | passes (gone) | ✅ |
| C6 | `provider.go:340` exact redirect_uri match replaced with a prefix match | 1a, 13a | CONFIRMED ×2 | passes (gone) | ✅ |

**Recall: 4 of 6 found and CONFIRMED. That misses the ≥5 target.** 5 of 6 were found.

- **C1:** slices 7 and 13a both found it, with a failing test, but rated it `low` ("privacy, no direct attack"). The protocol sends only ≥medium findings to verifiers, so it was never CONFIRMED. The reviewers also tested at the store layer. Both noticed that "production starts a web-flow sweeper, but it does not call" `Codes.Sweep`, and neither wrote the test at the `cmd/eidbridge` Build layer, where the planted regression lives. Slices 8b (startup wiring) and 10 (privacy) should have caught it at the wiring level, and both reported nothing about it. Root cause: the severity rubric gave no weight to "personal codes kept in memory past their stated retention", even though the brief defines a personal-code leak as a target defect.
- **C4:** slice 1a should have caught it; its checklist says "state/nonce bound and compared". After the canary, state and nonce are still copied into the request, echoed back and embedded in the id_token. Only the charset and length validation disappeared, so the visible effect is empty or unbounded state and nonce values. Arguably that is not a security failure in the code flow, because OIDC Core makes nonce optional there. The canary was a weak plant. Slice 13a also missed it even though the planted change deleted `TestStateNonceVerifierLengths`; the test-honesty method has no "look for tests that disappeared" step.
- **Precision:** zero findings were opinion only. All 18 returned findings came with a repro test. Every finding of medium or higher was CONFIRMED by its verifier; none were REFUTED or UNPROVEN.

## UNPROVEN / not verified

- None of the verifier verdicts was UNPROVEN.
- **Orchestrator note, not a reviewed finding.** `internal/smartid/v2/v2.go:236,272` appear to use the same `st.Cert.CertificateLevel` field as finding 6. Slice 2c (Smart-ID v2, Sonnet) returned an empty list. This needs a reviewer and a repro before anyone acts on it.

## Baseline on clean feat/full-build (`ad3a6de`)

- `go test -race ./...`: PASS, exit 0, 0 failing packages.
- `make check`: fmt-check, vet and test PASS. `licenses` FAILED with exit 127 because `/home/notroot/go/bin/go-licenses` is not installed, so make stopped there. `spec-pins` and `arch-trace`, run separately: PASS.

## Appendix: repro tests (the files were removed during cleanup)

### A1 `internal/revocation/zz_review_4_test.go`
```go
func TestZZReview4OCSPUnknownBypassedByCRLFallback(t *testing.T) {
	p := smartidtest.NewPKI("ocsp")
	now := time.Now()
	r := &responder{pki: p, status: ocsp.Unknown, this: now.Add(-time.Minute), next: now.Add(time.Hour)}
	c, leaf, iss := setup(t, r, true) // CRLFallback is true, as in production wiring
	r.crl = crlFor(t, p, nil, now.Add(-time.Minute), now.Add(time.Hour))
	if err := c.Check(context.Background(), leaf, iss); err == nil {
		t.Fatal("certificate with OCSP status 'unknown' was accepted via CRL fallback")
	}
}
```

### A2 `internal/eudi/zz_review_5_test.go`
```go
func TestReview5RejectStatusListWithoutFreshnessClaims(t *testing.T) {
	e := newVEnv(t)
	var statusServer *httptest.Server
	statusServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var compressed bytes.Buffer
		zw := zlib.NewWriter(&compressed)
		_, _ = zw.Write([]byte{0}) // index zero was valid in this old list
		_ = zw.Close()
		token, err := signES(e.prov.SignerKey(), header{Alg: "ES256", Typ: "statuslist+jwt", X5C: []string{
			base64.StdEncoding.EncodeToString(e.prov.Signer.Raw), base64.StdEncoding.EncodeToString(e.prov.Inter.Raw)}},
			map[string]any{"sub": statusServer.URL + "/status",
				"status_list": map[string]any{"bits": 1, "lst": b64.EncodeToString(compressed.Bytes())}})
		if err != nil { t.Errorf("sign stale status list: %v", err); return }
		_, _ = w.Write([]byte(token))
	}))
	defer statusServer.Close()
	e.prov.StatusURI = statusServer.URL + "/status"
	e.v.Status = &StatusChecker{AllowedHosts: map[string]bool{statusServer.Listener.Addr().String(): true}}
	w := e.prov.Issue(walletsim.IssueOptions{})
	if _, err := e.verify(w, "nonce", walletsim.PresentOptions{}); err == nil {
		t.Fatal("accepted status list with no freshness claims")
	}
}
```

### A3 `internal/smartid/zz_review_2a_test.go` (passes when the bug is present)
```go
func TestReview2AUnsignedCertificateLevelCanBeRaised(t *testing.T) {
	sy := newSynth(t, FlowQR, smartidtest.LeafOptions{})
	cert := sy.st["cert"].(map[string]any)
	cert["certificateLevel"] = LevelQualified // status signature unchanged
	id, err := sy.verify()
	if err != nil { t.Fatalf("mutated result rejected: %v", err) }
	if id.CertLevel != LevelQualified { t.Fatalf("identity level = %q, want %q", id.CertLevel, LevelQualified) }
}
```

### A4 `internal/version/zz_review_11_test.go`
Walks `.github/workflows/*.yml` and fails on every `- uses:` reference that does not end in `@<40-hex SHA>`. It also walks `Dockerfile` and `Dockerfile.goreleaser` and fails on every `FROM` image other than `scratch` that lacks `@sha256:`.

### A5 `python/tests/zz_review_12_test.py` (passes when the bug is present)
```python
os.environ["DJANGO_SETTINGS_MODULE"] = "django_settings"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "examples" / "django"))
import django; django.setup()
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.test import Client

def test_checked_in_django_secret_allows_forged_authenticated_session():
    forged = SessionStore(); forged["sub"] = "attacker-chosen-sub"
    forged["claims"] = {"sub": "attacker-chosen-sub"}; forged.save()
    client = Client(); client.cookies["sessionid"] = forged.session_key
    response = client.get("/me")
    assert response.status_code == 200
    assert response.json()["sub"] == "attacker-chosen-sub"
```

### A6 `internal/doctor/zz_review_8b_test.go`
```go
func TestReview8bDoctorDoesNotExposeUpstreamQuerySecrets(t *testing.T) {
	srv := httptest.NewServer(nil)
	baseURL := srv.URL + "/probe?api_key=review-secret-value"
	srv.Close()
	r := Run(context.Background(), []Target{{Component: "smartid", Env: "production", BaseURL: baseURL, PinsDisabled: true}}, nil, time.Now())[0]
	if strings.Contains(r.Detail, "review-secret-value") { t.Fatalf("doctor detail leaked configured query secret: %s", r.Detail) }
}
```

### A7 `internal/smartid/zz_review_2b_test.go`
```go
func TestReview2bMockSubmitGuardPrefixBypass(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1.attacker.invalid", "http://127.0.0.1@attacker.invalid"} {
		err := MockSubmit(context.Background(), base, MockDeviceLink{DocumentNumber: "PNOEE-40404040009-MOCK-Q", DeviceLink: "https://x"}, nil)
		if err == nil || !strings.Contains(err.Error(), "demo-only") {
			t.Errorf("base %q passed the demo-only guard; got err=%v", base, err)
		}
	}
}
```
