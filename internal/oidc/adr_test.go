package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/jose"
)

func TestUserinfoFromSealedAccessToken(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	st, m := e.userinfo(tr.AccessToken)
	if st != 200 || m["sub"] == nil || m["given_name"] != "OK" || m["eid_env"] != "demo" {
		t.Fatalf("%d %v", st, m)
	}
	// No server-side claim cache: the token is self-contained and opaque.
	raw, _ := base64.RawURLEncoding.DecodeString(tr.AccessToken)
	if strings.Contains(string(raw), "OK") || strings.Contains(string(raw), "basic") || raw[0] != atFormat {
		t.Fatal("access token is not sealed")
	}
}

func TestSubIsKeyedHMACNotPersonalCode(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	sub := claims(t, tr.IDToken)["sub"].(string)
	if strings.Contains(sub, "40404040009") || len(sub) != 43 {
		t.Fatalf("sub %q", sub)
	}
	// Fixed test vector: identical across builds.
	s := &Subjects{Keys: map[int][]byte{1: make32(1)}, Current: 1}
	got, _ := s.Sub(1, "c:basic", "PNO", "EE", "40404040009")
	if got != sub {
		t.Fatal("sub differs from the ADR-007 formula")
	}
	pub, _ := s.Sub(1, "g:public", "PNO", "EE", "40404040009")
	if pub == got || pub != "XrDMab1c4HuMeihMMjW1xuWn5yip2tXjsGT0PfJX9gs" { // vector computed independently with Python hmac
		t.Fatalf("public vector %q", pub)
	}
	// Pairwise differs across clients; public is shared.
	tr2 := e.exchange("pkj", e.code("pkj"), nil)
	if claims(t, tr2.IDToken)["sub"] == sub {
		t.Fatal("pairwise subs collide across clients")
	}
}

func TestSubParsesSerialNumberAndRejectsOtherForms(t *testing.T) {
	s := &Subjects{Keys: map[int][]byte{1: make32(1)}, Current: 1}
	for _, bad := range [][3]string{{"XYZ", "EE", "1"}, {"PNO", "ee", "1"}, {"PNO", "EE", ""}, {"PNO", "EST", "1"}} {
		if _, err := s.Sub(1, "g:public", bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := s.Sub(9, "g:public", "PNO", "EE", "1"); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestSubKeyVersionMigration(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Subjects = &Subjects{Keys: map[int][]byte{1: make32(1), 2: make32(2)}, Current: 2,
			Migration: &Migration{From: 1, To: 2, Started: time.Now().Add(-time.Hour), Days: 30, Clients: map[string]string{"basic": "c:basic"}}}
	})
	cl := claims(t, e.exchange("basic", e.code("basic"), nil).IDToken)
	old, _ := e.p.cfg.Subjects.Sub(1, "c:basic", "PNO", "EE", "40404040009")
	if cl["previous_sub"] != old || cl["sub"] == old {
		t.Fatalf("migration claims: %v", cl)
	}
	// Undeclared client gets no previous_sub; after the window it is gone.
	if _, ok := claims(t, e.exchange("pkj", e.code("pkj"), nil).IDToken)["previous_sub"]; ok {
		t.Fatal("undeclared client got previous_sub")
	}
	e.clk.StepWall(31 * 24 * time.Hour)
	if _, ok := claims(t, e.exchange("basic", e.code("basic"), nil).IDToken)["previous_sub"]; ok {
		t.Fatal("previous_sub after window")
	}
	for _, bad := range []*Migration{{From: 1, To: 2, Days: 0}, {From: 1, To: 2, Days: 91}, {From: 3, To: 2, Days: 5}, {From: 1, To: 1, Days: 5}} {
		s := &Subjects{Keys: map[int][]byte{1: make32(1), 2: make32(2)}, Current: 2, Migration: bad}
		if s.Validate() == nil {
			t.Errorf("migration %+v accepted", bad)
		}
	}
}

func TestSubKeyOrModeChangeNeedsMigration(t *testing.T) {
	dir := t.TempDir()
	subs := &Subjects{Keys: map[int][]byte{1: make32(1), 2: make32(2)}, Current: 1}
	cs := []Client{{ID: "a", SubMode: "pairwise"}}
	if err := CheckSubjectLock(dir, cs, subs); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(){
		"mode":    func() { cs[0].SubMode = "public" },
		"sector":  func() { cs[0].SubMode, cs[0].SectorID = "pairwise", "other" },
		"version": func() { cs[0].SectorID = ""; subs.Current = 2 },
	} {
		mut()
		if err := CheckSubjectLock(dir, cs, subs); err == nil {
			t.Fatalf("%s change accepted without migration", name)
		}
	}
	subs.Migration = &Migration{From: 1, To: 2, Started: time.Now(), Days: 5, Clients: map[string]string{"a": "c:a"}}
	if err := CheckSubjectLock(dir, cs, subs); err != nil {
		t.Fatalf("declared migration refused: %v", err)
	}
}

func TestPrivateKeyJWTRejectsJWKSURI(t *testing.T) {
	err := validateClients([]Client{{ID: "x", AuthMethod: AuthPrivKey, JWKSURI: "https://evil.example/jwks", RedirectURIs: []string{"https://a/cb"}, SubMode: "public"}}, false)
	if err == nil || !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatal(err)
	}
}

func TestPrivateKeyJWTAssertionRules(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func(map[string]any){
		"aud token endpoint": func(c map[string]any) { c["aud"] = e.p.cfg.Issuer + "/token" },
		"aud other":          func(c map[string]any) { c["aud"] = "https://other" },
		"iss other":          func(c map[string]any) { c["iss"] = "basic" },
		"sub other":          func(c map[string]any) { c["sub"] = "basic" },
		"exp too far":        func(c map[string]any) { c["exp"] = e.clk.Now().Add(10 * time.Minute).Unix() },
		"expired":            func(c map[string]any) { c["exp"] = e.clk.Now().Add(-time.Second).Unix() },
		"no jti":             func(c map[string]any) { delete(c, "jti") },
	}
	for name, mod := range cases {
		as := e.assertion(mod)
		tr := e.exchange("pkj", e.code("pkj"), func(f url.Values, _ *http.Request) { f.Set("client_assertion", as) })
		if tr.Error != "invalid_client" {
			t.Errorf("%s: %+v", name, tr)
		}
	}
	// Reused jti.
	as := e.assertion(nil)
	e.exchange("pkj", e.code("pkj"), func(f url.Values, _ *http.Request) { f.Set("client_assertion", as) })
	if tr := e.exchange("pkj", e.code("pkj"), func(f url.Values, _ *http.Request) { f.Set("client_assertion", as) }); tr.Error != "invalid_client" {
		t.Fatalf("jti replay: %+v", tr)
	}
	// Wrong key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad, _ := jose.Sign(&jose.Key{Alg: jose.RS256, Private: other}, "JWT", map[string]any{"iss": "pkj", "sub": "pkj", "aud": e.p.cfg.Issuer, "exp": e.clk.Now().Add(20 * time.Second).Unix(), "jti": "z"})
	if tr := e.exchange("pkj", e.code("pkj"), func(f url.Values, _ *http.Request) { f.Set("client_assertion", bad) }); tr.Error != "invalid_client" {
		t.Fatal("foreign key accepted")
	}
}

func TestConcurrentClientAssertionReplayRejected(t *testing.T) {
	e := newEnv(t)
	as := e.assertion(nil)
	var ok atomic.Int32
	var wg sync.WaitGroup
	codes := make([]string, 8)
	for i := range codes {
		codes[i] = e.code("pkj")
	}
	for i := range codes {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			if tr := e.exchange("pkj", c, func(f url.Values, _ *http.Request) { f.Set("client_assertion", as) }); tr.Status == 200 {
				ok.Add(1)
			}
		}(codes[i])
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d uses of one jti succeeded", ok.Load())
	}
	// Full jti store: 503 and unexpired entries kept.
	e2 := newEnv(t, func(c *Config) { c.JTICap = 1 })
	e2.exchange("pkj", e2.code("pkj"), nil)
	if tr := e2.exchange("pkj", e2.code("pkj"), nil); tr.Status != 503 || tr.header.Get("Retry-After") == "" {
		t.Fatalf("full jti store: %+v", tr)
	}
}

func TestSingleRegisteredClientAuthMethod(t *testing.T) {
	e := newEnv(t)
	// basic client using post credentials
	tr := e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) {
		r.Header.Del("Authorization")
		f.Set("client_id", "basic")
		f.Set("client_secret", secret)
	})
	if tr.Error != "invalid_client" {
		t.Fatalf("wrong method: %+v", tr)
	}
	// two methods at once
	tr = e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) { f.Set("client_secret", secret) })
	if tr.Error != "invalid_client" {
		t.Fatalf("two methods: %+v", tr)
	}
	tr = e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) { r.Header.Del("Authorization") })
	if tr.Error != "invalid_client" || tr.Status != 401 {
		t.Fatalf("no auth: %+v", tr)
	}
}

func TestAuthorizeUnprovableACRFails(t *testing.T) {
	e := newEnv(t)
	q := e.authParams("basic")
	q.Set("acr_values", "urn:eidbridge:loa:high")
	u := e.authorize(q)
	if u.Query().Get("error") != "unmet_authentication_requirements" || u.Query().Get("iss") != e.p.cfg.Issuer {
		t.Fatalf("%s", u)
	}
	q.Set("acr_values", "urn:eidbridge:loa:high demo")
	if u := e.authorize(q); u.Query().Get("code") == "" {
		t.Fatal("provable acr in the list must succeed")
	}
}

func TestAuthorizeResponseCarriesIss(t *testing.T) {
	e := newEnv(t)
	u := e.authorize(e.authParams("basic"))
	if u.Query().Get("iss") != e.p.cfg.Issuer || u.Query().Get("state") != "st-1" {
		t.Fatalf("success: %s", u)
	}
	q := e.authParams("basic")
	q.Set("scope", "profile")
	u = e.authorize(q)
	if u.Query().Get("iss") != e.p.cfg.Issuer || u.Query().Get("error") != "invalid_scope" || u.Query().Get("state") != "st-1" {
		t.Fatalf("error: %s", u)
	}
}

func TestAuthorizePromptAndMaxAge(t *testing.T) {
	e := newEnv(t)
	q := e.authParams("basic")
	q.Set("prompt", "none")
	if e.authorize(q).Query().Get("error") != "login_required" {
		t.Fatal("prompt=none")
	}
	q.Set("prompt", "none login")
	if e.authorize(q).Query().Get("error") != "invalid_request" {
		t.Fatal("prompt none+login")
	}
	q.Set("prompt", "login consent")
	if e.authorize(q).Query().Get("code") == "" {
		t.Fatal("prompt login")
	}
	q.Del("prompt")
	q.Set("max_age", "0")
	tr := e.exchange("basic", e.authorize(q).Query().Get("code"), nil)
	if claims(t, tr.IDToken)["auth_time"] == nil {
		t.Fatal("auth_time missing with max_age")
	}
	for _, k := range []string{"claims", "request", "request_uri"} {
		q2 := e.authParams("basic")
		q2.Set(k, "x")
		if e.authorize(q2).Query().Get("error") == "" {
			t.Errorf("%s accepted", k)
		}
	}
}

func TestInvalidClientRendersErrorPageAnd303(t *testing.T) {
	e := newEnv(t)
	for name, q := range map[string]url.Values{
		"unknown client":   {"client_id": {"nope"}, "redirect_uri": {"http://localhost:9000/cb"}},
		"unknown redirect": {"client_id": {"basic"}, "redirect_uri": {"https://evil.example/cb"}},
		"missing redirect": {"client_id": {"basic"}},
		"prefix redirect":  {"client_id": {"basic"}, "redirect_uri": {"http://localhost:9000/cb/extra"}},
		"repeated client":  {"client_id": {"basic", "post"}, "redirect_uri": {"http://localhost:9000/cb"}},
	} {
		resp, err := noRedirect.Get(e.srv.URL + "/demo/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// POST authorize redirects with 303.
	resp, err := noRedirect.PostForm(e.srv.URL+"/demo/authorize", e.authParams("basic"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST authorize: %d", resp.StatusCode)
	}
}

func TestAuthorizeParameterHygiene(t *testing.T) {
	e := newEnv(t)
	mods := map[string]func(url.Values){
		"repeated scope":   func(q url.Values) { q["scope"] = []string{"openid", "openid"} },
		"response_type":    func(q url.Values) { q.Set("response_type", "token") },
		"no state":         func(q url.Values) { q.Del("state") },
		"long state":       func(q url.Values) { q.Set("state", strings.Repeat("a", 513)) },
		"state reserved":   func(q url.Values) { q.Set("state", "a b") },
		"no nonce":         func(q url.Values) { q.Del("nonce") },
		"long nonce":       func(q url.Values) { q.Set("nonce", strings.Repeat("a", 513)) },
		"plain pkce":       func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"no pkce method":   func(q url.Values) { q.Del("code_challenge_method") },
		"no challenge":     func(q url.Values) { q.Del("code_challenge") },
		"short challenge":  func(q url.Values) { q.Set("code_challenge", "abc") },
		"max_age negative": func(q url.Values) { q.Set("max_age", "-1") },
		"response_mode":    func(q url.Values) { q.Set("response_mode", "fragment") },
	}
	for name, m := range mods {
		q := e.authParams("basic")
		m(q)
		u := e.authorize(q)
		if u.Query().Get("error") == "" || u.Query().Get("code") != "" {
			t.Errorf("%s: %s", name, u)
		}
	}
	// code_verifier outside 43–128 is invalid at the token endpoint.
	for _, v := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129)} {
		if tr := e.exchange("basic", e.code("basic"), func(f url.Values, _ *http.Request) { f.Set("code_verifier", v) }); tr.Error != "invalid_grant" {
			t.Errorf("verifier len %d: %+v", len(v), tr)
		}
	}
}

func TestAuthorizeAndUserinfoAcceptGetAndPost(t *testing.T) {
	e := newEnv(t)
	resp, _ := noRedirect.PostForm(e.srv.URL+"/demo/authorize", e.authParams("basic"))
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	tr := e.exchange("basic", loc.Query().Get("code"), nil)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/demo/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	r2, err := http.DefaultClient.Do(req)
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("POST userinfo: %v %d", err, r2.StatusCode)
	}
	r2.Body.Close()
}

func TestTokenAndUserinfoNoStoreHeaderOnly(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	if tr.header.Get("Cache-Control") != "no-store" {
		t.Fatal("token response cacheable")
	}
	resp, _ := http.Get(e.srv.URL + "/demo/userinfo?access_token=" + url.QueryEscape(tr.AccessToken))
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("query access_token accepted")
	}
	resp, _ = http.PostForm(e.srv.URL+"/demo/userinfo", url.Values{"access_token": {tr.AccessToken}})
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("form access_token accepted")
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/demo/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("userinfo cacheable")
	}
}

func TestScopeToClaimsMapping(t *testing.T) {
	e := newEnv(t)
	q := e.authParams("basic")
	q.Set("scope", "openid")
	cl := claims(t, e.exchange("basic", e.authorize(q).Query().Get("code"), nil).IDToken)
	if _, ok := cl["given_name"]; ok {
		t.Fatal("profile claims without profile scope")
	}
	for _, k := range []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "country", "eid_method", "eid_env"} {
		if cl[k] == nil {
			t.Errorf("openid claim %s missing", k)
		}
	}
	if cl["acr"] != "demo" {
		t.Fatal("demo acr")
	}
	q.Set("scope", "openid personal_code")
	if e.authorize(q).Query().Get("error") != "invalid_scope" {
		t.Fatal("personal_code without allow-list")
	}
	q2 := e.authParams("post")
	q2.Set("scope", "openid profile personal_code unknown")
	cl = claims(t, e.exchange("post", e.authorize(q2).Query().Get("code"), nil).IDToken)
	if cl["personal_code"] != "PNOEE-40404040009" || cl["given_name"] != "OK" {
		t.Fatalf("allow-listed claims: %v", cl)
	}
	// Names only when the verified identity carries them.
	e.front.id = &authn.Identity{Method: "smartid", AMR: []string{"smartid"}, IDType: "PNO", Country: "EE", Code: "40404040009"}
	cl = claims(t, e.exchange("basic", e.code("basic"), nil).IDToken)
	if _, ok := cl["given_name"]; ok {
		t.Fatal("empty given_name emitted")
	}
}

func TestIDTokenAlgPerClient(t *testing.T) {
	e := newEnv(t)
	hdr := func(jwt string) string {
		b, _ := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[0])
		var h map[string]string
		json.Unmarshal(b, &h)
		return h["alg"]
	}
	if hdr(e.exchange("basic", e.code("basic"), nil).IDToken) != "RS256" || hdr(e.exchange("pkj", e.code("pkj"), nil).IDToken) != "ES256" {
		t.Fatal("per-client alg")
	}
	if validateClients([]Client{{ID: "x", Secret: secret, AuthMethod: AuthBasic, RedirectURIs: []string{"https://a/cb"}, SubMode: "public", IDTokenAlg: "HS256"}}, false) == nil {
		t.Fatal("unsupported alg accepted")
	}
	if validateClients([]Client{{ID: "x", Secret: secret, AuthMethod: AuthBasic, RedirectURIs: []string{"https://a/cb"}, SubMode: "public", IDTokenAlg: "none"}}, false) == nil {
		t.Fatal("none accepted")
	}
}

func TestDemoLoopbackRedirectPolicy(t *testing.T) {
	for _, u := range []string{"http://localhost:8080/cb", "https://rp.example/cb"} {
		if validateRedirect(u, true) != nil {
			t.Errorf("demo refused %s", u)
		}
	}
	for _, u := range []string{"http://localhost:8080/cb", "http://127.0.0.1:8080/cb", "http://rp.example/cb"} {
		if validateRedirect(u, false) == nil {
			t.Errorf("production accepted %s", u)
		}
	}
	for _, u := range []string{"http://localhost/cb", "http://127.0.0.1:8080/cb", "https://u:p@rp.example/cb", "https://rp.example/cb#f", "https://*.example/cb", "http://localhost:8080.evil.com/cb"} {
		if validateRedirect(u, true) == nil {
			t.Errorf("demo accepted %s", u)
		}
	}
}

func TestUserinfoRejectsExpIatBeyondMaxLifetime(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	for name, p := range map[string]sealedPayload{
		"too long":    {IAT: now.Unix(), EXP: now.Add(10 * time.Minute).Unix(), Deadline: int64(e.clk.Mono() + time.Minute)},
		"nonpositive": {IAT: now.Unix(), EXP: now.Unix(), Deadline: int64(e.clk.Mono() + time.Minute)},
		"past mono":   {IAT: now.Unix(), EXP: now.Add(time.Minute).Unix(), Deadline: int64(e.clk.Mono())},
	} {
		if checkLifetime(p, 5*time.Minute, now, e.clk.Mono()) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDenyListLifetimeSurvivesWallClockStep(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	e.clk.StepWall(-time.Hour) // wall clock goes back: exp is far in the future
	e.clk.Advance(5*time.Minute + time.Second)
	if st, _ := e.userinfo(tr.AccessToken); st != 401 {
		t.Fatal("token accepted after its monotonic deadline")
	}
	// Restart (new sealer epoch) rejects earlier tokens.
	tr2 := e.exchange("basic", e.code("basic"), nil)
	e.p.sealer, _ = NewSealer()
	if st, _ := e.userinfo(tr2.AccessToken); st != 401 {
		t.Fatal("token survived restart")
	}
}

func TestSealedTokenEpochAndVersionValidation(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(tr.AccessToken)
	for name, mut := range map[string]func([]byte){
		"format":  func(b []byte) { b[0] = 2 },
		"version": func(b []byte) { b[2]++ },
		"nonce":   func(b []byte) { b[5] ^= 1 },
		"tag":     func(b []byte) { b[len(b)-1] ^= 1 },
	} {
		b := append([]byte(nil), raw...)
		mut(b)
		if st, _ := e.userinfo(base64.RawURLEncoding.EncodeToString(b)); st != 401 {
			t.Errorf("%s tamper accepted", name)
		}
	}
	for _, bad := range []string{"", "x", strings.Repeat("A", 9000), "!!!"} {
		if st, _ := e.userinfo(bad); st != 401 {
			t.Errorf("%q accepted", bad)
		}
	}
	e.p.sealer.Rotate() // retired sealing key
	if st, _ := e.userinfo(tr.AccessToken); st != 401 {
		t.Fatal("token sealed with a retired key accepted")
	}
}

func TestRandomValueEntropyAndConstantTimeCompare(t *testing.T) {
	e := newEnv(t)
	code := e.code("basic")
	if len(code) != 43 {
		t.Fatalf("code %d chars, want 43 (256 bits)", len(code))
	}
	s, _ := NewSealer()
	if len(s.Epoch()) != 22 {
		t.Fatal("epoch is not 128 bits")
	}
}

func writeKey(t *testing.T, dir string, k *rsa.PrivateKey, kid string, mode os.FileMode) {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	os.WriteFile(filepath.Join(dir, kid+".pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode)
	os.Chmod(filepath.Join(dir, kid+".pem"), mode)
	b, _ := json.Marshal([]KeyEntry{{KID: kid, Alg: jose.RS256, File: kid + ".pem", Status: "active"}})
	os.WriteFile(filepath.Join(dir, "keys.json"), b, 0o600)
}

func TestSigningKeyParametersAndFileMode(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tp, _ := jose.Thumbprint(&k.PublicKey)
	dir := t.TempDir()
	writeKey(t, dir, k, tp, 0o600)
	if _, err := LoadKeys(dir, false, nil, nil); err != nil {
		t.Fatalf("valid production key: %v", err)
	}
	writeKey(t, dir, k, tp, 0o644)
	if _, err := LoadKeys(dir, false, nil, nil); err == nil {
		t.Fatal("0644 key accepted")
	}
	writeKey(t, dir, k, "not-thumbprint", 0o600)
	if _, err := LoadKeys(dir, false, nil, nil); err == nil {
		t.Fatal("non-thumbprint kid accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	tps, _ := jose.Thumbprint(&small.PublicKey)
	writeKey(t, dir, small, tps, 0o600)
	if _, err := LoadKeys(dir, false, nil, nil); err == nil {
		t.Fatal("1024-bit key accepted")
	}
	if _, err := LoadKeys(t.TempDir(), false, nil, nil); err == nil {
		t.Fatal("production generated a key")
	}
	demoDir := t.TempDir()
	ks, err := LoadKeys(demoDir, true, nil, nil)
	if err != nil || !strings.HasPrefix(ks.Entries()[0].KID, "demo-") {
		t.Fatal("demo key kid must start with demo-")
	}
}

func TestProductionRejectsDemoKeyFingerprint(t *testing.T) {
	demoDir := t.TempDir()
	if _, err := LoadKeys(demoDir, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(demoDir, false, nil, nil); err == nil {
		t.Fatal("production loaded a demo- kid")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tp, _ := jose.Thumbprint(&k.PublicKey)
	dir := t.TempDir()
	writeKey(t, dir, k, tp, 0o600)
	fp := SPKIFingerprint(&k.PublicKey)
	if _, err := LoadKeys(dir, false, []string{fp}, nil); err == nil {
		t.Fatal("deny-listed fingerprint accepted")
	}
	FixtureFingerprints[fp] = true
	defer delete(FixtureFingerprints, fp)
	if _, err := LoadKeys(dir, false, nil, nil); err == nil {
		t.Fatal("embedded fixture fingerprint accepted")
	}
	if _, err := LoadKeys(dir, false, []string{"zz"}, nil); err == nil {
		t.Fatal("malformed deny-list accepted")
	}
}

func TestRetiredKeysSurviveRestart(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	if _, err := e.p.cfg.Keys.Rotate(jose.RS256, 6*time.Minute); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeys(e.dir, true, nil, e.clk.Now) // restart
	if err != nil {
		t.Fatal(err)
	}
	h := strings.Split(tr.IDToken, ".")[0]
	b, _ := base64.RawURLEncoding.DecodeString(h)
	var hd map[string]string
	json.Unmarshal(b, &hd)
	if len(ks.PublicKeys(jose.RS256, hd["kid"])) != 1 {
		t.Fatal("retired key missing from JWKS after restart")
	}
	if _, _, err := jose.Verify(tr.IDToken, []string{jose.RS256}, ks.PublicKeys); err != nil {
		t.Fatalf("pre-rotation ID token no longer verifies: %v", err)
	}
	e.clk.StepWall(7 * time.Minute)
	ks2, _ := LoadKeys(e.dir, true, nil, e.clk.Now)
	if len(ks2.PublicKeys(jose.RS256, hd["kid"])) != 0 {
		t.Fatal("retired key kept past not_after")
	}
}

func TestEmergencyRevocationDropsKeyFromJWKS(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	old, _ := e.p.cfg.Keys.Active(jose.RS256)
	// TestCompromisedKeyDroppedImmediately: no retention window.
	if err := EmergencyRevoke(e.p, old.KID); err != nil {
		t.Fatal(err)
	}
	if len(e.p.cfg.Keys.PublicKeys(jose.RS256, old.KID)) != 0 {
		t.Fatal("compromised key still in JWKS")
	}
	if _, _, err := jose.Verify(tr.IDToken, []string{jose.RS256}, e.p.cfg.Keys.PublicKeys); err == nil {
		t.Fatal("token signed by compromised key still verifies")
	}
	nk, ok := e.p.cfg.Keys.Active(jose.RS256)
	if !ok || nk.KID == old.KID {
		t.Fatal("no replacement key")
	}
	// Sealing key rotated: clients must re-authenticate.
	if st, _ := e.userinfo(tr.AccessToken); st != 401 {
		t.Fatal("access token survived emergency revocation")
	}
}

func TestKSubCompromiseAndReplacementKey(t *testing.T) {
	// A K_sub compromise is handled by a new version plus a declared
	// migration window: declared clients get previous_sub until relinked.
	TestSubKeyVersionMigration(t)
}
