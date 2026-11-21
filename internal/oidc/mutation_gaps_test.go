package oidc

// Tests added for gremlins survivors (2026-11-21).

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/clock"
)

func TestClientSecretLength(t *testing.T) {
	mk := func(sec string) []Client {
		return []Client{{ID: "x", Secret: sec, AuthMethod: AuthBasic, RedirectURIs: []string{"https://a.example/cb"}, SubMode: "public"}}
	}
	if err := validateClients(mk(strings.Repeat("a", 32)), false); err != nil {
		t.Fatalf("32-byte secret: %v", err)
	}
	if validateClients(mk(strings.Repeat("a", 31)), false) == nil {
		t.Fatal("31-byte secret accepted")
	}
}

func TestPairwiseSectorCollisions(t *testing.T) {
	c := func(id, sector string) Client {
		return Client{ID: id, Secret: secret, AuthMethod: AuthBasic, RedirectURIs: []string{"https://same.example/" + id}, SubMode: "pairwise", SectorID: sector}
	}
	for name, tc := range map[string]struct {
		cs []Client
		ok bool
	}{
		"no sector ids":                   {[]Client{c("a", ""), c("b", "")}, true},
		"sector equals other client id":   {[]Client{c("a", ""), c("b", "a")}, false},
		"client id equals earlier sector": {[]Client{c("b", "a"), c("a", "")}, false},
		"two equal explicit sectors":      {[]Client{c("a", "s.example"), c("b", "s.example")}, false},
		"distinct explicit sectors":       {[]Client{c("a", "s1.example"), c("b", "s2.example")}, true},
		"public client ignores sectors":   {[]Client{c("a", "s.example"), {ID: "b", Secret: secret, AuthMethod: AuthBasic, RedirectURIs: []string{"https://s.example/cb"}, SubMode: "public", SectorID: "s.example"}}, true},
	} {
		if err := validateClients(tc.cs, false); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBasicWithMismatchedBodyClientID(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) { f.Set("client_id", "post") })
	if tr.Status != 401 || tr.Error != "invalid_client" {
		t.Fatalf("basic with body client_id=post: %+v", tr)
	}
	tr = e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) { f.Set("client_id", "basic") })
	if tr.Status != 200 {
		t.Fatalf("basic with matching body client_id: %+v", tr)
	}
	tr = e.exchange("pkj", e.code("pkj"), func(f url.Values, r *http.Request) { f.Set("client_id", "basic") })
	if tr.Status != 401 {
		t.Fatalf("private_key_jwt with body client_id=basic: %+v", tr)
	}
}

func TestAssertionBounds(t *testing.T) {
	e := newEnv(t)
	e.clk.StepWall(-time.Duration(e.clk.Now().Nanosecond())) // whole seconds, so exp hits the bounds exactly
	for name, tc := range map[string]struct {
		mod func(map[string]any)
		ok  bool
	}{
		"jti 256":        {func(c map[string]any) { c["jti"] = strings.Repeat("j", 256) }, true},
		"jti 257":        {func(c map[string]any) { c["jti"] = strings.Repeat("k", 257) }, false},
		"exp now":        {func(c map[string]any) { c["exp"] = e.clk.Now().Unix() }, false},
		"exp at max":     {func(c map[string]any) { c["exp"] = e.clk.Now().Add(60*time.Second + e.p.cfg.ClockSkew).Unix() }, true},
		"exp beyond max": {func(c map[string]any) { c["exp"] = e.clk.Now().Add(61*time.Second + e.p.cfg.ClockSkew).Unix() }, false},
	} {
		tr := e.exchange("pkj", e.code("pkj"), func(f url.Values, r *http.Request) { f.Set("client_assertion", e.assertion(tc.mod)) })
		if (tr.Status == 200) != tc.ok {
			t.Errorf("%s: %+v", name, tr)
		}
	}
}

func TestJTIExpiryBoundaries(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := &jtiStore{cap: 1, m: map[string]time.Duration{}, clk: clk}
	if err := s.insert("c", "j1", time.Second); err != nil {
		t.Fatal(err)
	}
	if s.insert("c", "j1", time.Second) == nil {
		t.Fatal("replay inside the window accepted")
	}
	clk.Advance(time.Second) // exactly at expiry: the entry is gone
	if err := s.insert("c", "j2", time.Second); err != nil {
		t.Fatalf("cap 1 with an entry expiring now: %v", err)
	}
	clk.Advance(time.Second)
	if err := s.insert("c", "j2", time.Second); err != nil {
		t.Fatalf("same jti exactly at its expiry: %v", err)
	}
}

func TestProviderConfigBounds(t *testing.T) {
	for name, tc := range map[string]struct {
		mod func(*Config)
		ok  bool
	}{
		"access ttl 1s":    {func(c *Config) { c.AccessTokenTTL = time.Second }, true},
		"access ttl 999ms": {func(c *Config) { c.AccessTokenTTL = 999 * time.Millisecond }, false},
		"access ttl 300s":  {func(c *Config) { c.AccessTokenTTL = 300 * time.Second }, true},
		"access ttl 301s":  {func(c *Config) { c.AccessTokenTTL = 301 * time.Second }, false},
		"code ttl 60s":     {func(c *Config) { c.CodeTTL = 60 * time.Second }, true},
		"code ttl 61s":     {func(c *Config) { c.CodeTTL = 61 * time.Second }, false},
		"skew 0":           {func(c *Config) { c.ClockSkew = 0 }, true},
		"skew 120s":        {func(c *Config) { c.ClockSkew = 120 * time.Second }, true},
		"skew 121s":        {func(c *Config) { c.ClockSkew = 121 * time.Second }, false},
		"skew negative":    {func(c *Config) { c.ClockSkew = -time.Second }, false},
		"demo http other":  {func(c *Config) { c.Issuer = "http://example.com/demo" }, false},
		"prod http local":  {func(c *Config) { c.Issuer, c.Demo = "http://localhost:1", false }, false},
	} {
		base := newEnv(t).p.cfg
		tc.mod(&base)
		_, err := New(base)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStateNonceVerifierLengths(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		key string
		n   int
		ok  bool
	}{
		"state 512": {"state", 512, true}, "state 513": {"state", 513, false},
		"nonce 512": {"nonce", 512, true}, "nonce 513": {"nonce", 513, false},
	} {
		q := e.authParams("basic")
		q.Set(tc.key, strings.Repeat("s", tc.n))
		u := e.authorize(q)
		if (u.Query().Get("code") != "") != tc.ok {
			t.Errorf("%s: %s", name, u)
		}
	}
	for n, ok := range map[int]bool{42: false, 43: true, 128: true, 129: false} {
		v := strings.Repeat("v", n)
		q := e.authParams("basic")
		q.Set("code_challenge", challenge(v))
		code := e.authorize(q).Query().Get("code")
		tr := e.exchange("basic", code, func(f url.Values, r *http.Request) { f.Set("code_verifier", v) })
		if (tr.Status == 200) != ok {
			t.Errorf("verifier length %d: %+v", n, tr)
		}
	}
}

func TestExpiresInAndErrorHeaders(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), nil)
	if tr.ExpiresIn != int(e.p.cfg.AccessTokenTTL/time.Second) {
		t.Fatalf("expires_in %d", tr.ExpiresIn)
	}
	bad := e.exchange("basic", "nope", nil)
	if bad.Status != 400 || bad.header.Get("Retry-After") != "" || bad.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("400 headers %v", bad.header)
	}
	unauth := e.exchange("basic", e.code("basic"), func(f url.Values, r *http.Request) { r.SetBasicAuth("basic", "wrong") })
	if unauth.Status != 401 || unauth.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("401 headers %v", unauth.header)
	}
}

func TestUserinfoRefusesTokenInBody(t *testing.T) {
	e := newEnv(t)
	tok := e.exchange("basic", e.code("basic"), nil).AccessToken
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/demo/userinfo", strings.NewReader("access_token="+tok))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 && resp.StatusCode != 400 {
		t.Fatalf("token in body accepted: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, e.srv.URL+"/demo/userinfo", strings.NewReader("x=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST userinfo with header token: %d", resp.StatusCode)
	}
}

func TestBirthdateClaim(t *testing.T) {
	e := newEnv(t)
	id := testIdentity
	id.Extra = map[string]string{"birthdate": "1990-05-17"}
	e.front.id = &id
	tok := e.exchange("basic", e.code("basic"), nil).AccessToken
	if _, ui := e.userinfo(tok); ui["birthdate"] != "1990-05-17" {
		t.Fatalf("birthdate missing: %v", ui)
	}
	e.front.id = nil
	tok = e.exchange("basic", e.code("basic"), nil).AccessToken
	if _, ui := e.userinfo(tok); ui["birthdate"] != nil {
		t.Fatalf("empty birthdate claimed: %v", ui)
	}
	_ = authn.Identity{}
}

func TestSealedShortTokensNoPanic(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= 31; n++ {
		raw := make([]byte, n)
		if n > 0 {
			raw[0] = atFormat
		}
		if _, err := s.open(base64.RawURLEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("raw length %d accepted", n)
		}
	}
}

func TestCheckLifetimeBoundaries(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	p := sealedPayload{IAT: now.Unix() - 10, EXP: now.Unix() + 290, Deadline: int64(time.Hour)}
	if err := checkLifetime(p, 300*time.Second, now, 0); err != nil {
		t.Fatalf("life exactly max: %v", err)
	}
	p.EXP++
	if checkLifetime(p, 300*time.Second, now, 0) == nil {
		t.Fatal("life over max accepted")
	}
	p = sealedPayload{IAT: now.Unix() - 10, EXP: now.Unix(), Deadline: int64(time.Hour)}
	if checkLifetime(p, 300*time.Second, now, 0) == nil {
		t.Fatal("token accepted at exp")
	}
	p = sealedPayload{IAT: now.Unix(), EXP: now.Unix(), Deadline: int64(time.Hour)}
	if checkLifetime(p, 300*time.Second, now.Add(-time.Second), 0) == nil {
		t.Fatal("zero lifetime accepted")
	}
	p = sealedPayload{IAT: now.Unix() - 10, EXP: now.Unix() + 100, Deadline: 5}
	if checkLifetime(p, 300*time.Second, now, 5) == nil {
		t.Fatal("token accepted at the monotonic deadline")
	}
}

func TestMigrationWindow(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	m := &Migration{Started: start, Days: 2}
	if !m.Active(start.Add(48*time.Hour-time.Second)) || m.Active(start.Add(48*time.Hour)) {
		t.Fatal("migration window boundaries")
	}
	for days, ok := range map[int]bool{0: false, 1: true, 90: true, 91: false} {
		s := &Subjects{Keys: map[int][]byte{1: make32(1), 2: make32(2)}, Current: 2, Migration: &Migration{From: 1, To: 2, Days: days, Started: start}}
		if err := s.Validate(); (err == nil) != ok {
			t.Errorf("days %d: %v", days, err)
		}
	}
}

func TestDenyListFingerprints(t *testing.T) {
	good := strings.Repeat("ab", 32)
	if _, err := LoadKeys(t.TempDir(), true, []string{good}, nil); err != nil {
		t.Fatalf("valid fingerprint: %v", err)
	}
	for _, bad := range []string{good[:62], good + "ab", strings.Repeat("zz", 32)} {
		if _, err := LoadKeys(t.TempDir(), true, []string{bad}, nil); err == nil {
			t.Errorf("fingerprint %q accepted", bad)
		}
	}
}

func TestErrorRedirectEchoesStateUpTo512(t *testing.T) {
	e := newEnv(t)
	for n, echoed := range map[int]bool{512: true, 513: false} {
		q := e.authParams("basic")
		q.Set("state", strings.Repeat("s", n))
		q.Set("code_challenge_method", "plain") // forces an error redirect
		u := e.authorize(q)
		if u.Query().Get("error") == "" || (u.Query().Get("state") != "") != echoed {
			t.Errorf("state %d: %s", n, u)
		}
	}
}

func TestKeyRetentionRevokeAndOrder(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clk := func() time.Time { return now }
	dir := t.TempDir()
	ks, err := LoadKeys(dir, true, nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	n0 := len(ks.JWKS())
	if _, err := ks.Rotate(ks.Entries()[0].Alg, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := len(ks.JWKS()); n != n0+1 {
		t.Fatalf("within retention: %d keys", n)
	}
	j := ks.JWKS()
	for i := 1; i < len(j); i++ {
		if j[i-1].KID > j[i].KID {
			t.Fatal("JWKS not sorted by kid")
		}
	}
	now = now.Add(2 * time.Hour)
	if n := len(ks.JWKS()); n != n0 {
		t.Fatalf("after retention: %d keys", n)
	}
	reloaded, err := LoadKeys(dir, true, nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(reloaded.Entries()); n != n0 {
		t.Fatalf("reload kept %d entries past retention", n)
	}
	before := len(ks.Entries())
	if ks.Revoke("no-such-kid") == nil || len(ks.Entries()) != before {
		t.Fatal("revoking an unknown kid changed the key set")
	}
}
