package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/jose"
	"github.com/tomkabel/eidbridge/internal/store"
)

const secret = "s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t"

var testIdentity = authn.Identity{Method: "smartid", AMR: []string{"smartid"}, IDType: "PNO", Country: "EE", Code: "40404040009",
	GivenName: "OK", FamilyName: "TEST", CertLevel: "QUALIFIED"}

// fakeFront completes every flow immediately with testIdentity, the way the
// web layer does after a verified login.
type fakeFront struct {
	p   *Provider
	id  *authn.Identity
	ttl time.Duration
	err string
}

func (f *fakeFront) Begin(w http.ResponseWriter, r *http.Request, req *AuthRequest) {
	res, err := f.p.Reserve(time.Minute)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	id := testIdentity
	if f.id != nil {
		id = *f.id
	}
	u, err := f.p.Complete(req, res, &id, f.p.cfg.Clock.Now())
	if err != nil {
		res.Release()
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (f *fakeFront) ErrorPage(w http.ResponseWriter, r *http.Request, status int, reason string) {
	f.err = reason
	w.WriteHeader(status)
	w.Write([]byte("error page: " + reason))
}

type env struct {
	t     *testing.T
	p     *Provider
	srv   *httptest.Server
	clk   *clock.Fake
	front *fakeFront
	dir   string
	ecKey *ecdsa.PrivateKey
	codes *store.Codes
}

type envOpt func(*Config)

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(time.Now())
	ks, err := LoadKeys(dir, true, nil, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.add(jose.ES256); err != nil {
		t.Fatal(err)
	}
	ks.save()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecj, _ := jose.PublicJWK(&ec.PublicKey, "c1", jose.ES256)
	srv := httptest.NewUnstartedServer(nil)
	issuer := "http://localhost:" + strings.Split(srv.Listener.Addr().String(), ":")[1] + "/demo"
	codes := store.NewCodes(store.CodesConfig{Cap: 100, CodeTTL: 60 * time.Second, TombstoneTTL: 5*time.Minute + 30*time.Second, Clock: clk})
	cfg := Config{Issuer: issuer, Demo: true, Keys: ks, AccessTokenTTL: 5 * time.Minute, CodeTTL: 60 * time.Second, ClockSkew: 30 * time.Second,
		Methods: []string{"smartid"}, Clock: clk, Codes: codes,
		Subjects: &Subjects{Keys: map[int][]byte{1: make32(1), 2: make32(2)}, Current: 1},
		Clients: []Client{
			{ID: "basic", Secret: secret, AuthMethod: AuthBasic, RedirectURIs: []string{"http://localhost:9000/cb"}, SubMode: "pairwise"},
			{ID: "post", Secret: secret, AuthMethod: AuthPost, RedirectURIs: []string{"http://localhost:9000/cb"}, SubMode: "public", PersonalCode: true},
			{ID: "pkj", AuthMethod: AuthPrivKey, JWKS: []jose.JWK{ecj}, RedirectURIs: []string{"http://localhost:9000/cb"}, SubMode: "pairwise", IDTokenAlg: jose.ES256},
		}}
	for _, o := range opts {
		o(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFront{p: p}
	p.SetFrontend(f)
	mux := http.NewServeMux()
	p.Register(mux)
	srv.Config.Handler = mux
	srv.Start()
	t.Cleanup(srv.Close)
	return &env{t: t, p: p, srv: srv, clk: clk, front: f, dir: dir, ecKey: ec, codes: codes}
}

func make32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-RFC7636"

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func (e *env) authParams(client string) url.Values {
	return url.Values{"client_id": {client}, "redirect_uri": {"http://localhost:9000/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
}

// authorize returns the redirect Location.
func (e *env) authorize(q url.Values) *url.URL {
	e.t.Helper()
	resp, err := noRedirect.Get(e.srv.URL + "/demo/authorize?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("authorize status %d", resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	return u
}

func (e *env) code(client string) string {
	e.t.Helper()
	u := e.authorize(e.authParams(client))
	c := u.Query().Get("code")
	if c == "" {
		e.t.Fatalf("no code: %s", u)
	}
	return c
}

type tokenResp struct {
	Status      int
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	Desc        string `json:"error_description"`
	ExpiresIn   int    `json:"expires_in"`
	header      http.Header
}

func (e *env) exchange(client, code string, mod func(url.Values, *http.Request)) tokenResp {
	e.t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:9000/cb"}, "code_verifier": {verifier}}
	if client == "post" {
		f.Set("client_id", "post")
		f.Set("client_secret", secret)
	}
	if client == "pkj" {
		f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		f.Set("client_assertion", e.assertion(nil))
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/demo/token", nil)
	if client == "basic" {
		req.SetBasicAuth("basic", secret)
	}
	if mod != nil {
		mod(f, req)
	}
	req.Body = http.NoBody
	req2, _ := http.NewRequest(http.MethodPost, req.URL.String(), strings.NewReader(f.Encode()))
	req2.Header = req.Header.Clone()
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req2)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr tokenResp
	json.NewDecoder(resp.Body).Decode(&tr)
	tr.Status, tr.header = resp.StatusCode, resp.Header
	return tr
}

func (e *env) assertion(mod func(map[string]any)) string {
	cl := map[string]any{"iss": "pkj", "sub": "pkj", "aud": e.p.cfg.Issuer, "exp": e.clk.Now().Add(30 * time.Second).Unix(), "jti": randID()}
	if mod != nil {
		mod(cl)
	}
	s, err := jose.Sign(&jose.Key{KID: "c1", Alg: jose.ES256, Private: e.ecKey}, "JWT", cl)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (e *env) userinfo(tok string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/demo/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func claims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}
