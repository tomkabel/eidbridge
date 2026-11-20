package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

func TestDiscoveryDocument(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.srv.URL + "/demo/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if d["issuer"] != e.p.cfg.Issuer || d["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("discovery: %v", d)
	}
	if cc := d["code_challenge_methods_supported"].([]any); len(cc) != 1 || cc[0] != "S256" {
		t.Fatal("code_challenge_methods_supported must be [S256]")
	}
	if rt := d["response_types_supported"].([]any); len(rt) != 1 || rt[0] != "code" {
		t.Fatal("code only")
	}
	for _, k := range []string{"claims_parameter_supported", "request_parameter_supported", "request_uri_parameter_supported"} {
		if d[k] != false {
			t.Errorf("%s must be false", k)
		}
	}
}

func TestCodeExchangeAndGoOIDCValidation(t *testing.T) {
	e := newEnv(t)
	for _, client := range []string{"basic", "post", "pkj"} {
		tr := e.exchange(client, e.code(client), nil)
		if tr.Status != 200 || tr.IDToken == "" || tr.AccessToken == "" {
			t.Fatalf("%s: %+v", client, tr)
		}
		// ID token validates with github.com/coreos/go-oidc in a test client.
		ctx := gooidc.InsecureIssuerURLContext(context.Background(), e.p.cfg.Issuer)
		prov, err := gooidc.NewProvider(ctx, e.srv.URL+"/demo")
		if err != nil {
			t.Fatal(err)
		}
		algs := []string{"RS256"}
		if client == "pkj" {
			algs = []string{"ES256"}
		}
		v := prov.Verifier(&gooidc.Config{ClientID: client, SupportedSigningAlgs: algs, Now: e.clk.Now})
		idt, err := v.Verify(ctx, tr.IDToken)
		if err != nil {
			t.Fatalf("%s: go-oidc rejected the ID token: %v", client, err)
		}
		if idt.Nonce != "n-1" || idt.Subject == "" {
			t.Fatalf("%s: nonce/sub", client)
		}
	}
}

func TestPKCEFailure(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), func(f url.Values, _ *http.Request) { f.Set("code_verifier", strings.Repeat("a", 43)) })
	if tr.Status != 400 || tr.Error != "invalid_grant" {
		t.Fatalf("%+v", tr)
	}
	tr = e.exchange("basic", e.code("basic"), func(f url.Values, _ *http.Request) { f.Del("code_verifier") })
	if tr.Error != "invalid_grant" {
		t.Fatalf("missing verifier: %+v", tr)
	}
}

func TestCodeReplayAndUserinfoRevocation(t *testing.T) {
	e := newEnv(t)
	code := e.code("basic")
	tr := e.exchange("basic", code, nil)
	if tr.Status != 200 {
		t.Fatal(tr)
	}
	if st, _ := e.userinfo(tr.AccessToken); st != 200 {
		t.Fatalf("userinfo before replay: %d", st)
	}
	// TestCodeReplayDenyListRejectsUserinfo
	if r := e.exchange("basic", code, nil); r.Error != "invalid_grant" {
		t.Fatalf("replay: %+v", r)
	}
	if st, _ := e.userinfo(tr.AccessToken); st != 401 {
		t.Fatal("token family not revoked after replay")
	}
}

func TestWrongRedirectURIAndExpiredCode(t *testing.T) {
	e := newEnv(t)
	tr := e.exchange("basic", e.code("basic"), func(f url.Values, _ *http.Request) { f.Set("redirect_uri", "http://localhost:9000/other") })
	if tr.Error != "invalid_grant" {
		t.Fatalf("wrong redirect: %+v", tr)
	}
	code := e.code("basic")
	e.clk.Advance(61 * time.Second)
	if tr := e.exchange("basic", code, nil); tr.Error != "invalid_grant" {
		t.Fatalf("expired: %+v", tr)
	}
}

func TestFailedExchangeStillConsumesCode(t *testing.T) {
	e := newEnv(t)
	for name, bad := range map[string]func(url.Values, *http.Request){
		"pkce":     func(f url.Values, _ *http.Request) { f.Set("code_verifier", strings.Repeat("b", 43)) },
		"redirect": func(f url.Values, _ *http.Request) { f.Set("redirect_uri", "http://localhost:9000/x") },
		"client":   func(f url.Values, r *http.Request) { r.SetBasicAuth("basic", "wrong-wrong-wrong-wrong-wrong-wrong") },
	} {
		code := e.code("basic")
		if tr := e.exchange("basic", code, bad); tr.Status == 200 {
			t.Fatalf("%s: bad exchange succeeded", name)
		}
		if tr := e.exchange("basic", code, nil); tr.Error != "invalid_grant" {
			t.Fatalf("%s: retry after failed exchange: %+v", name, tr)
		}
	}
}

func TestFailedExchangeLeavesFamilylessTombstone(t *testing.T) {
	e := newEnv(t)
	code := e.code("basic")
	good := e.exchange("basic", code, nil)
	e.exchange("basic", code, func(f url.Values, _ *http.Request) { f.Set("code_verifier", strings.Repeat("c", 43)) })
	if st, _ := e.userinfo(good.AccessToken); st != 401 {
		t.Fatal("correct-then-wrong did not revoke the family")
	}
}

func TestCodeIssuedToAnotherClient(t *testing.T) {
	e := newEnv(t)
	code := e.code("basic")
	if tr := e.exchange("post", code, nil); tr.Error != "invalid_grant" {
		t.Fatalf("%+v", tr)
	}
}

func TestConcurrentCodeExchangeSingleWinner(t *testing.T) {
	e := newEnv(t)
	code := e.code("basic")
	var wins atomic.Int32
	var wg sync.WaitGroup
	var tok atomic.Value
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tr := e.exchange("basic", code, nil); tr.Status == 200 {
				wins.Add(1)
				tok.Store(tr.AccessToken)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners", wins.Load())
	}
	// TestConcurrentExchangeLoserDenyListsWinnerFamily
	if st, _ := e.userinfo(tok.Load().(string)); st != 401 {
		t.Fatal("loser did not revoke winner's family")
	}
}
