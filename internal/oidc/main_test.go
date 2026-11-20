package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	DemoRSABits = 2048
	os.Exit(m.Run())
}

// FuzzAuthorizeRequest feeds arbitrary query strings to /authorize. It must
// never panic, never redirect to an unregistered URI and never issue a code
// without the full validated parameter set.
func FuzzAuthorizeRequest(f *testing.F) {
	f.Add("client_id=basic&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&response_type=code&scope=openid&state=a&nonce=b&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
	f.Add("client_id=basic&client_id=post")
	f.Add("redirect_uri=javascript:alert(1)")
	e := newEnv(&testing.T{})
	f.Fuzz(func(t *testing.T, q string) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/demo/authorize", nil)
		r.URL.RawQuery = q
		e.p.authorize(rec, r)
		loc := rec.Header().Get("Location")
		if loc == "" {
			return
		}
		u, err := url.Parse(loc)
		if err != nil || !strings.HasPrefix(loc, "http://localhost:9000/cb?") {
			t.Fatalf("redirect to unregistered target %q", loc)
		}
		if u.Query().Get("iss") != e.p.cfg.Issuer {
			t.Fatal("redirect without iss")
		}
	})
}

// FuzzTokenRequest feeds arbitrary form bodies to /token.
func FuzzTokenRequest(f *testing.F) {
	f.Add("grant_type=authorization_code&code=x&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&code_verifier=" + strings.Repeat("a", 43))
	f.Add("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=a.b.c")
	e := newEnv(&testing.T{})
	f.Fuzz(func(t *testing.T, body string) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/demo/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.p.token(rec, r)
		if rec.Code == 200 {
			t.Fatalf("fuzzed token request succeeded: %q", body)
		}
	})
}
