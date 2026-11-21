// Command demo-rp is a tiny OpenID Connect relying party for the eidbridge
// demo. It uses only standard OIDC client libraries (no eID protocol code),
// shows the verified claims and, with PRODUCTION=1, rejects demo tokens.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// backchannel rewrites the public issuer host to the container-network host
// for server-to-server calls (discovery, JWKS, token, userinfo).
type backchannel struct{ from, to string }

func (b backchannel) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.to != "" && r.URL.Host == b.from {
		r = r.Clone(r.Context())
		r.URL.Host = b.to
		r.Host = b.to
	}
	return http.DefaultTransport.RoundTrip(r)
}

type pendingLogin struct {
	state, nonce, verifier string
	at                     time.Time
}

func main() {
	issuer := env("ISSUER", "http://localhost:8080/demo")
	public := env("PUBLIC_URL", "http://localhost:8081")
	listen := env("LISTEN", ":8081")
	production := os.Getenv("PRODUCTION") == "1"
	iu, _ := url.Parse(issuer)
	bc := ""
	if v := os.Getenv("BACKCHANNEL_HOST"); v != "" {
		bc = v
	}
	hc := &http.Client{Transport: backchannel{from: iu.Host, to: bc}, Timeout: 15 * time.Second}
	ctx := oidc.ClientContext(context.Background(), hc)
	var provider *oidc.Provider
	var err error
	for i := 0; i < 60; i++ {
		if provider, err = oidc.NewProvider(ctx, issuer); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("discovery: %v", err)
	}
	conf := oauth2.Config{ClientID: env("CLIENT_ID", "demo-rp"), ClientSecret: env("CLIENT_SECRET", "demo-client-secret-not-for-production-use"),
		Endpoint: provider.Endpoint(), RedirectURL: public + "/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}}
	conf.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	verifier := provider.Verifier(&oidc.Config{ClientID: conf.ClientID})
	var mu sync.Mutex
	pending := map[string]pendingLogin{}
	page := template.Must(template.New("p").Parse(pageTmpl))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		page.Execute(w, map[string]any{"Start": true, "Production": production})
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		p := pendingLogin{state: rnd(), nonce: rnd(), verifier: oauth2.GenerateVerifier(), at: time.Now()}
		mu.Lock()
		pending[p.state] = p
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "demo_rp_state", Value: p.state, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
		http.Redirect(w, r, conf.AuthCodeURL(p.state, oidc.Nonce(p.nonce), oauth2.S256ChallengeOption(p.verifier)), http.StatusFound)
	})
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c, err := r.Cookie("demo_rp_state")
		mu.Lock()
		p, ok := pending[q.Get("state")]
		delete(pending, q.Get("state"))
		mu.Unlock()
		if err != nil || !ok || c.Value != q.Get("state") || time.Since(p.at) > 5*time.Minute {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		if q.Get("iss") != issuer {
			http.Error(w, "issuer mismatch (RFC 9207)", http.StatusBadRequest)
			return
		}
		if e := q.Get("error"); e != "" {
			page.Execute(w, map[string]any{"Error": e})
			return
		}
		tok, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(p.verifier))
		if err != nil {
			http.Error(w, "code exchange failed", http.StatusBadGateway)
			return
		}
		raw, _ := tok.Extra("id_token").(string)
		idt, err := verifier.Verify(ctx, raw)
		if err != nil || idt.Nonce != p.nonce {
			http.Error(w, "ID token rejected", http.StatusBadRequest)
			return
		}
		var claims map[string]any
		idt.Claims(&claims)
		if production && (claims["acr"] == "demo" || claims["eid_env"] == "demo" || strings.HasSuffix(idt.Issuer, "/demo")) {
			http.Error(w, "demo identities are refused in production", http.StatusForbidden)
			return
		}
		b, _ := json.MarshalIndent(claims, "", "  ")
		page.Execute(w, map[string]any{"Claims": string(b), "Sub": idt.Subject})
	})
	log.Printf("demo-rp listening on %s (issuer %s)", listen, issuer)
	log.Fatal(http.ListenAndServe(listen, nil))
}

func rnd() string {
	b := make([]byte, 24)
	rand.Read(b)
	s := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(s[:24])
}

const pageTmpl = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Demo relying party</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}pre{background:#f3f3f3;padding:1rem;overflow:auto}.b{display:inline-block;padding:.7rem 1rem;background:#0b4f9c;color:#fff;text-decoration:none;border-radius:.4rem}</style></head><body>
<h1>Demo relying party</h1>
<p>This sample app uses standard OpenID Connect only. Demo identities are test accounts.</p>
{{if .Start}}<p><a class="b" href="/login">Log in with eID (demo)</a></p>{{end}}
{{if .Error}}<p role="alert">Login ended: {{.Error}}</p><p><a href="/">Start again</a></p>{{end}}
{{if .Claims}}<h2>Verified claims</h2><p>Account key (sub): <code>{{.Sub}}</code></p><pre id="claims">{{.Claims}}</pre><p><a href="/">Log in again</a></p>{{end}}
<p><small>Unofficial, community-maintained software. Not affiliated with, endorsed by or certified by the operators of Smart-ID, Mobile-ID, the Estonian ID-card or any EUDI Wallet.</small></p>
</body></html>`
