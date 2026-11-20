//go:build redteam

package main

// Red-team harness (not part of the normal test run). It serves the real
// wiring in demo mode with every method on its fixture upstream, plus a
// "device" oracle that plays the user's ID card (Web eID) and wallet
// (EUDI), so a black-box tester can produce genuine device responses
// without seeing the implementation.
//
//	REDTEAM_DIR=/tmp/rt go test -tags redteam -run TestRedTeamHarness -timeout 0 ./cmd/eidbridge
//
// It writes $REDTEAM_DIR/harness.json and runs until $REDTEAM_DIR/stop exists.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
)

func TestRedTeamHarness(t *testing.T) {
	dir := os.Getenv("REDTEAM_DIR")
	if dir == "" {
		t.Skip("REDTEAM_DIR not set")
	}
	secret := "redteam-secret-redteam-secret-redteam-0001"
	clients := `[{"client_id":"rp-a","client_secret":"` + secret + `","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["http://localhost:18710/cb"],"sub_mode":"pairwise"},
{"client_id":"rp-b","client_secret":"` + secret + `","token_endpoint_auth_method":"client_secret_post","redirect_uris":["http://localhost:18711/cb"],"sub_mode":"public"},
{"client_id":"signer","client_secret":"` + secret + `","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["http://localhost:18712/cb"],"sub_mode":"pairwise","sector_id":"signer.example","signing_allowed":true}]`
	cf := filepath.Join(dir, "clients.json")
	os.WriteFile(cf, []byte(clients), 0o600)
	ln, err := net.Listen("tcp", "127.0.0.1:18700")
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{ReadHeaderTimeout: 10 * time.Second}}
	srv.StartTLS()
	defer srv.Close()
	env := map[string]string{"EIDBRIDGE_ISSUER": srv.URL, "EIDBRIDGE_LOG_LEVEL": "debug", "EIDBRIDGE_KEY_DIR": t.TempDir(),
		"EIDBRIDGE_CLIENTS_FILE": cf, "EIDBRIDGE_METHODS": "smartid,mobileid,webeid,eudi,smartid-v2",
		"EIDBRIDGE_SMARTID_ENV": "mock", "EIDBRIDGE_MOBILEID_ENV": "mock", "EIDBRIDGE_WEBEID_ENV": "mock", "EIDBRIDGE_EUDI_ENV": "mock",
		"EIDBRIDGE_SMARTID_FLOWS": "device-link,notification", "EIDBRIDGE_MOCK_DOCUMENT": "manual",
		"EIDBRIDGE_MOCK_LISTEN": "127.0.0.1:18701", "EIDBRIDGE_SIGNING_ENABLED": "true"}
	cfg, err := config.Load(func(k string) string { return env[k] }, true, filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	logf, _ := os.Create(filepath.Join(dir, "bridge-debug.log"))
	defer logf.Close()
	app, err := Build(cfg, newLogger(logf, true), clock.Real())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	srv.Config.Handler = app.Handler

	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}
	var mu sync.Mutex
	cards := map[string]*webeidtest.Leaf{
		"default":   webeidFixture.NewLeaf(webeidtest.LeafOptions{}),
		"second":    webeidFixture.NewLeaf(webeidtest.LeafOptions{SerialNumber: "PNOEE-60001019906"}),
		"signing":   webeidFixture.NewLeaf(webeidtest.LeafOptions{Signing: true}),
		"untrusted": webeidtest.NewPKI("untrusted").NewLeaf(webeidtest.LeafOptions{}),
	}
	wallets := map[string]*walletsim.Wallet{}
	wallet := func(name string) *walletsim.Wallet {
		mu.Lock()
		defer mu.Unlock()
		if w := wallets[name]; w != nil {
			return w
		}
		w := eudiFixture.Issue(walletsim.IssueOptions{}) // each wallet has its own holder key
		wallets[name] = w
		return w
	}
	dev := http.NewServeMux()
	dev.HandleFunc("POST /webeid/token", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Origin, Challenge, Alg, Card string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Alg == "" {
			in.Alg = "ES384"
		}
		c := cards[in.Card]
		if c == nil {
			c = cards["default"]
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(c.Token(in.Alg, in.Origin, in.Challenge))
	})
	dev.HandleFunc("POST /wallet/fetch", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ QR string }
		json.NewDecoder(r.Body).Decode(&in)
		req, err := walletsim.FetchRequest(insecure, in.QR)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		json.NewEncoder(w).Encode(req)
	})
	dev.HandleFunc("POST /wallet/present", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nonce, Aud, Wallet string
			Disclose           []string
			NoKB, WrongKBKey   bool
		}
		json.NewDecoder(r.Body).Decode(&in)
		o := walletsim.PresentOptions{Disclose: in.Disclose, NoKB: in.NoKB}
		if in.WrongKBKey {
			o.KBKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		json.NewEncoder(w).Encode(map[string]string{"vp_token": walletsim.VPToken(wallet(in.Wallet).Present(in.Nonce, in.Aud, o))})
	})
	dln, err := net.Listen("tcp", "127.0.0.1:18702")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(dln, dev)
	meta := map[string]any{"issuer": cfg.Issuer, "bridge": srv.URL, "smartid_mock_control": "http://127.0.0.1:18701",
		"device_oracle": "http://127.0.0.1:18702", "clients_file": cf, "debug_log": logf.Name()}
	b, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(filepath.Join(dir, "harness.json"), b, 0o644)
	t.Logf("harness up: %s", b)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
