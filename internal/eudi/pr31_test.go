package eudi

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func TestPR31StatusFreshness(t *testing.T) {
	e := newVEnv(t)
	now := time.Now().Truncate(time.Second)
	iat, exp := now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix()
	for _, tc := range []struct {
		name   string
		claims map[string]any
		ok     bool
	}{
		{"fresh", map[string]any{"iat": iat, "exp": exp}, true},
		{"missing expiration", map[string]any{"iat": iat}, false},
		{"missing issuance", map[string]any{"exp": exp}, false},
		{"expired now", map[string]any{"iat": iat, "exp": now.Unix()}, false},
		{"future issuance", map[string]any{"iat": now.Add(2 * time.Minute).Unix(), "exp": exp}, false},
		{"older than local cap", map[string]any{"iat": now.Add(-24*time.Hour - time.Second).Unix(), "exp": exp}, false},
		{"ttl replay", map[string]any{"iat": now.Add(-3 * time.Minute).Unix(), "exp": exp, "ttl": 60}, false},
		{"invalid ttl", map[string]any{"iat": iat, "exp": exp, "ttl": "600"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var compressed bytes.Buffer
			zw := zlib.NewWriter(&compressed)
			_, _ = zw.Write([]byte{0})
			_ = zw.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.claims["sub"] = "http://" + r.Host + "/status"
				tc.claims["status_list"] = map[string]any{"bits": 1, "lst": b64.EncodeToString(compressed.Bytes())}
				tok, err := signES(e.prov.SignerKey(), header{Alg: "ES256", Typ: "statuslist+jwt", X5C: []string{
					base64.StdEncoding.EncodeToString(e.prov.Signer.Raw), base64.StdEncoding.EncodeToString(e.prov.Inter.Raw),
				}}, tc.claims)
				if err != nil {
					t.Errorf("sign status token: %v", err)
					return
				}
				_, _ = w.Write([]byte(tok))
			}))
			defer srv.Close()
			s := StatusChecker{AllowedHosts: map[string]bool{srv.Listener.Addr().String(): true}}
			err := s.Check(context.Background(), statusRef(srv.URL+"/status", 0), smartid.NewTrustStore(e.prov.Root, e.prov.Inter), now)
			if tc.ok && err != nil {
				t.Fatalf("fresh status rejected: %v", err)
			}
			if !tc.ok && authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
				t.Fatalf("expected status unavailable, got %v", err)
			}
		})
	}
}
