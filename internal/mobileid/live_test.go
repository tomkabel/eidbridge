package mobileid

import (
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// capture is a recorded demo session: the hash the bridge sent and the raw
// status the service returned. Demo test numbers only (SK's published list).
type capture struct {
	Phone, Code, Hash string
	Status            json.RawMessage
	Captured          string
}

func liveClient(t *testing.T, status smartid.StatusChecker) *Client {
	t.Helper()
	ts, err := smartid.LoadCADir(filepath.Join("..", "..", "trust", "demo", "mobileid-auth-ca"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(Config{BaseURL: "https://tsp.demo.sk.ee/mid-api", RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO",
		HTTP: &http.Client{Timeout: 90 * time.Second}, Trust: ts, PolicyOIDs: []asn1.ObjectIdentifier{MIDPolicyOID}, Status: status})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLiveDemo runs against SK's public Mobile-ID demo (EIDBRIDGE_LIVE=1).
// With EIDBRIDGE_CAPTURE=1 it writes testdata/live/*.json for the replay
// tests.
func TestLiveDemo(t *testing.T) {
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1 to call tsp.demo.sk.ee")
	}
	// The demo OCSP responder answers revoked/certificateHold/1970 (the RFC
	// 6960 non-issued convention) for demo Mobile-ID certificates, as it
	// does for Smart-ID (ADR 0001); TestLiveDemoOCSPNonIssued records that.
	status := smartid.NoStatusCheck{Reason: "demo OCSP uses the non-issued convention"}
	for _, tc := range []struct{ name, phone, code, reason string }{
		{"ok", "+37269930366", "51307149560", ""},
		{"user-cancelled", "+37201100266", "60001019950", authn.ReasonRefused},
		{"not-mid-client", "+37200000266", "60001019939", authn.ReasonAccountUnusable},
		{"delivery-error", "+37207110066", "60001019947", authn.ReasonUpstreamError},
		{"signature-hash-mismatch", "+37200000666", "60001019961", authn.ReasonAccountUnusable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := liveClient(t, status)
			ctx := context.Background()
			s, err := c.Start(ctx, StartRequest{Phone: tc.phone, Code: tc.code, Lang3: "ENG", DisplayText: "eidbridge test"})
			if err != nil {
				t.Fatal(err)
			}
			hash := append([]byte(nil), s.Hash...)
			var st *Status
			var raw []byte
			for i := 0; i < 10; i++ {
				body, err := c.do(ctx, http.MethodGet, "/authentication/session/"+s.ID+"?timeoutMs=20000", nil)
				if err != nil {
					t.Fatal(err)
				}
				if st, err = ParseStatus(body); err != nil {
					t.Fatal(err)
				}
				if st.State == "COMPLETE" {
					raw = body
					break
				}
			}
			id, verr := c.Verify(ctx, s, st)
			t.Logf("%s: result=%s verify=%v", tc.name, st.Result, verr)
			if tc.reason == "" && (verr != nil || id.Code != tc.code) {
				t.Fatalf("live ok failed: %v", verr)
			}
			if tc.reason != "" && authn.ReasonOf(verr) != tc.reason {
				t.Fatalf("reason %s, want %s", authn.ReasonOf(verr), tc.reason)
			}
			if os.Getenv("EIDBRIDGE_CAPTURE") == "1" {
				b, _ := json.MarshalIndent(capture{Phone: tc.phone, Code: tc.code, Hash: base64.StdEncoding.EncodeToString(hash),
					Status: raw, Captured: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
				os.MkdirAll("testdata/live", 0o755)
				if err := os.WriteFile(filepath.Join("testdata", "live", tc.name+".json"), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLiveDemoOCSPNonIssued(t *testing.T) {
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1 to call tsp.demo.sk.ee")
	}
	status := &revocation.Checker{AllowedHosts: map[string]bool{"aia.demo.sk.ee": true, "c.sk.ee": true, "demo.sk.ee": true}, CRLFallback: true, Revoked: smartid.ErrRevoked}
	c := liveClient(t, status)
	s, err := c.Start(context.Background(), StartRequest{Phone: "+37269930366", Code: "51307149560", Lang3: "ENG"})
	if err != nil {
		t.Fatal(err)
	}
	var st *Status
	for i := 0; i < 10 && (st == nil || st.State != "COMPLETE"); i++ {
		if st, err = c.Poll(context.Background(), s.ID, 20*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Verify(context.Background(), s, st); err == nil || authn.ReasonOf(err) != authn.ReasonVerificationFailed {
		t.Fatalf("demo OCSP no longer reports the non-issued convention: %v", err)
	}
}
