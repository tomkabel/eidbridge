package v2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

type capture struct {
	Expected, Hash, Captured string
	Status                   json.RawMessage
}

func liveClient(t *testing.T) *Client {
	ts, err := smartid.LoadCADir(filepath.Join("..", "..", "..", "trust", "demo", "smartid-auth-ca"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(Config{BaseURL: "https://sid.demo.sk.ee/smart-id-rp/v2", RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO",
		HTTP: &http.Client{Timeout: 90 * time.Second}, Trust: ts, MinCertLevel: "QUALIFIED", PolicyOIDs: smartid.DemoPolicyOIDs,
		Status: smartid.NoStatusCheck{Reason: "demo OCSP non-issued convention (ADR 0001)"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLiveDemoV2 runs against sid.demo.sk.ee RP API v2 (EIDBRIDGE_LIVE=1);
// EIDBRIDGE_CAPTURE=1 writes testdata/live/*.json.
func TestLiveDemoV2(t *testing.T) {
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1")
	}
	for name, tc := range map[string]struct{ id, reason string }{"ok": {"PNOEE-40404040009", ""}, "refused": {"PNOEE-30403039917", authn.ReasonRefused}} {
		c := liveClient(t)
		s, err := c.Start(context.Background(), tc.id, "eidbridge test")
		if err != nil {
			t.Fatal(err)
		}
		hash := base64.StdEncoding.EncodeToString(s.Hash)
		var raw []byte
		var st *Status
		for i := 0; i < 10 && (st == nil || st.State != "COMPLETE"); i++ {
			raw, err = c.do(context.Background(), http.MethodGet, "/session/"+s.ID+"?timeoutMs=20000", nil)
			if err != nil {
				t.Fatal(err)
			}
			st = &Status{}
			json.Unmarshal(raw, st)
		}
		id, verr := c.Verify(context.Background(), s, st)
		t.Logf("%s: endResult=%s verify=%v", name, st.Result.EndResult, verr)
		if tc.reason == "" && (verr != nil || id.Code != "40404040009") || tc.reason != "" && authn.ReasonOf(verr) != tc.reason {
			t.Fatalf("%s: %v", name, verr)
		}
		if os.Getenv("EIDBRIDGE_CAPTURE") == "1" {
			b, _ := json.MarshalIndent(capture{Expected: tc.id, Hash: hash, Status: raw, Captured: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
			os.MkdirAll("testdata/live", 0o755)
			os.WriteFile(filepath.Join("testdata", "live", name+".json"), b, 0o644)
		}
	}
}

func loadCapture(t *testing.T, name string) (*Client, *Session, *Status) {
	b, err := os.ReadFile(filepath.Join("testdata", "live", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c capture
	json.Unmarshal(b, &c)
	h, _ := base64.StdEncoding.DecodeString(c.Hash)
	var st Status
	json.Unmarshal(c.Status, &st)
	at, _ := time.Parse(time.RFC3339, c.Captured)
	cl := liveClient(t)
	cl.cfg.Now = func() time.Time { return at }
	return cl, &Session{ID: "x", Hash: h, VC: VerificationCode(h), Expected: c.Expected}, &st
}

// Known-answer tests on the live v2 captures (2026-11-20).
func TestReplayLiveV2(t *testing.T) {
	c, s, st := loadCapture(t, "ok")
	if id, err := c.Verify(context.Background(), s, st); err != nil || id.Code != "40404040009" {
		t.Fatalf("ok: %+v %v", id, err)
	}
	c, s, st = loadCapture(t, "ok")
	s.Hash[0] ^= 1
	if _, err := c.Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonVerificationFailed {
		t.Fatalf("other hash: %v", err)
	}
	c, s, st = loadCapture(t, "ok")
	s.Expected = "PNOEE-40504040001"
	if _, err := c.Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonIdentityMismatch {
		t.Fatalf("identity mismatch: %v", err)
	}
	c, s, st = loadCapture(t, "refused")
	if _, err := c.Verify(context.Background(), s, st); authn.ReasonOf(err) != authn.ReasonRefused {
		t.Fatalf("refused: %v", err)
	}
}
