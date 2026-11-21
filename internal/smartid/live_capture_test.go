package smartid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLiveCaptureFixtures records demo exchanges for offline replay when
// EIDBRIDGE_LIVE=1 and EIDBRIDGE_CAPTURE=1. It uses only SK's published demo
// test accounts through the automated testing interface.
func TestLiveCaptureFixtures(t *testing.T) {
	if os.Getenv("EIDBRIDGE_CAPTURE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1 EIDBRIDGE_CAPTURE=1 to refresh fixtures")
	}
	_ = liveClient(t)
	type scen struct{ name, flow, doc, semantics string }
	for _, sc := range []scen{
		{"qr-ok", FlowQR, "PNOEE-40404040009-MOCK-Q", ""},
		{"qr-refused", FlowQR, "PNOEE-30403039917-MOCK-Q", ""},
		{"web2app-ok", FlowWeb2App, "PNOEE-40404040009-MOCK-Q", ""},
		{"notification-ok", FlowNotification, "", "PNOEE-40504040001"},
		{"notification-refused", FlowNotification, "", "PNOEE-30403039917"},
		{"notification-wrong-vc", FlowNotification, "", "PNOEE-30403039972"},
	} {
		t.Run(sc.name, func(t *testing.T) {
			rec := &Recorder{}
			c := liveClient(t)
			c.cfg.Recorder = rec
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			var s *Session
			var err error
			var cbURL string
			switch sc.flow {
			case FlowNotification:
				s, err = c.StartNotification(ctx, NotificationRequest{SemanticsID: sc.semantics, DisplayText60: "eidbridge live test"})
			case FlowQR:
				s, err = c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "eidbridge live test"})
			case FlowWeb2App:
				s, err = c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowWeb2App, DisplayText60: "eidbridge live test",
					InitialCallbackURL: "https://localhost/flow/callback?value=" + randToken(t)})
			}
			if err != nil {
				for _, x := range rec.Exchanges {
					t.Logf("%s %d %s", x.Name, x.Status, x.Response)
				}
				t.Fatal(err)
			}
			switch sc.flow {
			case FlowQR:
				link, _ := s.QRLink(time.Now())
				if err := MockSubmit(ctx, "https://sid.demo.sk.ee/mock", MockDeviceLink{DocumentNumber: sc.doc, DeviceLink: link}, rec); err != nil {
					t.Fatal(err)
				}
			case FlowWeb2App:
				link, _ := s.Web2AppLink()
				if err := MockSubmit(ctx, "https://sid.demo.sk.ee/mock", MockDeviceLink{DocumentNumber: sc.doc, DeviceLink: link,
					BrowserCookie: "__Host-eidb-test=eidbridgecapture", DisableCallbackGetRequest: true}, rec); err != nil {
					for _, x := range rec.Exchanges {
						t.Logf("%s %d %s", x.Name, x.Status, x.Response)
					}
					t.Fatal(err)
				}
			}
			st := pollDone(t, c, s.ID)
			if sc.flow == FlowWeb2App && Outcome(st) == nil {
				cbURL, err = MockCallbackURL(ctx, "https://sid.demo.sk.ee/mock", s.SessionToken(), rec)
				if err != nil {
					t.Fatal(err)
				}
			}
			var cb *Callback
			if cbURL != "" {
				u, _ := url.Parse(cbURL)
				cb = &Callback{SessionSecretDigest: u.Query().Get("sessionSecretDigest"), UserChallengeVerifier: u.Query().Get("userChallengeVerifier")}
			}
			_, verr := c.Verify(s, st, cb)
			dir := filepath.Join("testdata", "live", sc.name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			meta := fixtureMeta{Captured: time.Now().UTC().Format(time.RFC3339), Flow: s.Flow, RPChallenge: s.RPChallengeB64(),
				Interactions: s.Interactions, InitialCallbackURL: s.InitialCallbackURL, ExpectedIdentity: s.ExpectedIdentity,
				SessionSecret: base64.StdEncoding.EncodeToString(s.secret), SessionToken: s.token, DeviceLinkBase: s.linkBase,
				CallbackURL: cbURL, VerifyReason: reasonOrOK(verr), VC: s.VC,
				Source: "sid.demo.sk.ee public demo RP with SK automated testing interface; published demo test account"}
			for i, x := range rec.Exchanges {
				b, _ := json.MarshalIndent(x, "", "  ")
				os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d-%s.json", i, x.Name)), b, 0o644)
			}
			b, _ := json.MarshalIndent(meta, "", "  ")
			os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644)
			t.Logf("%s: verify=%s", sc.name, meta.VerifyReason)
		})
	}
}

func reasonOrOK(err error) string {
	if err == nil {
		return "OK"
	}
	return ReasonOf(err) + ": " + err.Error()
}

func randToken(t *testing.T) string {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
