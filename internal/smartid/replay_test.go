package smartid

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// replay rebuilds a captured live session for offline verification.
type replay struct {
	meta   fixtureMeta
	status []byte
	link   string
	client *Client
}

func loadReplay(t *testing.T, name string) *replay {
	t.Helper()
	dir := filepath.Join("testdata", "live", name)
	var r replay
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r.meta); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*-*.json"))
	for _, f := range files {
		var x Exchange
		b, _ := os.ReadFile(f)
		json.Unmarshal(b, &x)
		switch x.Name {
		case "session-status":
			r.status = x.Response
		case "mock-device-link":
			var req struct{ DeviceLink string }
			json.Unmarshal(x.Request, &req)
			r.link = req.DeviceLink
		}
	}
	trust, err := LoadCADir(filepath.Join("..", "..", "trust", "demo", "smartid-auth-ca"))
	if err != nil {
		t.Fatal(err)
	}
	captured, _ := time.Parse(time.RFC3339, r.meta.Captured)
	r.client, err = NewClient(Config{BaseURL: DemoBaseURL, RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
		Trust: trust, MinCertLevel: LevelQualified, Status: NoStatusCheck{}, PolicyOIDs: DemoPolicyOIDs,
		Now: func() time.Time { return captured }})
	if err != nil {
		t.Fatal(err)
	}
	return &r
}

func (r *replay) session(t *testing.T) *Session {
	ch, _ := base64.StdEncoding.DecodeString(r.meta.RPChallenge)
	sec, _ := base64.StdEncoding.DecodeString(r.meta.SessionSecret)
	return &Session{Flow: r.meta.Flow, InitialCallbackURL: r.meta.InitialCallbackURL, Interactions: r.meta.Interactions,
		Lang: "eng", ExpectedIdentity: r.meta.ExpectedIdentity, token: r.meta.SessionToken, secret: sec,
		linkBase: r.meta.DeviceLinkBase, rpChallenge: ch, scheme: SchemeDemo, rpName: DemoRPName}
}

func (r *replay) callback() *Callback {
	if r.meta.CallbackURL == "" {
		return nil
	}
	u, _ := url.Parse(r.meta.CallbackURL)
	return &Callback{SessionSecretDigest: u.Query().Get("sessionSecretDigest"), UserChallengeVerifier: u.Query().Get("userChallengeVerifier")}
}

func (r *replay) parsed(t *testing.T) *Status {
	st, err := ParseStatus(r.status)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestReplayLiveFixturesVerifyOffline(t *testing.T) {
	for _, name := range []string{"qr-ok", "web2app-ok", "notification-ok"} {
		t.Run(name, func(t *testing.T) {
			r := loadReplay(t, name)
			id, err := r.client.Verify(r.session(t), r.parsed(t), r.callback())
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if id.Country != "EE" || id.IDType != "PNO" || id.CertLevel != LevelQualified || id.FlowType != r.meta.Flow {
				t.Fatalf("identity fields: %+v", *id)
			}
			if id.GivenName == "" || id.Surname == "" {
				t.Fatal("demo certificate carries GN and SN")
			}
		})
	}
}

// The live demo accepted these links, so recomputing them is a known-answer
// test for the authCode and link layout.
func TestReplayAuthCodeKnownAnswer(t *testing.T) {
	for _, name := range []string{"qr-ok", "web2app-ok"} {
		r := loadReplay(t, name)
		s := r.session(t)
		var got string
		if s.Flow == FlowQR {
			el := strings.Split(strings.Split(r.link, "elapsedSeconds=")[1], "&")[0]
			got, _ = s.link("QR", el)
		} else {
			got, _ = s.Web2AppLink()
		}
		if got != r.link {
			t.Fatalf("%s: link differs\n got %s\nwant %s", name, got, r.link)
		}
	}
}

func TestReplayNonOKFixturesMapToReasons(t *testing.T) {
	for name, want := range map[string]string{"qr-refused": ReasonRefused, "notification-refused": ReasonRefused, "notification-wrong-vc": ReasonWrongCode} {
		r := loadReplay(t, name)
		_, err := r.client.Verify(r.session(t), r.parsed(t), nil)
		if ReasonOf(err) != want {
			t.Fatalf("%s: reason %q, want %q", name, ReasonOf(err), want)
		}
	}
}

func TestReplayTamperedLiveResponsesFail(t *testing.T) {
	type mut func(m map[string]any)
	sig := func(m map[string]any) map[string]any { return m["signature"].(map[string]any) }
	cases := map[string]mut{
		"signature value":   func(m map[string]any) { v := sig(m)["value"].(string); sig(m)["value"] = "A" + v[1:] },
		"serverRandom":      func(m map[string]any) { sig(m)["serverRandom"] = "P3UygfCL/KKtubiGwP0pDzkX" },
		"userChallenge":     func(m map[string]any) { sig(m)["userChallenge"] = strings.Repeat("A", 43) },
		"flowType":          func(m map[string]any) { sig(m)["flowType"] = "Web2App" },
		"interactionType":   func(m map[string]any) { m["interactionTypeUsed"] = "confirmationMessage" },
		"pkcs1 algorithm":   func(m map[string]any) { sig(m)["signatureAlgorithm"] = "sha512WithRSAEncryption" },
		"cert level":        func(m map[string]any) { m["cert"].(map[string]any)["certificateLevel"] = "ADVANCED" },
		"documentNumber":    func(m map[string]any) { m["result"].(map[string]any)["documentNumber"] = "PNOEE-30403039917-MOCK-Q" },
		"protocol":          func(m map[string]any) { m["signatureProtocol"] = "RAW_DIGEST_SIGNATURE" },
		"state running":     func(m map[string]any) { m["state"] = "RUNNING" },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			r := loadReplay(t, "qr-ok")
			var m map[string]any
			json.Unmarshal(r.status, &m)
			f(m)
			b, _ := json.Marshal(m)
			st, err := ParseStatus(b)
			if err == nil {
				_, err = r.client.Verify(r.session(t), st, nil)
			}
			if err == nil {
				t.Fatal("tampered response verified")
			}
		})
	}
	t.Run("wrong rpChallenge", func(t *testing.T) {
		r := loadReplay(t, "qr-ok")
		s := r.session(t)
		s.rpChallenge[0] ^= 1
		if _, err := r.client.Verify(s, r.parsed(t), nil); err == nil {
			t.Fatal("wrong challenge verified")
		}
	})
	t.Run("wrong scheme name", func(t *testing.T) {
		r := loadReplay(t, "qr-ok")
		s := r.session(t)
		s.scheme = SchemeLive
		if _, err := r.client.Verify(s, r.parsed(t), nil); err == nil {
			t.Fatal("wrong scheme verified")
		}
	})
	t.Run("expired at verification time", func(t *testing.T) {
		r := loadReplay(t, "qr-ok")
		r.client.cfg.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
		if _, err := r.client.Verify(r.session(t), r.parsed(t), nil); err == nil {
			t.Fatal("expired certificate verified")
		}
	})
	t.Run("web2app wrong digest and verifier", func(t *testing.T) {
		r := loadReplay(t, "web2app-ok")
		cb := r.callback()
		bad := *cb
		bad.SessionSecretDigest = strings.Repeat("A", 43)
		if _, err := r.client.Verify(r.session(t), r.parsed(t), &bad); err == nil {
			t.Fatal("wrong digest verified")
		}
		bad = *cb
		bad.UserChallengeVerifier += "x"
		if _, err := r.client.Verify(r.session(t), r.parsed(t), &bad); err == nil {
			t.Fatal("wrong verifier verified")
		}
		if _, err := r.client.Verify(r.session(t), r.parsed(t), nil); err == nil {
			t.Fatal("missing callback verified")
		}
	})
	t.Run("notification identity mismatch", func(t *testing.T) {
		r := loadReplay(t, "notification-ok")
		s := r.session(t)
		s.ExpectedIdentity = "PNOEE-39901012239"
		_, err := r.client.Verify(s, r.parsed(t), nil)
		if ReasonOf(err) != ReasonIdentityMismatch {
			t.Fatalf("reason %q", ReasonOf(err))
		}
	})
}
