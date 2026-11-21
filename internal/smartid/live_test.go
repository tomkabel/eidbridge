package smartid

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Live tests run only with EIDBRIDGE_LIVE=1. They use the public demo
// relying party and SK's automated testing interface with published demo
// test accounts; no real identity is involved.
var liveRec = &Recorder{}

func liveClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("live demo test; set EIDBRIDGE_LIVE=1")
	}
	trust, err := LoadCADir(filepath.Join("..", "..", "trust", "demo", "smartid-auth-ca"))
	if err != nil {
		t.Fatalf("demo trust: %v", err)
	}
	c, err := NewClient(Config{BaseURL: DemoBaseURL, RPUUID: DemoRPUUID, RPName: DemoRPName,
		SchemeName: SchemeDemo, Trust: trust, MinCertLevel: LevelQualified, Status: liveStatus(t), Recorder: liveRec})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pollDone(t *testing.T, c *Client, id string) *Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for {
		st, err := c.Poll(ctx, id, 10*time.Second)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if st.State == "COMPLETE" {
			return st
		}
	}
}

func TestLiveDemoQRAuthentication(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	s, err := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "eidbridge live test"})
	if err != nil {
		for _, x := range liveRec.Exchanges {
			t.Logf("%s %d %s", x.Name, x.Status, x.Response)
		}
		t.Fatal(err)
	}
	link, _ := s.QRLink(time.Now())
	if err := MockSubmitDeviceLink(ctx, "https://sid.demo.sk.ee/mock", "PNOEE-40404040009-MOCK-Q", link, liveRec); err != nil {
		for _, x := range liveRec.Exchanges {
			t.Logf("%s %d %s", x.Name, x.Status, x.Response)
		}
		t.Fatal(err)
	}
	st := pollDone(t, c, s.ID)
	if d := os.Getenv("EIDBRIDGE_DUMP_DIR"); d != "" && st.Cert != nil {
		der, _ := base64.StdEncoding.DecodeString(st.Cert.Value)
		_ = os.WriteFile(filepath.Join(d, "leaf.der"), der, 0o644)
		if cert, err := x509.ParseCertificate(der); err == nil {
			t.Logf("issuer=%q aia=%v ocsp=%v policies=%v eku=%v unk=%v ku=%d", cert.Issuer.CommonName, cert.IssuingCertificateURL, cert.OCSPServer, cert.PolicyIdentifiers, cert.ExtKeyUsage, cert.UnknownExtKeyUsage, cert.KeyUsage)
		}
	}
	id, err := c.Verify(s, st, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Country != "EE" || id.FlowType != FlowQR {
		t.Fatalf("unexpected identity country/flow %s/%s", id.Country, id.FlowType)
	}
}
