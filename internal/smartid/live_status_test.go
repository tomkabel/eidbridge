package smartid

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/revocation"
)

// liveStatus: SK's demo OCSP answers "revoked, certificateHold, 1970-01-01"
// for the automated-testing (mock) account certificates, the RFC 6960
// non-issued convention (ADR 0001). Live login tests therefore skip status;
// TestLiveDemoOCSPAnswersForMockCertificate proves the OCSP path itself.
func liveStatus(t *testing.T) StatusChecker {
	t.Helper()
	return NoStatusCheck{Reason: "demo mock-account certificates are not known to the demo OCSP responder"}
}

func TestLiveDemoOCSPAnswersForMockCertificate(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	s, err := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "eidbridge live test"})
	if err != nil {
		t.Fatal(err)
	}
	link, _ := s.QRLink(time.Now())
	if err := MockSubmitDeviceLink(ctx, "https://sid.demo.sk.ee/mock", "PNOEE-40404040009-MOCK-Q", link, nil); err != nil {
		t.Fatal(err)
	}
	st := pollDone(t, c, s.ID)
	der, _ := base64.StdEncoding.DecodeString(st.Cert.Value)
	leaf, _ := x509.ParseCertificate(der)
	issuer := c.cfg.Trust.Issuer(leaf)
	chk := &revocation.Checker{AllowedHosts: map[string]bool{"aia.demo.sk.ee": true}}
	err = chk.Check(ctx, leaf, issuer)
	if !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("demo OCSP answer changed: %v (update ADR 0001)", err)
	}
	// And Verify fails closed with a real status checker.
	c.cfg.Status = &revocation.Checker{AllowedHosts: map[string]bool{"aia.demo.sk.ee": true}, Revoked: ErrRevoked}
	if _, err := c.Verify(s, st, nil); err == nil {
		t.Fatal("not-good status verified")
	}
}
