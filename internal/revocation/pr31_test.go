package revocation

import (
	"context"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"golang.org/x/crypto/ocsp"
)

func TestPR31UnknownIsTerminal(t *testing.T) {
	p := smartidtest.NewPKI("pr31")
	now := time.Now()
	r := &responder{pki: p, status: ocsp.Unknown, this: now.Add(-time.Minute), next: now.Add(time.Hour)}
	r.crl = crlFor(t, p, nil, r.this, r.next)
	c, leaf, issuer := setup(t, r, true)
	if err := c.Check(context.Background(), leaf, issuer); err == nil {
		t.Error("accepted an issuer-signed OCSP unknown status")
	}
	if hits := r.hits.Load(); hits != 1 {
		t.Errorf("terminal status made %d requests, want one OCSP request", hits)
	}
}
