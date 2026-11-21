package v2

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func TestPR31V2RejectsUnsignedLevelUpgrade(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	session, err := e.c.Start(ctx, "PNOEE-40404040009", "Log in")
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.c.Poll(ctx, session.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Verify(ctx, session, st); err != nil {
		t.Fatalf("fixture must first authenticate: %v", err)
	}
	e.c.cfg.PolicyOIDs = nil // isolate the level policy from the configurable scheme allowlist
	leaf := e.srv.PKI.NewLeaf(smartidtest.LeafOptions{})
	p1, _ := x509.ParseOID("1.3.6.1.4.1.10015.17.1")
	p2, _ := x509.ParseOID("0.4.0.2042.1.1")
	leaf.Cert.PolicyIdentifiers = nil
	leaf.Cert.Policies = []x509.OID{p1, p2}
	der, err := x509.CreateCertificate(rand.Reader, leaf.Cert, e.srv.PKI.Inter, leaf.Key.Public(), e.srv.PKI.IssuerKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, leaf.Key.(*rsa.PrivateKey), crypto.SHA512, session.Hash)
	if err != nil {
		t.Fatal(err)
	}
	st.Cert.Value = base64.StdEncoding.EncodeToString(der)
	st.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	if id, err := e.c.Verify(ctx, session, st); err == nil || id != nil {
		t.Fatal("qualified minimum accepted an advanced certificate labeled qualified")
	}
}
