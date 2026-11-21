package smartid

import (
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func TestPR31V3CertificateLevelBoundToPolicies(t *testing.T) {
	for _, tc := range []struct {
		name              string
		policies          []string
		reported, minimum string
		ok                bool
	}{
		{"qualified", []string{"1.3.6.1.4.1.10015.17.2", "0.4.0.2042.1.2"}, LevelQualified, LevelQualified, true},
		{"advanced", []string{"1.3.6.1.4.1.10015.17.1", "0.4.0.2042.1.1"}, LevelAdvanced, LevelAdvanced, true},
		{"unsigned upgrade", []string{"1.3.6.1.4.1.10015.17.1", "0.4.0.2042.1.1"}, LevelQualified, LevelQualified, false},
		{"unknown policies", nil, LevelQualified, LevelAdvanced, false},
		{"conflicting", []string{"1.3.6.1.4.1.10015.17.1", "0.4.0.2042.1.1", "1.3.6.1.4.1.10015.17.2", "0.4.0.2042.1.2"}, LevelQualified, LevelQualified, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sy := newSynth(t, FlowQR, smartidtest.LeafOptions{})
			sy.c.cfg.PolicyOIDs = nil // isolate the level check from the configurable scheme allowlist
			sy.c.cfg.MinCertLevel = tc.minimum
			cert := *sy.leaf.Cert
			cert.PolicyIdentifiers = nil
			cert.Policies = nil
			for _, raw := range tc.policies {
				oid, err := x509.ParseOID(raw)
				if err != nil {
					t.Fatal(err)
				}
				cert.Policies = append(cert.Policies, oid)
			}
			der, err := x509.CreateCertificate(rand.Reader, &cert, testPKI.Inter, sy.leaf.Key.Public(), testPKI.IssuerKey())
			if err != nil {
				t.Fatal(err)
			}
			sy.leaf.Cert, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			sy.sign()
			sy.st["cert"].(map[string]any)["certificateLevel"] = tc.reported
			id, err := sy.verify()
			if tc.ok {
				if err != nil || id == nil || id.CertLevel != tc.reported {
					t.Fatalf("valid policy and matching level rejected: %v", err)
				}
			} else if err == nil || id != nil {
				t.Fatal("accepted level unsupported by signed certificate policies")
			}
		})
	}
}
