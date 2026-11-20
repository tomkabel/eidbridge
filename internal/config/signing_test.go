package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// Red-team #2 F2: production must refuse demo CAs as signing CAs too.
func TestProductionRefusesDemoSigningCA(t *testing.T) {
	m := prodEnv(t)
	m["EIDBRIDGE_SIGNING_ENABLED"] = "true"
	if _, err := Load(envOf(m), false, ""); err != nil {
		t.Fatalf("signing with the production auth CAs: %v", err)
	}
	m["EIDBRIDGE_SIGNING_CA_DIR"] = filepath.Join(root(t), "trust", "demo", "smartid-auth-ca")
	_, err := Load(envOf(m), false, "")
	if err == nil || !strings.Contains(err.Error(), "mixed trust") {
		t.Fatalf("demo signing CA accepted in production: %v", err)
	}
	m["EIDBRIDGE_SIGNING_CA_DIR"] = m["EIDBRIDGE_SMARTID_AUTH_CA_DIR"]
	if _, err := Load(envOf(m), false, ""); err != nil {
		t.Fatalf("production signing CA dir refused: %v", err)
	}
}
