package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func envOf(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func root(t *testing.T) string {
	// repository root (for trust/demo)
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..")
}

// prodEnv returns a complete, valid production environment.
func prodEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	p := smartidtest.NewPKI("prod")
	ca := filepath.Join(dir, "ca")
	os.MkdirAll(ca, 0o755)
	os.WriteFile(filepath.Join(ca, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw}), 0o644)
	os.WriteFile(filepath.Join(dir, "clients.json"), []byte(`[{"client_id":"kc","client_secret":"`+strings.Repeat("x", 40)+`","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://kc.example/cb"],"sub_mode":"pairwise"}]`), 0o600)
	k := make([]byte, 32)
	rand.Read(k)
	os.WriteFile(filepath.Join(dir, "ksub.json"), []byte(`{"current":1,"keys":{"1":"`+base64.StdEncoding.EncodeToString(k)+`"}}`), 0o600)
	m := map[string]string{"EIDBRIDGE_MODE": "production", "EIDBRIDGE_ISSUER": "https://eid.example.com", "EIDBRIDGE_CLIENTS_FILE": filepath.Join(dir, "clients.json"),
		"EIDBRIDGE_KEY_DIR": filepath.Join(dir, "keys"), "EIDBRIDGE_SUB_KEY_FILE": filepath.Join(dir, "ksub.json"),
		"EIDBRIDGE_SMARTID_ENV": "production", "EIDBRIDGE_SMARTID_BASE_URL": "https://rp-api.smart-id.com", "EIDBRIDGE_RP_UUID": "7c8d2c0e-1111-4222-8333-444444444444",
		"EIDBRIDGE_RP_NAME": "Example Ltd", "EIDBRIDGE_SMARTID_TLS_PINS": "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"EIDBRIDGE_SMARTID_AUTH_CA_DIR": ca, "EIDBRIDGE_SMARTID_POLICY_OIDS": "1.3.6.1.4.1.10015.17.2", "EIDBRIDGE_SMARTID_CERT_STATUS": "ocsp",
		"EIDBRIDGE_SMARTID_STATUS_HOSTS": "aia.sk.ee"}
	for _, o := range Options {
		if o.ProdReq && m[o.Env] == "" {
			m[o.Env] = o.Demo
		}
	}
	return m
}

func TestDemoDefaultsLoadWithNoConfiguration(t *testing.T) {
	c, err := Load(envOf(nil), true, root(t))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Demo || c.Issuer != "http://localhost:8080/demo" || len(c.Clients) != 1 || c.SmartID.Trust == nil {
		t.Fatalf("%+v", c)
	}
}

func TestProductionValidLoads(t *testing.T) {
	c, err := Load(envOf(prodEnv(t)), false, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Demo || c.Issuer != "https://eid.example.com" {
		t.Fatalf("%+v", c)
	}
}

func TestModeInvariantMatrix(t *testing.T) {
	if _, err := Load(envOf(nil), false, root(t)); err == nil || !strings.Contains(err.Error(), "no default") {
		t.Fatalf("mode unset: %v", err)
	}
	if _, err := Load(envOf(map[string]string{"EIDBRIDGE_MODE": "production"}), true, root(t)); err == nil {
		t.Fatal("--demo with EIDBRIDGE_MODE=production accepted")
	}
	demo := func(k, v string) error {
		_, err := Load(envOf(map[string]string{k: v}), true, root(t))
		return err
	}
	for k, v := range map[string]string{
		"EIDBRIDGE_SMARTID_BASE_URL":    "https://rp-api.smart-id.com",
		"EIDBRIDGE_RP_UUID":             "7c8d2c0e-1111-4222-8333-444444444444",
		"EIDBRIDGE_RP_NAME":             "Example Ltd",
		"EIDBRIDGE_SMARTID_ENV":         "production",
		"EIDBRIDGE_SMARTID_AUTH_CA_DIR": t.TempDir(),
	} {
		if demo(k, v) == nil {
			t.Errorf("demo accepted production value %s=%s", k, v)
		}
	}
	prodBad := map[string]string{
		"EIDBRIDGE_SMARTID_BASE_URL":    "https://sid.demo.sk.ee/smart-id-rp",
		"EIDBRIDGE_RP_UUID":             DemoRPUUID,
		"EIDBRIDGE_RP_NAME":             DemoRPName,
		"EIDBRIDGE_SMARTID_ENV":         "demo",
		"EIDBRIDGE_SMARTID_AUTH_CA_DIR": filepath.Join(root(t), "trust", "demo", "smartid-auth-ca"),
		"EIDBRIDGE_SMARTID_CERT_STATUS": "none",
		"EIDBRIDGE_SMARTID_POLICY_OIDS": "",
		"EIDBRIDGE_SUB_KEY_FILE":        "",
		"EIDBRIDGE_CLIENTS_FILE":        "",
		"EIDBRIDGE_METHOD_ACR":          "not json",
	}
	for k, v := range prodBad {
		m := prodEnv(t)
		m[k] = v
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("production accepted %s=%q", k, v)
		}
	}
	m := prodEnv(t)
	m["EIDBRIDGE_SMARTID_ENV"] = "mock"
	if _, err := Load(envOf(m), false, ""); err == nil {
		t.Error("production accepted mock env")
	}
}

func TestProductionRejectsHTTPIssuerAndEnvMismatch(t *testing.T) {
	for _, iss := range []string{"http://eid.example.com", "http://localhost:8080", "https://eid.example.com/demo", "ftp://x"} {
		m := prodEnv(t)
		m["EIDBRIDGE_ISSUER"] = iss
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("production issuer %s accepted", iss)
		}
	}
	if _, err := Load(envOf(map[string]string{"EIDBRIDGE_ISSUER": "http://bridge.example"}), true, root(t)); err == nil {
		t.Error("demo http issuer off localhost accepted")
	}
}

func TestProductionRequiresExplicitBoundedValues(t *testing.T) {
	for _, o := range Options {
		if !o.ProdReq {
			continue
		}
		m := prodEnv(t)
		if strings.Contains(o.Env, "MOBILEID") {
			m = prodMIDEnv(t)
		}
		if strings.Contains(o.Env, "WEBEID") {
			m = prodWebEIDEnv(t)
		}
		delete(m, o.Env)
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("production started without %s", o.Env)
		}
	}
	for k, v := range map[string]string{"EIDBRIDGE_ACCESS_TOKEN_LIFETIME": "301s", "EIDBRIDGE_FLOW_TTL": "301s", "EIDBRIDGE_CLOCK_SKEW": "121s",
		"EIDBRIDGE_GRACE_PERIOD": "5s", "EIDBRIDGE_RETRY_BUDGET": "0", "EIDBRIDGE_POLL_SLOTS": "20000", "EIDBRIDGE_CODE_STORE_CAP": "10"} {
		m := prodEnv(t)
		m[k] = v
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("out-of-bounds %s=%s accepted", k, v)
		}
	}
}

// FR-007: startup fails with a clear error if production lacks RP UUID/name.
func TestProductionFailsWithoutRPIdentity(t *testing.T) {
	for _, k := range []string{"EIDBRIDGE_RP_UUID", "EIDBRIDGE_RP_NAME"} {
		m := prodEnv(t)
		delete(m, k)
		_, err := Load(envOf(m), false, "")
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s: %v", k, err)
		}
	}
}

func TestProductionFailsWithoutSubKey(t *testing.T) {
	m := prodEnv(t)
	delete(m, "EIDBRIDGE_SUB_KEY_FILE")
	if _, err := Load(envOf(m), false, ""); err == nil {
		t.Fatal("no K_sub accepted")
	}
	m = prodEnv(t)
	os.WriteFile(m["EIDBRIDGE_SUB_KEY_FILE"], []byte(`{"keys":{"1":"AAAA"}}`), 0o600)
	if _, err := Load(envOf(m), false, ""); err == nil {
		t.Fatal("K_sub without version accepted")
	}
}

func TestPinPolicyThroughConfig(t *testing.T) {
	m := prodEnv(t)
	m["EIDBRIDGE_SMARTID_TLS_PINS"] = "disabled"
	if _, err := Load(envOf(m), false, ""); err == nil {
		t.Fatal("production disabled pins without acknowledgement")
	}
	m["EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK"] = "I_UNDERSTAND"
	c, err := Load(envOf(m), false, "")
	if err != nil || len(c.Deviations) == 0 || len(c.Warnings) == 0 {
		t.Fatalf("acknowledged: %v %+v", err, c)
	}
	c, err = Load(envOf(nil), true, root(t))
	if err != nil || len(c.Warnings) == 0 {
		t.Fatal("demo disabled pins must warn")
	}
}

func TestInteractionDisplayTextLimits(t *testing.T) {
	if _, err := Load(envOf(map[string]string{"EIDBRIDGE_SMARTID_DISPLAY_TEXT": strings.Repeat("a", 61)}), true, root(t)); err == nil {
		t.Fatal("61-character display text accepted")
	}
	m := prodEnv(t)
	os.WriteFile(m["EIDBRIDGE_CLIENTS_FILE"], []byte(`[{"client_id":"kc","client_secret":"`+strings.Repeat("x", 40)+`","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://kc.example/cb"],"sub_mode":"pairwise","display_text":{"et":"`+strings.Repeat("ä", 61)+`"}}]`), 0o600)
	if _, err := Load(envOf(m), false, ""); err == nil {
		t.Fatal("client display text over the protocol limit accepted")
	}
}

func TestConfigurationDocMatchesCode(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root(t), "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != Markdown() {
		t.Fatal("docs/configuration.md is stale: run go run ./cmd/eidbridge config docs > docs/configuration.md")
	}
}

// Red-team finding F1 (2026-11-20): the production demo-host guard compared
// the raw host, so case changes and a trailing dot passed, and demo OCSP/CRL
// hosts were accepted as status hosts.
func TestProductionRefusesDemoHostVariants(t *testing.T) {
	for _, base := range []string{"https://SID.DEMO.SK.EE/smart-id-rp", "https://Sid.Demo.Sk.Ee/smart-id-rp",
		"https://sid.demo.sk.ee./smart-id-rp", "https://any.demo.sk.ee/x", "https://demo.sk.ee/x", "https://DEMO.SK.EE./x"} {
		m := prodEnv(t)
		m["EIDBRIDGE_SMARTID_BASE_URL"] = base
		if _, err := Load(envOf(m), false, ""); err == nil || !strings.Contains(err.Error(), "demo host") {
			t.Errorf("production accepted %s: %v", base, err)
		}
	}
	for _, sh := range []string{"aia.demo.sk.ee", "AIA.DEMO.SK.EE", "aia.demo.sk.ee.", "aia.sk.ee,aia.demo.sk.ee:80"} {
		m := prodEnv(t)
		m["EIDBRIDGE_SMARTID_STATUS_HOSTS"] = sh
		if _, err := Load(envOf(m), false, ""); err == nil || !strings.Contains(err.Error(), "demo host") {
			t.Errorf("production accepted status host %s: %v", sh, err)
		}
	}
	for _, h := range []string{"notdemo.sk.ee", "demo.sk.ee.example.com"} {
		if IsDemoHost(h) {
			t.Errorf("IsDemoHost(%q) = true", h)
		}
	}
}

func TestDemoModeNormalizesHost(t *testing.T) {
	if _, err := Load(envOf(map[string]string{"EIDBRIDGE_SMARTID_BASE_URL": "https://SID.DEMO.SK.EE/smart-id-rp"}), true, root(t)); err != nil {
		t.Fatalf("demo refused upper-case demo host: %v", err)
	}
}

// prodMIDEnv is a valid production environment with Mobile-ID enabled.
func prodMIDEnv(t *testing.T) map[string]string {
	m := prodEnv(t)
	m["EIDBRIDGE_METHODS"] = "smartid,mobileid"
	for k, v := range map[string]string{"EIDBRIDGE_MOBILEID_ENV": "production", "EIDBRIDGE_MOBILEID_BASE_URL": "https://mid.sk.ee/mid-api",
		"EIDBRIDGE_MOBILEID_RP_UUID": "7c8d2c0e-1111-4222-8333-444444444444", "EIDBRIDGE_MOBILEID_RP_NAME": "Example Ltd",
		"EIDBRIDGE_MOBILEID_TLS_PINS": m["EIDBRIDGE_SMARTID_TLS_PINS"], "EIDBRIDGE_MOBILEID_AUTH_CA_DIR": m["EIDBRIDGE_SMARTID_AUTH_CA_DIR"],
		"EIDBRIDGE_MOBILEID_POLICY_OIDS": "1.3.6.1.4.1.10015.18.1", "EIDBRIDGE_MOBILEID_CERT_STATUS": "ocsp", "EIDBRIDGE_MOBILEID_STATUS_HOSTS": "aia.sk.ee"} {
		m[k] = v
	}
	return m
}

// Story 4.2 with ADR-003: the demo/production invariants hold for Mobile-ID.
func TestMobileIDModeInvariants(t *testing.T) {
	if _, err := Load(envOf(prodMIDEnv(t)), false, ""); err != nil {
		t.Fatalf("valid production Mobile-ID refused: %v", err)
	}
	for name, mod := range map[string]map[string]string{
		"demo env":          {"EIDBRIDGE_MOBILEID_ENV": "demo"},
		"mock env":          {"EIDBRIDGE_MOBILEID_ENV": "mock"},
		"demo host":         {"EIDBRIDGE_MOBILEID_BASE_URL": "https://TSP.DEMO.SK.EE./mid-api"},
		"demo status host":  {"EIDBRIDGE_MOBILEID_STATUS_HOSTS": "aia.demo.sk.ee"},
		"demo RP UUID":      {"EIDBRIDGE_MOBILEID_RP_UUID": "00000000-0000-0000-0000-000000000000"},
		"demo RP name":      {"EIDBRIDGE_MOBILEID_RP_NAME": "DEMO"},
		"http":              {"EIDBRIDGE_MOBILEID_BASE_URL": "http://mid.sk.ee/mid-api"},
		"status none":       {"EIDBRIDGE_MOBILEID_CERT_STATUS": "none"},
		"demo CA":           {"EIDBRIDGE_MOBILEID_AUTH_CA_DIR": filepath.Join(root(t), "trust", "demo", "mobileid-auth-ca")},
		"pins disabled":     {"EIDBRIDGE_MOBILEID_TLS_PINS": "disabled"},
		"long display text": {"EIDBRIDGE_MOBILEID_DISPLAY_TEXT": strings.Repeat("x", 41)},
		"non GSM display":   {"EIDBRIDGE_MOBILEID_DISPLAY_TEXT": "Logi sisse – õ"},
	} {
		m := prodMIDEnv(t)
		for k, v := range mod {
			m[k] = v
		}
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("production accepted %s", name)
		}
	}
	c, err := Load(envOf(map[string]string{"EIDBRIDGE_METHODS": "smartid,mobileid"}), true, root(t))
	if err != nil || c.MobileID.Trust == nil || c.MobileID.BaseURL != "https://tsp.demo.sk.ee/mid-api" {
		t.Fatalf("demo Mobile-ID defaults: %v", err)
	}
	for name, mod := range map[string]map[string]string{
		"production host": {"EIDBRIDGE_MOBILEID_BASE_URL": "https://mid.sk.ee/mid-api"},
		"production env":  {"EIDBRIDGE_MOBILEID_ENV": "production"},
		"own RP in demo":  {"EIDBRIDGE_MOBILEID_RP_UUID": "7c8d2c0e-1111-4222-8333-444444444444"},
		"non-demo CA":     {"EIDBRIDGE_MOBILEID_AUTH_CA_DIR": prodEnv(t)["EIDBRIDGE_SMARTID_AUTH_CA_DIR"]},
	} {
		m := map[string]string{"EIDBRIDGE_METHODS": "smartid,mobileid"}
		for k, v := range mod {
			m[k] = v
		}
		if _, err := Load(envOf(m), true, root(t)); err == nil {
			t.Errorf("demo accepted %s", name)
		}
	}
}

func prodWebEIDEnv(t *testing.T) map[string]string {
	m := prodEnv(t)
	m["EIDBRIDGE_METHODS"] = "smartid,webeid"
	for k, v := range map[string]string{"EIDBRIDGE_WEBEID_ENV": "production", "EIDBRIDGE_WEBEID_CA_DIR": m["EIDBRIDGE_SMARTID_AUTH_CA_DIR"],
		"EIDBRIDGE_WEBEID_CERT_STATUS": "ocsp", "EIDBRIDGE_WEBEID_STATUS_HOSTS": "aia.sk.ee"} {
		m[k] = v
	}
	return m
}

// Story 5.1 with ADR-003: the ID-card method keeps demo and production
// apart and needs an https issuer.
func TestWebEIDModeInvariants(t *testing.T) {
	if _, err := Load(envOf(prodWebEIDEnv(t)), false, ""); err != nil {
		t.Fatalf("valid production Web eID refused: %v", err)
	}
	for name, mod := range map[string]map[string]string{
		"demo env":         {"EIDBRIDGE_WEBEID_ENV": "demo"},
		"mock env":         {"EIDBRIDGE_WEBEID_ENV": "mock"},
		"status none":      {"EIDBRIDGE_WEBEID_CERT_STATUS": "none"},
		"demo status host": {"EIDBRIDGE_WEBEID_STATUS_HOSTS": "aia.sk.ee,AIA.DEMO.SK.EE"},
		"demo CA":          {"EIDBRIDGE_WEBEID_CA_DIR": filepath.Join(root(t), "trust", "demo", "webeid-ca")},
		"bad policy":       {"EIDBRIDGE_WEBEID_DISALLOWED_POLICIES": "x.y"},
	} {
		m := prodWebEIDEnv(t)
		for k, v := range mod {
			m[k] = v
		}
		if _, err := Load(envOf(m), false, ""); err == nil {
			t.Errorf("production accepted %s", name)
		}
	}
	if _, err := Load(envOf(map[string]string{"EIDBRIDGE_METHODS": "smartid,webeid"}), true, root(t)); err == nil {
		t.Error("demo Web eID accepted an http issuer")
	}
	c, err := Load(envOf(map[string]string{"EIDBRIDGE_METHODS": "smartid,webeid", "EIDBRIDGE_ISSUER": "https://localhost:8443"}), true, root(t))
	if err != nil || c.WebEID.Trust == nil {
		t.Fatalf("demo Web eID: %v", err)
	}
	m := map[string]string{"EIDBRIDGE_METHODS": "smartid,webeid", "EIDBRIDGE_ISSUER": "https://localhost:8443", "EIDBRIDGE_WEBEID_CA_DIR": prodEnv(t)["EIDBRIDGE_SMARTID_AUTH_CA_DIR"]}
	if _, err := Load(envOf(m), true, root(t)); err == nil {
		t.Error("demo accepted a non-demo card CA")
	}
}
