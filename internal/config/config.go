// Package config loads eidbridge configuration from environment variables
// and an optional JSON file, and enforces the startup invariants of
// architecture ADR-003 and ADR-008. Mode has no default. Demo mode supplies
// documented defaults so a clean clone reaches a QR page; production
// requires every bounded value to be set explicitly.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/mobileid"
	"github.com/tomkabel/eidbridge/internal/oidc"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/tlspin"
)

// Option documents one setting. Options is the single source for parsing
// documentation (docs/configuration.md is generated from it and checked in
// CI).
type Option struct {
	Env     string
	Demo    string // demo default ("" = none)
	ProdReq bool   // must be set explicitly in production
	Bounds  string
	Desc    string
}

// Options lists every environment variable.
var Options = []Option{
	{"EIDBRIDGE_MODE", "", false, "demo or production", "Required, no default. `--demo` sets demo."},
	{"EIDBRIDGE_LISTEN", ":8080", false, "", "Listen address."},
	{"EIDBRIDGE_ISSUER", "http://localhost:8080", true, "production: https; demo: https or http://localhost", "Public base URL. Demo appends `/demo` to form the issuer."},
	{"EIDBRIDGE_METHODS", "smartid", false, "smartid, mobileid, webeid, eudi, smartid-v2", "Enabled methods, comma-separated, in chooser order."},
	{"EIDBRIDGE_CLIENTS_FILE", "", true, "", "JSON file with static OIDC clients. Demo without it registers the sample client `demo-rp`."},
	{"EIDBRIDGE_DEMO_CLIENT_SECRET", "demo-client-secret-not-for-production-use", false, "demo only", "Secret of the built-in demo client."},
	{"EIDBRIDGE_DEMO_REDIRECT_URIS", "http://localhost:8081/callback", false, "demo only", "Redirect URIs of the built-in demo client."},
	{"EIDBRIDGE_KEY_DIR", "./data/demo-keys", true, "mode 0700, key files 0600", "Signing-key directory (keys.json manifest). Demo generates a `demo-` key when empty."},
	{"EIDBRIDGE_SUB_KEY_FILE", "", true, "32-byte keys", "JSON `{\"current\":N,\"keys\":{\"N\":\"<base64>\"}}` with versioned K_sub. Demo uses a random in-memory key."},
	{"EIDBRIDGE_SUB_MIGRATION", "", false, "days 1–90", "JSON migration declaration `{\"from\":1,\"to\":2,\"started\":\"2026-11-20T00:00:00Z\",\"days\":30,\"clients\":{\"id\":\"c:id\"}}`."},
	{"EIDBRIDGE_DEMO_KEY_DENYLIST", "", false, "hex SHA-256 SPKI fingerprints", "Comma-separated key fingerprints production must refuse."},
	{"EIDBRIDGE_METHOD_ACR", "", false, "JSON map", "Operator-backed acr per method, e.g. `{\"smartid\":\"urn:example:loa:high\"}` (ADR 0003)."},
	{"EIDBRIDGE_FLOW_TTL", "120s", true, "≥ long poll + 30 s, ≤ 300 s", "Flow timeout; the absolute flow deadline adds 30 s."},
	{"EIDBRIDGE_ACCESS_TOKEN_LIFETIME", "300s", true, "1–300 s", "Sealed access-token lifetime; ID tokens use the same."},
	{"EIDBRIDGE_CLOCK_SKEW", "30s", true, "0–120 s", "Allowed clock skew for client assertions."},
	{"EIDBRIDGE_RETRY_BUDGET", "3", true, "1–10", "Upstream poll retries for transient errors."},
	{"EIDBRIDGE_RETRY_BASE", "500ms", true, "50 ms–10 s", "First retry backoff (doubles)."},
	{"EIDBRIDGE_GRACE_PERIOD", "60s", true, "10–300 s", "SIGTERM drain limit."},
	{"EIDBRIDGE_MAX_FLOWS", "10000", true, "1–1,000,000", "Pending-flow ceiling (NFR-003)."},
	{"EIDBRIDGE_CODE_STORE_CAP", "20000", true, "≥ MAX_FLOWS", "Code store slots: reservations, codes and tombstones."},
	{"EIDBRIDGE_POLL_SLOTS", "1000", true, "1–MAX_FLOWS", "Upstream concurrency (one long poll per pending flow)."},
	{"EIDBRIDGE_UPSTREAM_RATE", "50", true, "requests/s", "Global upstream request rate."},
	{"EIDBRIDGE_PER_IP_BURST", "20", true, "", "Per-IP (IPv4 or IPv6 /64) burst for new flows."},
	{"EIDBRIDGE_PER_IP_RATE", "1", true, "per second", "Per-IP refill rate."},
	{"EIDBRIDGE_PER_CLIENT_BURST", "1000", true, "", "Per-client burst."},
	{"EIDBRIDGE_PER_CLIENT_RATE", "50", true, "per second", "Per-client refill rate."},
	{"EIDBRIDGE_PER_TARGET_BURST", "3", true, "", "Per notification target (person) burst."},
	{"EIDBRIDGE_PER_TARGET_RATE", "0.01", true, "per second", "Per-target refill rate."},
	{"EIDBRIDGE_BUCKET_CAP", "100000", true, "", "Maximum tracked rate-limit keys per bucket map."},
	{"EIDBRIDGE_TRUSTED_PROXIES", "", false, "CIDRs", "Proxy hops whose X-Forwarded-For is trusted. Empty: forwarding headers are ignored."},
	{"EIDBRIDGE_DEFAULT_LOCALE", "en", false, "en, et, lv, lt, ru", "Fallback locale."},
	{"EIDBRIDGE_REMEMBER_METHOD", "false", false, "true or false", "Offer an opt-in method preference cookie (chooser only)."},
	{"EIDBRIDGE_LOG_LEVEL", "info", false, "info or debug", "Redaction applies at every level."},
	{"EIDBRIDGE_TLS_CERT_FILE", "", false, "PEM", "Serve HTTPS directly (otherwise terminate TLS at a proxy)."},
	{"EIDBRIDGE_TLS_KEY_FILE", "", false, "PEM, mode 0600", "Key for EIDBRIDGE_TLS_CERT_FILE."},
	{"EIDBRIDGE_MOCK_DOCUMENT", "PNOEE-40404040009-MOCK-Q", false, "mock env only", "Test document the fixture upstream uses to auto-complete device-link sessions; `manual` waits for the mock interface."},
	{"EIDBRIDGE_MOCK_LISTEN", "127.0.0.1:0", false, "loopback only, mock env", "Address of the built-in fixture upstream (RP API and automated testing interface)."},
	{"EIDBRIDGE_SMARTID_ENV", "demo", true, "demo, production, mock", "Must agree with mode; mock (fixture upstream) is demo-only."},
	{"EIDBRIDGE_SMARTID_BASE_URL", "https://sid.demo.sk.ee/smart-id-rp", true, "", "RP API base URL (without /v3)."},
	{"EIDBRIDGE_RP_UUID", "00000000-0000-4000-8000-000000000000", true, "", "Relying-party UUID from your agreement."},
	{"EIDBRIDGE_RP_NAME", "DEMO", true, "", "Registered relying-party name, byte-exact."},
	{"EIDBRIDGE_SMARTID_TLS_PINS", "disabled", true, "sha256/<b64>[,…] or disabled", "SPKI pins (current and next)."},
	{"EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK", "", false, "I_UNDERSTAND", "Production acknowledgement for disabled pins."},
	{"EIDBRIDGE_SMARTID_AUTH_CA_DIR", "trust/demo/smartid-auth-ca", true, "", "Authentication CA certificates (separate from TLS trust)."},
	{"EIDBRIDGE_SMARTID_POLICY_OIDS", "1.3.6.1.4.1.10015.17.2", true, "dotted OIDs", "Certificate policies the end-entity certificate must carry (Q-02)."},
	{"EIDBRIDGE_SMARTID_CERT_LEVEL", "QUALIFIED", false, "ADVANCED or QUALIFIED", "Minimum certificate level."},
	{"EIDBRIDGE_SMARTID_FLOWS", "device-link", false, "device-link, notification", "device-link offers QR and same-device; notification is opt-in."},
	{"EIDBRIDGE_SMARTID_CERT_STATUS", "ocsp", true, "ocsp or none (demo only)", "Certificate status checking."},
	{"EIDBRIDGE_SMARTID_STATUS_HOSTS", "aia.demo.sk.ee,c.sk.ee", true, "host[:port] list", "Allow-listed OCSP/CRL hosts."},
	{"EIDBRIDGE_SMARTID_DISPLAY_TEXT", "Log in to the service", false, "≤ 60 characters", "Text shown on the device; per-client overrides in the clients file."},
	{"EIDBRIDGE_MOBILEID_ENV", "demo", true, "demo, production, mock", "Mobile-ID (only read when `mobileid` is in EIDBRIDGE_METHODS). Must agree with mode; mock is demo-only."},
	{"EIDBRIDGE_MOBILEID_BASE_URL", "https://tsp.demo.sk.ee/mid-api", true, "", "MID REST API base URL."},
	{"EIDBRIDGE_MOBILEID_RP_UUID", "00000000-0000-0000-0000-000000000000", true, "lower-case UUID", "Mobile-ID relying-party UUID from your agreement."},
	{"EIDBRIDGE_MOBILEID_RP_NAME", "DEMO", true, "", "Mobile-ID relying-party name."},
	{"EIDBRIDGE_MOBILEID_TLS_PINS", "disabled", true, "sha256/<b64>[,…] or disabled", "SPKI pins of the MID API host (current and next)."},
	{"EIDBRIDGE_MOBILEID_TLS_PINS_DISABLED_ACK", "", false, "I_UNDERSTAND", "Production acknowledgement for disabled Mobile-ID pins."},
	{"EIDBRIDGE_MOBILEID_AUTH_CA_DIR", "trust/demo/mobileid-auth-ca", true, "", "Mobile-ID authentication CA certificates."},
	{"EIDBRIDGE_MOBILEID_POLICY_OIDS", "1.3.6.1.4.1.10015.18.1", true, "dotted OIDs", "Certificate policies the Mobile-ID certificate must carry."},
	{"EIDBRIDGE_MOBILEID_CERT_STATUS", "ocsp", true, "ocsp or none (demo only)", "Mobile-ID certificate status checking. The demo OCSP marks demo certificates as non-issued; use none in demo."},
	{"EIDBRIDGE_MOBILEID_STATUS_HOSTS", "aia.demo.sk.ee,c.sk.ee", true, "host[:port] list", "Allow-listed OCSP/CRL hosts for Mobile-ID."},
	{"EIDBRIDGE_MOBILEID_DISPLAY_TEXT", "Log in", false, "≤ 40 GSM-7 characters", "Text shown on the phone next to the relying-party name."},
}

// Config is the validated configuration.
type Config struct {
	Mode                                                 string
	Demo                                                 bool
	Listen                                               string
	BaseURL                                              string
	Issuer                                               string
	Methods                                              []string
	Clients                                              []oidc.Client
	KeyDir                                               string
	Subjects                                             *oidc.Subjects
	DenyFP                                               []string
	MethodACR                                            map[string]string
	FlowTTL, AccessTokenTTL, ClockSkew, RetryBase, Grace time.Duration
	RetryBudget                                          int
	MaxFlows, CodeCap, PollSlots, BucketCap              int
	UpstreamRate                                         float64
	PerIP, PerClient, PerTarget                          [2]float64 // burst, rate
	TrustedProxies                                       []netip.Prefix
	DefaultLocale                                        string
	RememberMethod                                       bool
	LogDebug                                             bool
	TLSCert, TLSKey                                      string
	MockDocument, MockListen                             string
	Warnings                                             []string
	Deviations                                           []string

	SmartID  SmartIDConfig
	MobileID MobileIDConfig
	Extra    map[string]string // method-specific variables, parsed by their packages
}

// SmartIDConfig is the Smart-ID method configuration.
type SmartIDConfig struct {
	Env, BaseURL, RPUUID, RPName string
	Pins                         tlspin.Resolved
	CADir                        string
	PolicyOIDs                   []string
	CertLevel                    string
	Flows                        []string
	CertStatus                   string
	StatusHosts                  []string
	DisplayText                  string
	Trust                        *smartid.TrustStore
}

// MobileIDConfig is the Mobile-ID method configuration.
type MobileIDConfig struct {
	Env, BaseURL, RPUUID, RPName string
	Pins                         tlspin.Resolved
	CADir                        string
	PolicyOIDs                   []string
	CertStatus                   string
	StatusHosts                  []string
	DisplayText                  string
	Trust                        *smartid.TrustStore
}

// Getenv abstracts the environment for tests.
type Getenv func(string) string

// Load reads configuration. demoFlag is the --demo flag; file is the
// optional JSON config file (clients, method_acr).
func Load(env Getenv, demoFlag bool, root string) (*Config, error) {
	mode := env("EIDBRIDGE_MODE")
	if demoFlag {
		if mode == "production" {
			return nil, errors.New("config: --demo conflicts with EIDBRIDGE_MODE=production")
		}
		mode = "demo"
	}
	if mode != "demo" && mode != "production" {
		return nil, errors.New("config: EIDBRIDGE_MODE is required (demo or production); there is no default")
	}
	c := &Config{Mode: mode, Demo: mode == "demo", Extra: map[string]string{}}
	var missing []string
	get := func(name string) string {
		v := env(name)
		if v != "" {
			return v
		}
		for _, o := range Options {
			if o.Env == name {
				if !c.Demo && o.ProdReq {
					missing = append(missing, name)
					return ""
				}
				return o.Demo
			}
		}
		return ""
	}
	dur := func(name string, lo, hi time.Duration) time.Duration {
		v := get(name)
		if v == "" {
			return 0
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < lo || d > hi {
			missing = append(missing, fmt.Sprintf("%s=%q (bounds %v–%v)", name, v, lo, hi))
		}
		return d
	}
	num := func(name string, lo, hi float64) float64 {
		v := get(name)
		if v == "" {
			return 0
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < lo || f > hi {
			missing = append(missing, fmt.Sprintf("%s=%q (bounds %v–%v)", name, v, lo, hi))
		}
		return f
	}
	c.Listen = get("EIDBRIDGE_LISTEN")
	c.BaseURL = strings.TrimRight(get("EIDBRIDGE_ISSUER"), "/")
	c.Methods = splitList(get("EIDBRIDGE_METHODS"))
	c.FlowTTL = dur("EIDBRIDGE_FLOW_TTL", 40*time.Second, 300*time.Second)
	c.AccessTokenTTL = dur("EIDBRIDGE_ACCESS_TOKEN_LIFETIME", time.Second, 300*time.Second)
	c.ClockSkew = dur("EIDBRIDGE_CLOCK_SKEW", 0, 120*time.Second)
	c.RetryBase = dur("EIDBRIDGE_RETRY_BASE", 50*time.Millisecond, 10*time.Second)
	c.Grace = dur("EIDBRIDGE_GRACE_PERIOD", 10*time.Second, 300*time.Second)
	c.RetryBudget = int(num("EIDBRIDGE_RETRY_BUDGET", 1, 10))
	c.MaxFlows = int(num("EIDBRIDGE_MAX_FLOWS", 1, 1e6))
	c.CodeCap = int(num("EIDBRIDGE_CODE_STORE_CAP", 1, 1e7))
	c.PollSlots = int(num("EIDBRIDGE_POLL_SLOTS", 1, 1e6))
	c.UpstreamRate = num("EIDBRIDGE_UPSTREAM_RATE", 0.1, 1e5)
	c.PerIP = [2]float64{num("EIDBRIDGE_PER_IP_BURST", 1, 1e6), num("EIDBRIDGE_PER_IP_RATE", 0.0001, 1e5)}
	c.PerClient = [2]float64{num("EIDBRIDGE_PER_CLIENT_BURST", 1, 1e7), num("EIDBRIDGE_PER_CLIENT_RATE", 0.0001, 1e6)}
	c.PerTarget = [2]float64{num("EIDBRIDGE_PER_TARGET_BURST", 1, 1e4), num("EIDBRIDGE_PER_TARGET_RATE", 0.00001, 100)}
	c.BucketCap = int(num("EIDBRIDGE_BUCKET_CAP", 10, 1e7))
	c.DefaultLocale = get("EIDBRIDGE_DEFAULT_LOCALE")
	c.RememberMethod = get("EIDBRIDGE_REMEMBER_METHOD") == "true"
	c.LogDebug = get("EIDBRIDGE_LOG_LEVEL") == "debug"
	c.TLSCert, c.TLSKey = env("EIDBRIDGE_TLS_CERT_FILE"), env("EIDBRIDGE_TLS_KEY_FILE")
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("config: EIDBRIDGE_TLS_CERT_FILE and EIDBRIDGE_TLS_KEY_FILE go together")
	}
	c.MockDocument, c.MockListen = get("EIDBRIDGE_MOCK_DOCUMENT"), get("EIDBRIDGE_MOCK_LISTEN")
	c.KeyDir = get("EIDBRIDGE_KEY_DIR")
	if c.KeyDir != "" && !filepath.IsAbs(c.KeyDir) && root != "" {
		c.KeyDir = filepath.Join(root, c.KeyDir)
	}
	if v := env("EIDBRIDGE_DEMO_KEY_DENYLIST"); v != "" {
		c.DenyFP = splitList(v)
	}
	if v := env("EIDBRIDGE_METHOD_ACR"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.MethodACR); err != nil {
			return nil, errors.New("config: EIDBRIDGE_METHOD_ACR must be a JSON object")
		}
		if c.Demo {
			return nil, errors.New("config: EIDBRIDGE_METHOD_ACR is production-only; demo always emits acr=demo")
		}
	}
	for _, p := range splitList(env("EIDBRIDGE_TRUSTED_PROXIES")) {
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("config: EIDBRIDGE_TRUSTED_PROXIES: %q is not a CIDR", p)
		}
		c.TrustedProxies = append(c.TrustedProxies, pr)
	}
	c.SmartID = SmartIDConfig{Env: get("EIDBRIDGE_SMARTID_ENV"), BaseURL: strings.TrimRight(get("EIDBRIDGE_SMARTID_BASE_URL"), "/"),
		RPUUID: get("EIDBRIDGE_RP_UUID"), RPName: get("EIDBRIDGE_RP_NAME"), CADir: get("EIDBRIDGE_SMARTID_AUTH_CA_DIR"),
		PolicyOIDs: splitList(get("EIDBRIDGE_SMARTID_POLICY_OIDS")), CertLevel: get("EIDBRIDGE_SMARTID_CERT_LEVEL"),
		CertStatus: get("EIDBRIDGE_SMARTID_CERT_STATUS"), StatusHosts: splitList(get("EIDBRIDGE_SMARTID_STATUS_HOSTS")),
		DisplayText: get("EIDBRIDGE_SMARTID_DISPLAY_TEXT")}
	if c.SmartID.CADir != "" && !filepath.IsAbs(c.SmartID.CADir) && root != "" {
		c.SmartID.CADir = filepath.Join(root, c.SmartID.CADir)
	}
	for _, f := range splitList(get("EIDBRIDGE_SMARTID_FLOWS")) {
		switch f {
		case "device-link":
			c.SmartID.Flows = append(c.SmartID.Flows, "qr", "same-device")
		case "notification":
			c.SmartID.Flows = append(c.SmartID.Flows, "notification")
		default:
			return nil, fmt.Errorf("config: EIDBRIDGE_SMARTID_FLOWS: unknown flow %q", f)
		}
	}
	pinVal := get("EIDBRIDGE_SMARTID_TLS_PINS")
	var midPins string
	if contains(c.Methods, "mobileid") {
		m := &c.MobileID
		*m = MobileIDConfig{Env: get("EIDBRIDGE_MOBILEID_ENV"), BaseURL: strings.TrimRight(get("EIDBRIDGE_MOBILEID_BASE_URL"), "/"),
			RPUUID: get("EIDBRIDGE_MOBILEID_RP_UUID"), RPName: get("EIDBRIDGE_MOBILEID_RP_NAME"), CADir: get("EIDBRIDGE_MOBILEID_AUTH_CA_DIR"),
			PolicyOIDs: splitList(get("EIDBRIDGE_MOBILEID_POLICY_OIDS")), CertStatus: get("EIDBRIDGE_MOBILEID_CERT_STATUS"),
			StatusHosts: splitList(get("EIDBRIDGE_MOBILEID_STATUS_HOSTS")), DisplayText: get("EIDBRIDGE_MOBILEID_DISPLAY_TEXT")}
		if m.CADir != "" && !filepath.IsAbs(m.CADir) && root != "" {
			m.CADir = filepath.Join(root, m.CADir)
		}
		midPins = get("EIDBRIDGE_MOBILEID_TLS_PINS")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("config: production requires explicit values (or a value is out of bounds): %s", strings.Join(missing, ", "))
	}
	if contains(c.Methods, "smartid") {
		pins, err := tlspin.Policy(mode, pinVal, env("EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK") == "I_UNDERSTAND")
		if err != nil {
			return nil, fmt.Errorf("config: EIDBRIDGE_SMARTID_TLS_PINS: %w", err)
		}
		c.SmartID.Pins = pins
		if pins.Warning != "" {
			c.Warnings = append(c.Warnings, pins.Warning)
		}
		if pins.Deviation != "" {
			c.Deviations = append(c.Deviations, pins.Deviation)
		}
	}
	if contains(c.Methods, "mobileid") && c.MobileID.Env != "mock" {
		pins, err := tlspin.Policy(mode, midPins, env("EIDBRIDGE_MOBILEID_TLS_PINS_DISABLED_ACK") == "I_UNDERSTAND")
		if err != nil {
			return nil, fmt.Errorf("config: EIDBRIDGE_MOBILEID_TLS_PINS: %w", err)
		}
		c.MobileID.Pins = pins
		if pins.Warning != "" {
			c.Warnings = append(c.Warnings, "Mobile-ID: "+pins.Warning)
		}
		if pins.Deviation != "" {
			c.Deviations = append(c.Deviations, "Mobile-ID: "+pins.Deviation)
		}
	}
	if err := c.invariants(env, root); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) invariants(env Getenv, root string) error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("config: EIDBRIDGE_ISSUER must be an absolute URL")
	}
	switch {
	case !c.Demo && u.Scheme != "https":
		return errors.New("config: production issuer must be https")
	case c.Demo && u.Scheme == "http" && u.Hostname() != "localhost":
		return errors.New("config: demo allows http only on localhost")
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("config: issuer scheme must be https")
	}
	if !c.Demo && strings.HasSuffix(u.Path, "/demo") {
		return errors.New("config: the /demo issuer path is reserved for demo mode")
	}
	c.Issuer = c.BaseURL
	if c.Demo {
		c.Issuer += "/demo"
	}
	if c.PollSlots > c.MaxFlows {
		return errors.New("config: EIDBRIDGE_POLL_SLOTS must not exceed EIDBRIDGE_MAX_FLOWS")
	}
	if c.CodeCap < c.MaxFlows {
		return errors.New("config: EIDBRIDGE_CODE_STORE_CAP must be at least EIDBRIDGE_MAX_FLOWS")
	}
	if len(c.Methods) == 0 {
		return errors.New("config: EIDBRIDGE_METHODS is empty")
	}
	for _, m := range c.Methods {
		if !contains([]string{"smartid", "mobileid", "webeid", "eudi", "smartid-v2"}, m) {
			return fmt.Errorf("config: unknown method %q", m)
		}
	}
	if !contains([]string{"en", "et", "lv", "lt", "ru"}, c.DefaultLocale) {
		return errors.New("config: EIDBRIDGE_DEFAULT_LOCALE must be en, et, lv, lt or ru")
	}
	if err := c.loadClients(env, root); err != nil {
		return err
	}
	if err := c.loadSubjects(env); err != nil {
		return err
	}
	if contains(c.Methods, "smartid") {
		if err := c.smartIDInvariants(); err != nil {
			return err
		}
	}
	if contains(c.Methods, "mobileid") {
		if err := c.mobileIDInvariants(); err != nil {
			return err
		}
	}
	return nil
}

// mobileIDInvariants applies the demo/production rules of ADR-003 to
// Mobile-ID: environment agrees with mode, demo hosts, RP identity and CAs
// never mix with production, production checks status and policies.
func (c *Config) mobileIDInvariants() error {
	m := &c.MobileID
	switch {
	case c.Demo && m.Env == "production", !c.Demo && m.Env != "production":
		return fmt.Errorf("config: EIDBRIDGE_MOBILEID_ENV=%s disagrees with mode %s", m.Env, c.Mode)
	case m.Env != "demo" && m.Env != "production" && m.Env != "mock":
		return errors.New("config: EIDBRIDGE_MOBILEID_ENV must be demo, production or mock")
	}
	if !mobileid.ValidDisplayText(m.DisplayText) {
		return errors.New("config: EIDBRIDGE_MOBILEID_DISPLAY_TEXT must be ≤ 40 plain GSM-7 characters")
	}
	if m.Env == "mock" {
		if !c.Demo {
			return errors.New("config: EIDBRIDGE_MOBILEID_ENV=mock is demo-only")
		}
		c.Warnings = append(c.Warnings, "Mobile-ID uses the built-in fixture upstream (mock): synthetic identities only")
		return nil
	}
	u, err := url.Parse(m.BaseURL)
	if err != nil || u.Host == "" {
		return errors.New("config: EIDBRIDGE_MOBILEID_BASE_URL is invalid")
	}
	host := u.Hostname()
	if c.Demo {
		if !IsDemoHost(host) {
			return fmt.Errorf("config: demo mode refuses Mobile-ID host %s outside the demo allow-list", host)
		}
		if m.RPUUID != DemoMIDRPUUID || m.RPName != DemoRPName {
			return errors.New("config: demo mode uses the public Mobile-ID demo relying party only")
		}
	} else {
		if IsDemoHost(host) {
			return fmt.Errorf("config: production refuses demo host %s", host)
		}
		for _, sh := range m.StatusHosts {
			if IsDemoHost(sh) {
				return fmt.Errorf("config: production refuses demo host %s in EIDBRIDGE_MOBILEID_STATUS_HOSTS", sh)
			}
		}
		if m.RPUUID == DemoMIDRPUUID || m.RPName == DemoRPName {
			return errors.New("config: production refuses the public Mobile-ID demo relying-party identity")
		}
		if u.Scheme != "https" {
			return errors.New("config: production Mobile-ID base URL must be https")
		}
		if m.CertStatus != "ocsp" {
			return errors.New("config: production requires EIDBRIDGE_MOBILEID_CERT_STATUS=ocsp")
		}
		if len(m.PolicyOIDs) == 0 {
			return errors.New("config: production requires EIDBRIDGE_MOBILEID_POLICY_OIDS")
		}
	}
	if m.CertStatus != "ocsp" && m.CertStatus != "none" {
		return errors.New("config: EIDBRIDGE_MOBILEID_CERT_STATUS must be ocsp or none")
	}
	if m.CertStatus == "none" {
		c.Warnings = append(c.Warnings, "Mobile-ID certificate status checking is off (demo only)")
	}
	trust, err := smartid.LoadCADir(m.CADir)
	if err != nil {
		return fmt.Errorf("config: Mobile-ID: %w", err)
	}
	for _, crt := range trust.Certificates() {
		sum := sha256.Sum256(crt.Raw)
		_, isDemo := DemoCAFingerprints[hex.EncodeToString(sum[:])]
		switch {
		case !c.Demo && isDemo:
			return fmt.Errorf("config: production refuses demo CA %q (mixed trust)", crt.Subject.CommonName)
		case c.Demo && !isDemo:
			return fmt.Errorf("config: demo mode refuses non-demo CA %q (mixed trust)", crt.Subject.CommonName)
		}
	}
	m.Trust = trust
	return nil
}

func (c *Config) smartIDInvariants() error {
	s := &c.SmartID
	u, err := url.Parse(s.BaseURL)
	if err != nil || u.Host == "" {
		return errors.New("config: EIDBRIDGE_SMARTID_BASE_URL is invalid")
	}
	host := u.Hostname()
	switch {
	case c.Demo && s.Env == "production", !c.Demo && s.Env != "production":
		return fmt.Errorf("config: EIDBRIDGE_SMARTID_ENV=%s disagrees with mode %s", s.Env, c.Mode)
	case s.Env != "demo" && s.Env != "production" && s.Env != "mock":
		return errors.New("config: EIDBRIDGE_SMARTID_ENV must be demo, production or mock")
	}
	if s.Env == "mock" {
		if !c.Demo {
			return errors.New("config: EIDBRIDGE_SMARTID_ENV=mock is demo-only")
		}
		if h, _, err := net.SplitHostPort(c.MockListen); err != nil || (h != "127.0.0.1" && h != "localhost" && h != "::1") {
			return errors.New("config: EIDBRIDGE_MOCK_LISTEN must be a loopback address")
		}
		c.Warnings = append(c.Warnings, "Smart-ID uses the built-in fixture upstream (mock): synthetic identities only")
		return nil // trust comes from the in-process fixture PKI
	}
	if c.Demo {
		if s.Env == "demo" && !IsDemoHost(host) {
			return fmt.Errorf("config: demo mode refuses Smart-ID host %s outside the demo allow-list", host)
		}
		if IsProductionHost(host) {
			return errors.New("config: demo mode refuses production Smart-ID hosts")
		}
		if s.Env == "demo" && (s.RPUUID != DemoRPUUID || s.RPName != DemoRPName) {
			return errors.New("config: demo mode uses the public demo relying party only")
		}
	} else {
		if IsDemoHost(host) {
			return fmt.Errorf("config: production refuses demo host %s", host)
		}
		for _, sh := range s.StatusHosts {
			if IsDemoHost(sh) {
				return fmt.Errorf("config: production refuses demo host %s in EIDBRIDGE_SMARTID_STATUS_HOSTS", sh)
			}
		}
		if s.RPUUID == DemoRPUUID || s.RPName == DemoRPName {
			return errors.New("config: production refuses the public demo relying-party identity")
		}
		if u.Scheme != "https" {
			return errors.New("config: production Smart-ID base URL must be https")
		}
		if s.CertStatus != "ocsp" {
			return errors.New("config: production requires EIDBRIDGE_SMARTID_CERT_STATUS=ocsp")
		}
		if len(s.PolicyOIDs) == 0 {
			return errors.New("config: production requires EIDBRIDGE_SMARTID_POLICY_OIDS (Q-02)")
		}
	}
	if s.CertStatus != "ocsp" && s.CertStatus != "none" {
		return errors.New("config: EIDBRIDGE_SMARTID_CERT_STATUS must be ocsp or none")
	}
	if s.CertStatus == "none" {
		c.Warnings = append(c.Warnings, "Smart-ID certificate status checking is off (demo only)")
	}
	if s.CertLevel != smartid.LevelAdvanced && s.CertLevel != smartid.LevelQualified {
		return errors.New("config: EIDBRIDGE_SMARTID_CERT_LEVEL must be ADVANCED or QUALIFIED")
	}
	if _, err := smartid.Interactions(s.DisplayText); err != nil {
		return fmt.Errorf("config: EIDBRIDGE_SMARTID_DISPLAY_TEXT: %w", err)
	}
	for _, cl := range c.Clients {
		for lang, txt := range cl.DisplayText {
			if _, err := smartid.Interactions(txt); err != nil {
				return fmt.Errorf("config: client %s display_text[%s]: %w", cl.ID, lang, err)
			}
		}
	}
	if len(s.Flows) == 0 {
		return errors.New("config: EIDBRIDGE_SMARTID_FLOWS is empty")
	}
	trust, err := smartid.LoadCADir(s.CADir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, crt := range trust.Certificates() {
		sum := sha256.Sum256(crt.Raw)
		_, isDemo := DemoCAFingerprints[hex.EncodeToString(sum[:])]
		switch {
		case !c.Demo && isDemo:
			return fmt.Errorf("config: production refuses demo CA %q (mixed trust)", crt.Subject.CommonName)
		case c.Demo && s.Env == "demo" && !isDemo:
			return fmt.Errorf("config: demo mode refuses non-demo CA %q (mixed trust)", crt.Subject.CommonName)
		}
	}
	s.Trust = trust
	return nil
}

func (c *Config) loadClients(env Getenv, root string) error {
	path := env("EIDBRIDGE_CLIENTS_FILE")
	if path == "" {
		if !c.Demo {
			return errors.New("config: production requires EIDBRIDGE_CLIENTS_FILE")
		}
		sec := env("EIDBRIDGE_DEMO_CLIENT_SECRET")
		if sec == "" {
			sec = "demo-client-secret-not-for-production-use"
		}
		ru := splitList(env("EIDBRIDGE_DEMO_REDIRECT_URIS"))
		if len(ru) == 0 {
			ru = []string{"http://localhost:8081/callback"}
		}
		c.Clients = []oidc.Client{{ID: "demo-rp", Secret: sec, AuthMethod: oidc.AuthBasic, RedirectURIs: ru, SubMode: "pairwise"}}
		return nil
	}
	if !filepath.IsAbs(path) && root != "" {
		path = filepath.Join(root, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: clients file: %w", err)
	}
	if err := json.Unmarshal(b, &c.Clients); err != nil {
		return fmt.Errorf("config: clients file: %w", err)
	}
	for i := range c.Clients {
		cl := &c.Clients[i]
		if strings.HasPrefix(cl.Secret, "file:") {
			sb, err := os.ReadFile(strings.TrimPrefix(cl.Secret, "file:"))
			if err != nil {
				return fmt.Errorf("config: client %s secret file: %w", cl.ID, err)
			}
			cl.Secret = strings.TrimSpace(string(sb))
		}
		if !c.Demo && cl.Secret == "demo-client-secret-not-for-production-use" {
			return errors.New("config: production refuses the demo client secret")
		}
	}
	return nil
}

func (c *Config) loadSubjects(env Getenv) error {
	path := env("EIDBRIDGE_SUB_KEY_FILE")
	if path == "" {
		if !c.Demo {
			return errors.New("config: production requires EIDBRIDGE_SUB_KEY_FILE (K_sub)")
		}
		k := make([]byte, 32)
		if _, err := randRead(k); err != nil {
			return err
		}
		c.Subjects = &oidc.Subjects{Keys: map[int][]byte{1: k}, Current: 1}
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: K_sub file: %w", err)
	}
	var f struct {
		Current int               `json:"current"`
		Keys    map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(b, &f); err != nil || f.Current == 0 {
		return errors.New("config: K_sub file must be {\"current\":N,\"keys\":{\"N\":\"<base64>\"}} with a version set")
	}
	s := &oidc.Subjects{Keys: map[int][]byte{}, Current: f.Current}
	for v, k := range f.Keys {
		n, err := strconv.Atoi(v)
		raw, err2 := base64.StdEncoding.DecodeString(k)
		if err != nil || err2 != nil || len(raw) != 32 {
			return fmt.Errorf("config: K_sub version %q must be 32 bytes base64", v)
		}
		s.Keys[n] = raw
	}
	if m := env("EIDBRIDGE_SUB_MIGRATION"); m != "" {
		var mg struct {
			From, To, Days int
			Started        time.Time
			Clients        map[string]string
		}
		if err := json.Unmarshal([]byte(m), &mg); err != nil {
			return errors.New("config: EIDBRIDGE_SUB_MIGRATION is not valid JSON")
		}
		s.Migration = &oidc.Migration{From: mg.From, To: mg.To, Days: mg.Days, Started: mg.Started, Clients: mg.Clients}
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	c.Subjects = s
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Markdown renders docs/configuration.md from Options.
func Markdown() string {
	var b strings.Builder
	b.WriteString("# Configuration\n\nGenerated from `internal/config` (`go run ./cmd/eidbridge config docs`); CI fails when this file and the code differ.\n\n")
	b.WriteString("Mode has no default. Demo mode uses the demo defaults below; production requires every variable marked required to be set explicitly. Startup fails on any invariant violation (architecture ADR-003 configuration invariants).\n\n")
	b.WriteString("| Variable | Demo default | Required in production | Bounds | Description |\n|---|---|---|---|---|\n")
	for _, o := range Options {
		req := "no"
		if o.ProdReq {
			req = "yes"
		}
		d := o.Demo
		if d == "" {
			d = "—"
		} else {
			d = "`" + d + "`"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", o.Env, d, req, o.Bounds, o.Desc)
	}
	b.WriteString("\nMethod-specific variables for Web eID, the EUDI Wallet and RP API v2 are listed in their guides under [docs/methods](methods/).\n")
	return b.String()
}
