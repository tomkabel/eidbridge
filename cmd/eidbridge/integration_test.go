package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/oidc"
)

func TestMain(m *testing.M) {
	oidc.DemoRSABits = 2048
	os.Exit(m.Run())
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type stack struct {
	t      *testing.T
	app    *App
	srv    *httptest.Server
	logs   *lockedBuf
	issuer string
	b      *http.Client
	nr     *http.Client
}

const testSecret = "integration-secret-integration-secret"

// newStack runs the real wiring (config.Load → Build) in demo mode with the
// built-in fixture upstream, behind TLS, with DEBUG logging captured.
func newStack(t *testing.T, extra map[string]string) *stack {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	env := map[string]string{"EIDBRIDGE_ISSUER": srv.URL, "EIDBRIDGE_SMARTID_ENV": "mock", "EIDBRIDGE_LOG_LEVEL": "debug",
		"EIDBRIDGE_KEY_DIR": t.TempDir(), "EIDBRIDGE_DEMO_CLIENT_SECRET": testSecret, "EIDBRIDGE_DEMO_REDIRECT_URIS": "https://rp.example/cb",
		"EIDBRIDGE_SMARTID_FLOWS": "device-link,notification"}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.Load(func(k string) string { return env[k] }, true, filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuf{}
	app, err := Build(cfg, newLogger(logs, true), clock.Real())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	srv.Config.Handler = app.Handler
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	s := &stack{t: t, app: app, srv: srv, logs: logs, issuer: cfg.Issuer,
		b: &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if r.URL.Host != strings.TrimPrefix(srv.URL, "https://") {
				return http.ErrUseLastResponse
			}
			return nil
		}},
		nr: &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return s
}

var ftRe = regexp.MustCompile(`name="ft" value="([^"]+)"`)

func body(r *http.Response) string { b, _ := io.ReadAll(r.Body); r.Body.Close(); return string(b) }

// login performs authorize → choose → start → (fixture auto-resolves) →
// continue and returns the client redirect.
func (s *stack) login(flow string, form url.Values) *url.URL {
	s.t.Helper()
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st123"}, "nonce": {"nonce123"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	resp, err := s.b.Get(s.issuer + "/authorize?" + q.Encode())
	if err != nil {
		s.t.Fatal(err)
	}
	page := body(resp)
	m := ftRe.FindStringSubmatch(page)
	if m == nil {
		s.t.Fatalf("no choose page: %d %.300s", resp.StatusCode, page)
	}
	id := strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
	f := url.Values{"ft": {m[1]}, "method": {"smartid"}, "flow": {flow}}
	for k, v := range form {
		f[k] = v
	}
	resp, err = s.b.PostForm(s.issuer+"/flow/"+id+"/start", f)
	if err != nil {
		s.t.Fatal(err)
	}
	body(resp)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := s.b.Get(s.issuer + "/flow/" + id + "/status")
		var st struct{ State, Next string }
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		if st.Next != "" {
			r, err := s.nr.Get(s.srv.URL + st.Next)
			if err != nil {
				s.t.Fatal(err)
			}
			r.Body.Close()
			u, _ := url.Parse(r.Header.Get("Location"))
			return u
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatal("login did not finish")
	return nil
}

func (s *stack) token(code string) map[string]any {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp.example/cb"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	req, _ := http.NewRequest(http.MethodPost, s.issuer+"/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-rp", testSecret)
	r, err := s.nr.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	r.Body.Close()
	return m
}

// TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData is the PACKET-
// INTEGRATION run: real wiring, fixture upstream, DEBUG logging. The
// captured logs must not contain the personal code, certificate, signature,
// authorization code or tokens (Story 1.3 AC 2, NFR-002).
func TestFixtureLoginEndToEndAndDebugLogsHaveNoIdentityData(t *testing.T) {
	s := newStack(t, nil)
	var secrets []string
	for _, flow := range []string{"qr", "notification"} {
		form := url.Values{}
		if flow == "notification" {
			form = url.Values{"country": {"EE"}, "personal_code": {"40404040009"}}
		}
		u := s.login(flow, form)
		code := u.Query().Get("code")
		if code == "" || u.Query().Get("iss") != s.issuer {
			t.Fatalf("%s: redirect %s", flow, u)
		}
		tok := s.token(code)
		idt, _ := tok["id_token"].(string)
		at, _ := tok["access_token"].(string)
		if idt == "" || at == "" {
			t.Fatalf("%s: token %v", flow, tok)
		}
		parts := strings.Split(idt, ".")
		cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var cl map[string]any
		json.Unmarshal(cb, &cl)
		if cl["acr"] != "demo" || cl["eid_env"] != "demo" || cl["given_name"] != "OK" {
			t.Fatalf("%s: claims %v", flow, cl)
		}
		req, _ := http.NewRequest(http.MethodGet, s.issuer+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		r, _ := s.nr.Do(req)
		if r.StatusCode != 200 {
			t.Fatalf("%s: userinfo %d", flow, r.StatusCode)
		}
		r.Body.Close()
		secrets = append(secrets, code, idt, at, parts[2], cl["sub"].(string))
	}
	leaf := s.app.Fixture.Leaf("PNOEE-40404040009")
	certB64 := base64.StdEncoding.EncodeToString(leaf.Cert.Raw)
	secrets = append(secrets, "40404040009", certB64[:40], certB64[200:240], "TEST,OK")
	logs := s.logs.String()
	if !strings.Contains(logs, `"level":"DEBUG"`) && !strings.Contains(logs, "DEBUG") {
		t.Fatal("DEBUG level not active")
	}
	for _, sec := range secrets {
		if sec != "" && strings.Contains(logs, sec) {
			t.Fatalf("DEBUG logs contain identity data or a secret (%.12s…)", sec)
		}
	}
	if s.app.Web.FlowCount() != 0 {
		t.Fatalf("%d flow entries remain after delivery", s.app.Web.FlowCount())
	}
}

// FR-005: the OIDC and web packages depend on internal/authn only, never on
// a method package.
func TestOIDCAndWebImportOnlyAuthn(t *testing.T) {
	for _, pkg := range []string{"./internal/oidc", "./internal/web"} {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "github.com/tomkabel/eidbridge/"+strings.TrimPrefix(pkg, "./")).Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			for _, bad := range []string{"/internal/smartid", "/internal/mobileid", "/internal/webeid", "/internal/eudi"} {
				if strings.Contains(line, "eidbridge"+bad) {
					t.Fatalf("%s depends on %s", pkg, line)
				}
			}
		}
	}
}

// Story 2.7: EIDBRIDGE_MODE=production eidbridge --demo exits non-zero with a
// clear message; production without RP identity or key fails clearly.
func TestProductionDemoFlagExitsNonZero(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--demo"}, func(k string) string {
		if k == "EIDBRIDGE_MODE" {
			return "production"
		}
		return ""
	}, io.Discard, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--demo conflicts with EIDBRIDGE_MODE=production") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run(nil, func(string) string { return "" }, io.Discard, &stderr); code == 0 || !strings.Contains(stderr.String(), "EIDBRIDGE_MODE is required") {
		t.Fatalf("mode unset: %d %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run(nil, func(k string) string {
		return map[string]string{"EIDBRIDGE_MODE": "production", "EIDBRIDGE_ISSUER": "https://eid.example.com"}[k]
	}, io.Discard, &stderr); code == 0 || !strings.Contains(stderr.String(), "EIDBRIDGE_RP_UUID") || !strings.Contains(stderr.String(), "EIDBRIDGE_KEY_DIR") {
		t.Fatalf("production without RP identity/key: %d %s", code, stderr.String())
	}
}

func TestConfigDocsCommand(t *testing.T) {
	var out bytes.Buffer
	if run([]string{"config", "docs"}, func(string) string { return "" }, &out, io.Discard) != 0 || out.String() != config.Markdown() {
		t.Fatal("config docs")
	}
}

// Story 2.4 AC: the discovery document is valid JSON with the required
// fields (the jq check from the source issue).
func TestDiscoveryOverRealWiring(t *testing.T) {
	s := newStack(t, nil)
	r, err := s.nr.Get(s.issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"} {
		if d[k] == nil {
			t.Errorf("discovery missing %s", k)
		}
	}
}

// "eidbridge serve --demo" must mean the same as "eidbridge --demo serve";
// a flag after the subcommand was silently ignored before.
func TestFlagsAfterSubcommand(t *testing.T) {
	env := func(string) string { return "" }
	var out, errb strings.Builder
	if code := run([]string{"trust", "show", "--demo", "--root", "../.."}, env, &out, &errb); code != 0 {
		t.Fatalf("trust show --demo: exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "TEST") {
		t.Fatalf("demo trust not shown: %s", out.String())
	}
}

// Story 4.2 AC: EIDBRIDGE_METHODS=smartid,mobileid serves both on one login
// page; a Mobile-ID login completes through the same issuer, and DEBUG logs
// hold neither the phone number nor the personal code.
func TestSmartIDAndMobileIDOnOneLoginPage(t *testing.T) {
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,mobileid", "EIDBRIDGE_MOBILEID_ENV": "mock"})
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st123"}, "nonce": {"nonce123"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	resp, err := s.b.Get(s.issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := body(resp)
	if !strings.Contains(page, `value="smartid"`) || !strings.Contains(page, `value="mobileid"`) || !strings.Contains(page, `name="phone"`) {
		t.Fatalf("login page lacks one of the methods: %.400s", page)
	}
	u := s.login("notification", url.Values{"method": {"mobileid"}, "country": {"EE"}, "personal_code": {"51307149560"}, "phone": {"+37269930366"}})
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect %s", u)
	}
	tok := s.token(code)
	idt, _ := tok["id_token"].(string)
	parts := strings.Split(idt, ".")
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var cl map[string]any
	json.Unmarshal(cb, &cl)
	if cl["eid_method"] != "mobileid" || cl["given_name"] != "MARY ÄNN" || cl["acr"] != "demo" || cl["iss"] != s.issuer {
		t.Fatalf("claims %v", cl)
	}
	if amr, _ := cl["amr"].([]any); len(amr) != 1 || amr[0] != "mobileid" {
		t.Fatalf("amr %v", cl["amr"])
	}
	logs := s.logs.String()
	for _, sec := range []string{"51307149560", "37269930366", "MARY", code, idt, cl["sub"].(string)} {
		if strings.Contains(logs, sec) {
			t.Fatalf("DEBUG logs contain identity data or a secret (%.12s…)", sec)
		}
	}
}

// Story 5.1: an ID-card login through the bridge with the mock card CA. The
// test plays the browser extension: it reads the challenge from the page
// and posts a token signed over the bridge's origin.
func TestWebEIDLoginThroughBridge(t *testing.T) {
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,webeid", "EIDBRIDGE_WEBEID_ENV": "mock"})
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st123"}, "nonce": {"nonce123"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	resp, err := s.b.Get(s.issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := body(resp)
	id := strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
	ft := ftRe.FindStringSubmatch(page)[1]
	r, _ := s.b.PostForm(s.issuer+"/flow/"+id+"/start", url.Values{"ft": {ft}, "method": {"webeid"}, "flow": {"browser"}})
	pending := body(r)
	m := regexp.MustCompile(`data-challenge="([^"]+)"`).FindStringSubmatch(pending)
	if m == nil || !strings.Contains(pending, "/static/webeid.js") {
		t.Fatalf("no challenge or script on the page: %.400s", pending)
	}
	challenge := html.UnescapeString(m[1])
	leaf := webeidFixture.NewLeaf(webeidtest.LeafOptions{})
	// Wrong origin first: refused, and the nonce is spent.
	bad := leaf.Token("ES384", "https://evil.example", challenge)
	r, _ = s.nr.PostForm(s.issuer+"/flow/"+id+"/browser", url.Values{"ft": {ft}, "token": {string(bad)}})
	r.Body.Close()
	r, _ = s.nr.Get(s.issuer + "/flow/" + id + "/continue")
	r.Body.Close()
	if u, _ := url.Parse(r.Header.Get("Location")); u == nil || u.Query().Get("error") == "" {
		t.Fatalf("wrong-origin token did not end the flow with an error: %v", r.Header.Get("Location"))
	}
	// A fresh flow with the right origin logs in.
	resp, _ = s.b.Get(s.issuer + "/authorize?" + q.Encode())
	page = body(resp)
	id = strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
	ft = ftRe.FindStringSubmatch(page)[1]
	r, _ = s.b.PostForm(s.issuer+"/flow/"+id+"/start", url.Values{"ft": {ft}, "method": {"webeid"}, "flow": {"browser"}})
	challenge = html.UnescapeString(regexp.MustCompile(`data-challenge="([^"]+)"`).FindStringSubmatch(body(r))[1])
	r, _ = s.nr.PostForm(s.issuer+"/flow/"+id+"/browser", url.Values{"ft": {ft}, "token": {string(leaf.Token("ES384", s.srv.URL, challenge))}})
	r.Body.Close()
	r, _ = s.nr.Get(s.issuer + "/flow/" + id + "/continue")
	r.Body.Close()
	u, _ := url.Parse(r.Header.Get("Location"))
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect %s", u)
	}
	tok := s.token(code)
	idt, _ := tok["id_token"].(string)
	cb, _ := base64.RawURLEncoding.DecodeString(strings.Split(idt, ".")[1])
	var cl map[string]any
	json.Unmarshal(cb, &cl)
	if cl["eid_method"] != "webeid" || cl["given_name"] != "JAAK-KRISTJAN" || cl["acr"] != "demo" {
		t.Fatalf("claims %v", cl)
	}
	logs := s.logs.String()
	for _, sec := range []string{"38001085718", "JAAK", challenge, code, base64.StdEncoding.EncodeToString(leaf.Cert.Raw)[:40]} {
		if strings.Contains(logs, sec) {
			t.Fatalf("DEBUG logs contain identity data or a secret (%.12s…)", sec)
		}
	}
}

// Story 6.1: an EUDI Wallet login through the bridge (mock PID provider).
// The test plays the wallet: it scans the QR (PendingUI), fetches the
// signed request object over HTTPS, and posts a presentation to the
// response URI. A replayed presentation into a second flow is refused.
func TestEUDIWalletLoginThroughBridge(t *testing.T) {
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,eudi", "EIDBRIDGE_EUDI_ENV": "mock"})
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st123"}, "nonce": {"nonce123"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	startFlow := func() (string, *walletsim.Request) {
		resp, err := s.b.Get(s.issuer + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		page := body(resp)
		id := strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
		ft := ftRe.FindStringSubmatch(page)[1]
		r, _ := s.b.PostForm(s.issuer+"/flow/"+id+"/start", url.Values{"ft": {ft}, "method": {"eudi"}, "flow": {"qr"}})
		body(r)
		ui, ok := s.app.Web.PendingUI(id)
		if !ok || !strings.HasPrefix(ui.QRPayload, "openid4vp://") {
			t.Fatalf("no wallet QR: %+v", ui)
		}
		wallet := &http.Client{Transport: s.nr.Transport} // no cookies: the wallet is another device
		req, err := walletsim.FetchRequest(wallet, ui.QRPayload)
		if err != nil {
			t.Fatal(err)
		}
		return id, req
	}
	id, req := startFlow()
	w := eudiFixture.Issue(walletsim.IssueOptions{})
	vp := walletsim.VPToken(w.Present(req.Nonce, req.ClientID, walletsim.PresentOptions{}))
	wallet := &http.Client{Transport: s.nr.Transport}
	resp, err := walletsim.Respond(wallet, req, vp, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("wallet response: %v %v", err, resp.StatusCode)
	}
	resp.Body.Close()
	var next string
	for i := 0; i < 50 && next == ""; i++ {
		r, _ := s.b.Get(s.issuer + "/flow/" + id + "/status")
		var st struct{ Next string }
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		next = st.Next
		time.Sleep(50 * time.Millisecond)
	}
	r, _ := s.nr.Get(s.srv.URL + next)
	r.Body.Close()
	u, _ := url.Parse(r.Header.Get("Location"))
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect %s", u)
	}
	tok := s.token(code)
	idt, _ := tok["id_token"].(string)
	cb, _ := base64.RawURLEncoding.DecodeString(strings.Split(idt, ".")[1])
	var cl map[string]any
	json.Unmarshal(cb, &cl)
	if cl["eid_method"] != "eudi" || cl["given_name"] != "MARI" || cl["birthdate"] != "1990-05-17" || cl["acr"] != "demo" {
		t.Fatalf("claims %v", cl)
	}
	if amr, _ := cl["amr"].([]any); len(amr) != 1 || amr[0] != "eudi_pid" {
		t.Fatalf("amr %v", cl["amr"])
	}
	// Replay the same presentation into a new flow: refused with 400.
	_, req2 := startFlow()
	resp, _ = walletsim.Respond(wallet, req2, vp, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("replayed presentation answered %d", resp.StatusCode)
	}
	resp.Body.Close()
	// A response with a forged state is refused and does not end the flow.
	resp, _ = walletsim.Respond(wallet, &walletsim.Request{ResponseURI: req2.ResponseURI, State: "forged"}, vp, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("forged state answered %d", resp.StatusCode)
	}
	resp.Body.Close()
	logs := s.logs.String()
	for _, sec := range []string{"49005170005", "MARI", "1990-05-17", req.Nonce, code} {
		if strings.Contains(logs, sec) {
			t.Fatalf("DEBUG logs contain identity data or a secret (%.12s…)", sec)
		}
	}
}

// Story 7.3: doctor --json emits the documented schema; mock upstreams are
// not contacted.
func TestDoctorJSON(t *testing.T) {
	env := map[string]string{"EIDBRIDGE_SMARTID_ENV": "mock", "EIDBRIDGE_KEY_DIR": t.TempDir()}
	var out, errb strings.Builder
	code := run([]string{"--demo", "--root", "../..", "doctor", "--json"}, func(k string) string { return env[k] }, &out, &errb)
	var doc struct {
		Version int              `json:"version"`
		Results []map[string]any `json:"results"`
	}
	if code != 0 || json.Unmarshal([]byte(out.String()), &doc) != nil || doc.Version != 1 || len(doc.Results) != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if code := run([]string{"--demo", "doctor", "--bogus"}, func(k string) string { return env[k] }, &out, &errb); code != 2 {
		t.Fatalf("bad flag exit %d", code)
	}
}

// Story 7.4: the bridge runs against a standalone mock RP API (the server
// eidbridge-mock serves) trusting only its CA bundle; the test approves
// the session through the mock control API.
func TestBridgeAgainstExternalMock(t *testing.T) {
	fx := smartidtest.NewServer()
	fx.MaxWait = 500 * time.Millisecond
	hs := httptest.NewServer(fx)
	defer hs.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.pem"), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fx.PKI.Root.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fx.PKI.Inter.Raw})...), 0o644)
	s := newStack(t, map[string]string{"EIDBRIDGE_SMARTID_BASE_URL": hs.URL + "/smart-id-rp", "EIDBRIDGE_SMARTID_AUTH_CA_DIR": dir})
	if s.app.Fixture != nil {
		t.Fatal("in-process fixture started although an external mock is configured")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			r, err := http.Get(hs.URL + "/_mock/sessions")
			if err == nil {
				var l struct{ Pending []string }
				json.NewDecoder(r.Body).Decode(&l)
				r.Body.Close()
				if len(l.Pending) > 0 {
					http.Post(hs.URL+"/_mock/sessions/"+l.Pending[0]+"/complete", "", nil)
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	u := s.login("qr", nil)
	<-done
	if u.Query().Get("code") == "" {
		t.Fatalf("redirect %s", u)
	}
}
