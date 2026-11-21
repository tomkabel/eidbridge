// Command eudi-conformance runs the EUDI Wallet verifier case catalog
// (conformance/cases) against an OpenID4VP verifier – by default a bridge it
// starts itself with the harness's simulated PID provider trusted – and
// writes JUnit XML and a Markdown report (Story 6.2). No certification of
// any kind is implied.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
)

type specRef struct {
	Doc, Section, URL string
}

type testCase struct {
	ID, Title, Expect, Mutation string
	Spec                        []specRef
	File                        string `yaml:"-"`
}

type result struct {
	Case     testCase
	Pass     bool
	Observed string
	Took     time.Duration
}

func main() {
	casesDir := flag.String("cases", "conformance/cases", "case catalog directory")
	bridgeBin := flag.String("bridge-bin", "", "eidbridge binary to start (the harness configures it)")
	repoRoot := flag.String("root", ".", "repository root for the bridge (--root)")
	junit := flag.String("junit", "", "write JUnit XML here")
	md := flag.String("md", "", "write a Markdown report here")
	flag.Parse()
	cases, err := loadCases(*casesDir)
	if err != nil {
		fail(err)
	}
	if *bridgeBin == "" {
		fail(errors.New("-bridge-bin is required (external targets need the harness CA configured; see conformance/README.md)"))
	}
	h, err := newHarness(*bridgeBin, *repoRoot)
	if err != nil {
		fail(err)
	}
	defer h.close()
	var results []result
	for _, c := range cases {
		start := time.Now()
		pass, observed := h.run(c)
		results = append(results, result{Case: c, Pass: pass, Observed: observed, Took: time.Since(start)})
		mark := "PASS"
		if !pass {
			mark = "FAIL"
		}
		fmt.Printf("%-4s %-28s expect=%-6s %s\n", mark, c.ID, c.Expect, observed)
	}
	if *junit != "" {
		if err := writeJUnit(*junit, results); err != nil {
			fail(err)
		}
	}
	if *md != "" {
		if err := writeMarkdown(*md, results); err != nil {
			fail(err)
		}
	}
	for _, r := range results {
		if !r.Pass {
			os.Exit(1)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "eudi-conformance:", err)
	os.Exit(2)
}

func loadCases(dir string) ([]testCase, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no cases in %s", dir)
	}
	sort.Strings(files)
	var out []testCase
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c testCase
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if c.ID == "" || (c.Expect != "accept" && c.Expect != "reject") || len(c.Spec) == 0 {
			return nil, fmt.Errorf("%s: id, expect (accept|reject) and spec are required", f)
		}
		c.File = filepath.Base(f)
		out = append(out, c)
	}
	return out, nil
}

type harness struct {
	prov    *walletsim.Provider
	other   *walletsim.Provider
	status  *httptest.Server
	cmd     *exec.Cmd
	issuer  string
	base    string
	tlsConf *tls.Config
	lastVP  string
}

func newHarness(bin, root string) (*harness, error) {
	dir, err := os.MkdirTemp("", "eudi-conformance-")
	if err != nil {
		return nil, err
	}
	h := &harness{prov: walletsim.NewProvider("conformance"), other: walletsim.NewProvider("untrusted")}
	h.status = httptest.NewServer(h.prov.StatusHandler())
	h.prov.StatusURI = h.status.URL + "/status/1"
	ca := filepath.Join(dir, "pid-ca")
	os.MkdirAll(ca, 0o755)
	os.WriteFile(filepath.Join(ca, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.prov.Root.Raw}), 0o644)
	certPEM, keyPEM, pool, err := selfSigned()
	if err != nil {
		return nil, err
	}
	os.WriteFile(filepath.Join(dir, "tls.pem"), certPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().String()
	ln.Close()
	port := addr[strings.LastIndex(addr, ":")+1:]
	h.base = "https://localhost:" + port
	h.issuer = h.base + "/demo"
	h.tlsConf = &tls.Config{RootCAs: pool}
	h.cmd = exec.Command(bin, "serve", "--demo", "--root", root)
	h.cmd.Env = append(os.Environ(), "EIDBRIDGE_LISTEN="+addr, "EIDBRIDGE_ISSUER="+h.base, "EIDBRIDGE_METHODS=eudi",
		"EIDBRIDGE_EUDI_ENV=demo", "EIDBRIDGE_EUDI_PID_CA_DIR="+ca, "EIDBRIDGE_EUDI_STATUS_HOSTS="+strings.TrimPrefix(h.status.URL, "http://"),
		"EIDBRIDGE_EUDI_FLOWS=same-device", "EIDBRIDGE_TLS_CERT_FILE="+filepath.Join(dir, "tls.pem"), "EIDBRIDGE_TLS_KEY_FILE="+filepath.Join(dir, "tls.key"),
		"EIDBRIDGE_KEY_DIR="+filepath.Join(dir, "keys"), "EIDBRIDGE_DEMO_REDIRECT_URIS=https://rp.example/cb", "EIDBRIDGE_SMARTID_ENV=mock")
	h.cmd.Stdout, h.cmd.Stderr = io.Discard, io.Discard
	if err := h.cmd.Start(); err != nil {
		return nil, err
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: h.tlsConf}, Timeout: 5 * time.Second}
	for i := 0; i < 100; i++ {
		if r, err := c.Get(h.base + "/readyz"); err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return h, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.close()
	return nil, errors.New("bridge did not become ready")
}

func (h *harness) close() {
	if h.cmd != nil && h.cmd.Process != nil {
		h.cmd.Process.Kill()
		h.cmd.Wait()
	}
	h.status.Close()
}

func selfSigned() (certPEM, keyPEM []byte, pool *x509.CertPool, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	d, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return nil, nil, nil, err
	}
	c, _ := x509.ParseCertificate(d)
	pool = x509.NewCertPool()
	pool.AddCert(c)
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), pool, nil
}

var (
	ftRe   = regexp.MustCompile(`name="ft" value="([^"]+)"`)
	linkRe = regexp.MustCompile(`href="(openid4vp://[^"]+)"`)
)

// browser holds the flow cookie manually (the bridge's __Host- cookies
// are Secure; Go's jar keeps them over https).
type browser struct {
	c  *http.Client
	nr *http.Client
}

func (h *harness) newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: h.tlsConf}
	return &browser{c: &http.Client{Jar: jar, Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			if r.URL.Host != strings.TrimPrefix(h.base, "https://") {
				return http.ErrUseLastResponse
			}
			return nil
		}},
		nr: &http.Client{Jar: jar, Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func readAll(r *http.Response) string { b, _ := io.ReadAll(r.Body); r.Body.Close(); return string(b) }

// startFlow logs a browser in up to the wallet link.
func (h *harness) startFlow() (*browser, string, string, error) {
	b := h.newBrowser()
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"}, "scope": {"openid profile"},
		"state": {"conformance"}, "nonce": {"conformance"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	resp, err := b.c.Get(h.issuer + "/authorize?" + q.Encode())
	if err != nil {
		return nil, "", "", err
	}
	page := readAll(resp)
	m := ftRe.FindStringSubmatch(page)
	if m == nil {
		return nil, "", "", fmt.Errorf("no login page (%d)", resp.StatusCode)
	}
	id := resp.Request.URL.Path[strings.LastIndex(resp.Request.URL.Path, "/")+1:]
	resp, err = b.c.PostForm(h.issuer+"/flow/"+id+"/start", url.Values{"ft": {m[1]}, "method": {"eudi"}, "flow": {"same-device"}})
	if err != nil {
		return nil, "", "", err
	}
	pending := readAll(resp)
	l := linkRe.FindStringSubmatch(pending)
	if l == nil {
		return nil, "", "", errors.New("no wallet link on the pending page")
	}
	return b, id, html.UnescapeString(l[1]), nil
}

// outcome polls the flow and follows continue; it reports whether the
// client received a code.
func (h *harness) outcome(b *browser, id string) string {
	for i := 0; i < 40; i++ {
		r, err := b.c.Get(h.issuer + "/flow/" + id + "/status")
		if err != nil {
			return "status error"
		}
		var st struct{ State, Next string }
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		if st.Next != "" {
			r, err := b.nr.Get(h.base + st.Next)
			if err != nil {
				return "continue error"
			}
			r.Body.Close()
			u, _ := url.Parse(r.Header.Get("Location"))
			if u.Query().Get("code") != "" {
				return "code"
			}
			return "error=" + u.Query().Get("error")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "pending"
}

func (h *harness) run(c testCase) (bool, string) {
	b, id, link, err := h.startFlow()
	if err != nil {
		return false, "setup: " + err.Error()
	}
	wallet := &http.Client{Transport: &http.Transport{TLSClientConfig: h.tlsConf}, Timeout: 10 * time.Second}
	req, err := walletsim.FetchRequest(wallet, link)
	if err != nil {
		return false, "request object: " + err.Error()
	}
	w := h.prov.Issue(walletsim.IssueOptions{})
	po := walletsim.PresentOptions{}
	stranger := h.other.Issue(walletsim.IssueOptions{})
	state := req.State
	var vp string
	switch c.Mutation {
	case "none":
	case "kb_nonce":
		po.Nonce = "nonce-from-another-request"
	case "kb_aud":
		po.Aud = "x509_hash:another-verifier"
	case "no_kb":
		po.NoKB = true
	case "kb_key":
		po.KBKey = stranger.HolderKey
	case "kb_sd_hash":
		po.BadSDHash = true
	case "expired":
		w = h.prov.Issue(walletsim.IssueOptions{Expired: true})
	case "untrusted_issuer":
		w = stranger
	case "wrong_vct":
		w = h.prov.Issue(walletsim.IssueOptions{VCT: "urn:example:not-pid"})
	case "injected_disclosure":
		po.ExtraDisclose = "personal_administrative_number"
	case "duplicate_disclosure":
		po.DupDisclosure, po.Disclose = true, []string{"given_name", "personal_administrative_number", "issuing_country"}
	case "revoked":
		h.prov.SetStatus(w.StatusIdx, 1)
	case "kb_stale":
		po.IAT = time.Now().Add(-30 * time.Minute)
	case "tampered_issuer":
		po.TamperIssuer = true
	case "issuer_typ":
		w = h.prov.Issue(walletsim.IssueOptions{Typ: "JWT"})
	case "replay":
		if h.lastVP == "" {
			return false, "no earlier accepted presentation to replay"
		}
		vp = h.lastVP
	case "wrong_state":
		state = "state-the-verifier-never-issued"
	default:
		return false, "unknown mutation " + c.Mutation
	}
	if vp == "" {
		vp = walletsim.VPToken(w.Present(req.Nonce, req.ClientID, po))
	}
	r2 := *req
	r2.State = state
	resp, err := walletsim.Respond(wallet, &r2, vp, nil)
	if err != nil {
		return false, "response: " + err.Error()
	}
	var ret struct {
		RedirectURI string `json:"redirect_uri"`
	}
	json.NewDecoder(resp.Body).Decode(&ret)
	resp.Body.Close()
	if ret.RedirectURI != "" {
		// Same-device: the wallet sends the login browser back with the
		// response_code (OpenID4VP 1.0 §8.2).
		if r, err := b.nr.Get(ret.RedirectURI); err == nil {
			r.Body.Close()
		}
	}
	out := h.outcome(b, id)
	if c.Mutation == "wrong_state" {
		// The flow must not complete with a forged state; it stays pending.
		observed := fmt.Sprintf("HTTP %d, flow %s", resp.StatusCode, out)
		return resp.StatusCode == 400 && out == "pending", observed
	}
	observed := fmt.Sprintf("HTTP %d, client got %s", resp.StatusCode, out)
	if c.Expect == "accept" {
		if resp.StatusCode == 200 && out == "code" {
			h.lastVP = vp
			return true, observed
		}
		return false, observed
	}
	return resp.StatusCode == 400 && out != "code", observed
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Time     string      `xml:"timestamp,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	SystemOut string        `xml:"system-out"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(path string, rs []result) error {
	s := junitSuite{Name: "eudi-openid4vp-verifier", Tests: len(rs), Time: time.Now().UTC().Format(time.RFC3339)}
	for _, r := range rs {
		var refs []string
		for _, sp := range r.Case.Spec {
			refs = append(refs, sp.Doc+" "+sp.Section+" <"+sp.URL+">")
		}
		jc := junitCase{Name: r.Case.ID, Classname: "conformance." + strings.TrimSuffix(r.Case.File, ".yaml"),
			Time: fmt.Sprintf("%.3f", r.Took.Seconds()), SystemOut: "expect " + r.Case.Expect + "; observed " + r.Observed + "\n" + strings.Join(refs, "\n")}
		if !r.Pass {
			s.Failures++
			jc.Failure = &junitFailure{Message: "expected " + r.Case.Expect + ", observed " + r.Observed}
		}
		s.Cases = append(s.Cases, jc)
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := xml.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, append([]byte(xml.Header), b...), 0o644)
}

func writeMarkdown(path string, rs []result) error {
	var b strings.Builder
	pass := 0
	for _, r := range rs {
		if r.Pass {
			pass++
		}
	}
	fmt.Fprintf(&b, "# EUDI verifier conformance report\n\nRun %s. %d of %d cases passed. Not a certification.\n\n", time.Now().UTC().Format(time.RFC3339), pass, len(rs))
	b.WriteString("| Case | Expect | Observed | Result | Specification |\n|---|---|---|---|---|\n")
	for _, r := range rs {
		res := "PASS"
		if !r.Pass {
			res = "FAIL"
		}
		var refs []string
		for _, sp := range r.Case.Spec {
			refs = append(refs, fmt.Sprintf("[%s %s](%s)", sp.Doc, sp.Section, sp.URL))
		}
		fmt.Fprintf(&b, "| `%s` %s | %s | %s | %s | %s |\n", r.Case.ID, r.Case.Title, r.Case.Expect, r.Observed, res, strings.Join(refs, "; "))
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
