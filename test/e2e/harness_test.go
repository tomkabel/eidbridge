//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// All containers and the bridge use host networking on ports 18000-18999 so the
// driver (this test), the bridge and the IdP all reach each other at
// http://localhost:<port>.
const (
	bridgePort   = 18080
	bridgeOrigin = "http://localhost:18080"
	bridgeIssuer = bridgeOrigin + "/demo"
)

var (
	binDir  string
	binOnce sync.Once
	binErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// requireDocker skips the test with a precise reason when docker is unusable.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary not found in PATH: " + err.Error())
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	if err != nil {
		t.Skipf("docker daemon unavailable (docker info: %v: %s)", err, strings.TrimSpace(string(out)))
	}
}

func portFree(t *testing.T, port int) {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port %d is already in use: %v", port, err)
	}
	l.Close()
}

// docker runs a docker CLI command and fails the test on error.
func docker(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

// pull pulls an image reference (tag@digest) and fails if it cannot.
func pull(t *testing.T, ref string) {
	t.Helper()
	if exec.Command("docker", "image", "inspect", ref).Run() == nil {
		return
	}
	var out []byte
	var err error
	for i := 0; i < 3; i++ { // registries rate-limit and flake
		if out, err = exec.Command("docker", "pull", ref).CombinedOutput(); err == nil {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("docker pull %s: %v\n%s", ref, err, out)
}

// runContainer starts a detached host-network container and removes it (dumping
// its logs when the test failed) on cleanup.
func runContainer(t *testing.T, name string, args ...string) {
	t.Helper()
	name = "eidbridge-e2e-" + name
	exec.Command("docker", "rm", "-f", name).Run()
	docker(t, append([]string{"run", "-d", "--network", "host", "--name", name}, args...)...)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "150", name).CombinedOutput()
			t.Logf("--- docker logs %s (tail) ---\n%s", name, out)
		}
		exec.Command("docker", "rm", "-f", name).Run()
	})
}

func waitHTTP(t *testing.T, u string, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last string
	for time.Now().Before(deadline) {
		r, err := http.Get(u)
		if err == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == want {
				return
			}
			last = r.Status
		} else {
			last = err.Error()
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not return %d within %s (last: %s)", u, want, d, last)
}

func buildBridge(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "eidbridge-e2e-bin")
		if binErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-o", filepath.Join(binDir, "eidbridge"), "./cmd/eidbridge")
		cmd.Dir = repoRoot()
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return filepath.Join(binDir, "eidbridge")
}

// bridgeClient is the OIDC client registered at the bridge for one IdP.
type bridgeClient struct {
	ID, Secret string
}

// startBridge runs `eidbridge serve --demo` with its fixture upstream (mock
// environment) and one static client whose redirect URI is the IdP's broker
// callback. authMethod is client_secret_basic or client_secret_post.
func startBridge(t *testing.T, clientID, authMethod string, redirectURIs ...string) bridgeClient {
	t.Helper()
	bin := buildBridge(t)
	portFree(t, bridgePort)
	tmp := t.TempDir()
	cl := bridgeClient{ID: clientID, Secret: randHex(24)} // 48 hex chars
	b, _ := json.Marshal([]map[string]any{{"client_id": cl.ID, "client_secret": cl.Secret,
		"token_endpoint_auth_method": authMethod, "redirect_uris": redirectURIs, "sub_mode": "pairwise"}})
	clients := filepath.Join(tmp, "clients.json")
	if err := os.WriteFile(clients, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(bin, "serve", "--demo", "--root", repoRoot())
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("EIDBRIDGE_LISTEN=127.0.0.1:%d", bridgePort),
		"EIDBRIDGE_ISSUER="+bridgeOrigin,
		"EIDBRIDGE_SMARTID_ENV=mock",
		"EIDBRIDGE_SMARTID_CERT_STATUS=none",
		"EIDBRIDGE_KEY_DIR="+filepath.Join(tmp, "keys"),
		"EIDBRIDGE_CLIENTS_FILE="+clients)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("--- eidbridge log (tail) ---\n%s", tail(logs.String(), 3000))
		}
	})
	waitHTTP(t, bridgeOrigin+"/readyz", 200, 60*time.Second)
	return cl
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// looseJar is a cookie jar that, like a browser on localhost, returns Secure
// cookies (the bridge's __Host- cookies) over plain http.
type looseJar struct{ j *cookiejar.Jar }

func (l looseJar) SetCookies(u *url.URL, cs []*http.Cookie) {
	out := make([]*http.Cookie, len(cs))
	for i, c := range cs {
		c2 := *c
		c2.Secure = false
		out[i] = &c2
	}
	l.j.SetCookies(u, out)
}
func (l looseJar) Cookies(u *url.URL) []*http.Cookie { return l.j.Cookies(u) }

var (
	ftRe     = regexp.MustCompile(`name="ft" value="([^"]+)"`)
	flowPath = regexp.MustCompile(`^/demo/flow/([^/]+)$`)
)

// browser is a minimal browser: cookie jar, manual redirect following, and the
// bridge login page driver.
type browser struct {
	t *testing.T
	c *http.Client
}

func newBrowser(t *testing.T) *browser {
	j, _ := cookiejar.New(nil)
	return &browser{t: t, c: &http.Client{Jar: looseJar{j}, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, u string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept-Language", "en")
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// pageHandler lets an IdP test deal with its own 200 pages (e.g. a login chooser
// or a profile form). It returns the next URL to GET, or "" when it does not
// recognise the page.
type pageHandler func(b *browser, u *url.URL, body string) string

// Follow GETs start and follows redirects, driving the bridge login page when it
// appears, until the browser is redirected to a URL starting with stopPrefix. It
// returns that final URL without fetching it.
func (b *browser) Follow(start, stopPrefix string, h pageHandler) *url.URL {
	b.t.Helper()
	cur := start
	for hop := 0; hop < 60; hop++ {
		if strings.HasPrefix(cur, stopPrefix) {
			u, _ := url.Parse(cur)
			return u
		}
		resp, body := b.do(http.MethodGet, cur, nil)
		base, _ := url.Parse(cur)
		if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next, err := base.Parse(loc)
			if err != nil {
				b.t.Fatal(err)
			}
			cur = next.String()
			continue
		}
		if resp.StatusCode == 200 && base.Host == "localhost:18080" && flowPath.MatchString(base.Path) {
			cur = b.bridgeLogin(base, body)
			continue
		}
		if h != nil {
			if next := h(b, base, body); next != "" {
				cur = next
				continue
			}
		}
		b.t.Fatalf("unexpected page at %s: HTTP %d: %.600s", cur, resp.StatusCode, stripTags(body))
	}
	b.t.Fatalf("too many redirects from %s", start)
	return nil
}

// bridgeLogin performs the bridge login page: choose Smart-ID QR, start, wait for
// the fixture to approve, and return the continue URL.
func (b *browser) bridgeLogin(flowURL *url.URL, page string) string {
	b.t.Helper()
	m := ftRe.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("bridge page %s has no flow token: %.400s", flowURL, stripTags(page))
	}
	id := flowPath.FindStringSubmatch(flowURL.Path)[1]
	resp, body := b.do(http.MethodPost, bridgeOrigin+"/demo/flow/"+id+"/start",
		url.Values{"ft": {html.UnescapeString(m[1])}, "method": {"smartid"}, "flow": {"qr"}})
	if resp.StatusCode >= 400 {
		b.t.Fatalf("bridge start: HTTP %d: %.300s", resp.StatusCode, stripTags(body))
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, sb := b.do(http.MethodGet, bridgeOrigin+"/demo/flow/"+id+"/status", nil)
		var st struct{ State, Next string }
		json.Unmarshal([]byte(sb), &st)
		if st.Next != "" {
			return bridgeOrigin + st.Next
		}
		time.Sleep(200 * time.Millisecond)
	}
	b.t.Fatal("bridge login flow did not finish within 30s")
	return ""
}

var tagRe = regexp.MustCompile(`(?s)<(script|style).*?</(script|style)>|<[^>]*>`)

func stripTags(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tagRe.ReplaceAllString(s, " "))), " ")
}

// jsonAPI is a tiny JSON-over-HTTP helper for IdP admin APIs.
type jsonAPI struct {
	t     *testing.T
	base  string
	auth  string // full Authorization header value
	extra map[string]string
}

func (a *jsonAPI) Do(method, path string, in any, out any) int {
	a.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		a.t.Fatal(err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if a.auth != "" {
		req.Header.Set("Authorization", a.auth)
	}
	for k, v := range a.extra {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && len(data) > 0 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			a.t.Fatalf("%s %s: decode: %v: %.300s", method, path, err, data)
		}
	}
	if resp.StatusCode >= 400 {
		a.t.Logf("%s %s -> HTTP %d: %.500s", method, path, resp.StatusCode, data)
	}
	return resp.StatusCode
}

// Must requires a 2xx status.
func (a *jsonAPI) Must(method, path string, in any, out any) {
	a.t.Helper()
	if st := a.Do(method, path, in, out); st >= 300 {
		a.t.Fatalf("%s %s: HTTP %d", method, path, st)
	}
}

// doQuiet is Do without logging HTTP errors (for readiness polling).
func (a *jsonAPI) doQuiet(method, path string, out any) int {
	req, _ := http.NewRequest(method, a.base+path, nil)
	if a.auth != "" {
		req.Header.Set("Authorization", a.auth)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == 200 {
		json.Unmarshal(data, out)
	}
	return resp.StatusCode
}

// postJSON POSTs a JSON body with the browser's cookies and returns the response body.
func (b *browser) postJSON(u string, in any) string {
	b.t.Helper()
	data, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range b.c.Jar.Cookies(req.URL) {
		if c.Name == "authentik_csrf" {
			req.Header.Set("X-authentik-CSRF", c.Value)
		}
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		b.t.Fatalf("POST %s: HTTP %d: %.300s", u, resp.StatusCode, out)
	}
	return string(out)
}

// fetch GETs u like a script in the page would: it follows redirects.
func (b *browser) fetch(u string) string {
	b.t.Helper()
	for i := 0; i < 8; i++ {
		resp, body := b.do(http.MethodGet, u, nil)
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" {
			return body
		}
		base, _ := url.Parse(u)
		n, _ := base.Parse(loc)
		u = n.String()
	}
	b.t.Fatalf("too many redirects fetching %s", u)
	return ""
}
