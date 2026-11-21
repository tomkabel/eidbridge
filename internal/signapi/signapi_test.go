package signapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

type stubAuth map[string]string // user:pass → client id

func (s stubAuth) AuthenticateSigningClient(r *http.Request) (string, bool) {
	u, p, ok := r.BasicAuth()
	id, found := s[u+":"+p]
	return id, ok && found
}

var clients = stubAuth{"a:secret-a": "client-a", "b:secret-b": "client-b"}

func newAPI(t *testing.T, mod func(*Config)) (*Handler, *smartidtest.Server) {
	t.Helper()
	srv := smartidtest.NewServer()
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	c, err := smartid.NewClient(smartid.Config{BaseURL: hs.URL + "/smart-id-rp", RPUUID: smartid.DemoRPUUID, RPName: smartid.DemoRPName,
		SchemeName: smartid.SchemeDemo, Trust: smartid.NewTrustStore(srv.PKI.Root, srv.PKI.Inter), MinCertLevel: smartid.LevelQualified,
		Status: smartid.NoStatusCheck{}, PolicyOIDs: smartid.DemoPolicyOIDs, HTTP: hs.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Upstream: c, Auth: clients, PollTimeout: 200 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	h := New(cfg)
	t.Cleanup(h.Close)
	return h, srv
}

func call(h http.Handler, method, path, cred string, body any) (int, map[string]any) {
	var rd *bytes.Reader
	if s, ok := body.(string); ok {
		rd = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if cred != "" {
		u, p, _ := strings.Cut(cred, ":")
		req.SetBasicAuth(u, p)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func wait(t *testing.T, h http.Handler, cred, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		code, out := call(h, "GET", "/api/v1/sign/"+id, cred, nil)
		if code != 200 {
			t.Fatalf("status %d %v", code, out)
		}
		if out["status"] != "pending" {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout")
	return nil
}

var digest = func() string { d := sha256.Sum256([]byte("contract")); return base64.StdEncoding.EncodeToString(d[:]) }()

func certificate(t *testing.T, h http.Handler, cred string) string {
	t.Helper()
	code, out := call(h, "POST", "/api/v1/sign/certificate", cred, map[string]string{"signer": "PNOEE-40404040009"})
	if code != 202 {
		t.Fatalf("certificate: %d %v", code, out)
	}
	id := out["id"].(string)
	res := wait(t, h, cred, id)
	if res["status"] != "complete" || res["certificate"] == "" {
		t.Fatalf("certificate job: %v", res)
	}
	return id
}

func signBody(cert string) map[string]string {
	return map[string]string{"certificate": cert, "digest": digest, "hash_algorithm": "SHA-256",
		"signature_algorithm": "rsassa-pss", "display_text": "Sign the synthetic contract"}
}

func TestSignRoundTrip(t *testing.T) {
	h, _ := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	code, out := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert))
	if code != 202 || out["verification_code"] == nil {
		t.Fatalf("sign: %d %v", code, out)
	}
	res := wait(t, h, "a:secret-a", out["id"].(string))
	if res["status"] != "complete" || res["signature"] == "" || res["signature_algorithm"] != "rsassa-pss" || res["certificate"] == "" {
		t.Fatalf("result %v", res)
	}
	if _, ok := res["document_number"]; ok {
		t.Fatal("document number disclosed")
	}
	// The result is delivered once; a replayed read finds nothing.
	if code, _ := call(h, "GET", "/api/v1/sign/"+out["id"].(string), "a:secret-a", nil); code != 404 {
		t.Fatalf("second read: %d", code)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	h, srv := newAPI(t, nil)
	for _, cred := range []string{"", "a:wrong", "c:secret-a"} {
		for _, r := range []struct{ m, p string }{{"POST", "/api/v1/sign/certificate"}, {"POST", "/api/v1/sign"}, {"GET", "/api/v1/sign/x"}} {
			code, _ := call(h, r.m, r.p, cred, map[string]string{"signer": "PNOEE-40404040009"})
			if code != 401 {
				t.Errorf("%q %s %s: %d", cred, r.m, r.p, code)
			}
		}
	}
	if n := srv.Creates.Load(); n != 0 {
		t.Fatalf("%d upstream sessions created without authentication", n)
	}
}

func TestWrongClientCannotUseJobs(t *testing.T) {
	h, _ := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	if code, _ := call(h, "GET", "/api/v1/sign/"+cert, "b:secret-b", nil); code != 404 {
		t.Fatalf("other client read certificate job: %d", code)
	}
	if code, _ := call(h, "POST", "/api/v1/sign", "b:secret-b", signBody(cert)); code != 404 {
		t.Fatalf("other client used certificate: %d", code)
	}
	_, out := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert))
	if code, _ := call(h, "GET", "/api/v1/sign/"+out["id"].(string), "b:secret-b", nil); code != 404 {
		t.Fatalf("other client read signature: %d", code)
	}
}

func TestReplayedSignRejected(t *testing.T) {
	h, srv := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert)); code != 202 {
		t.Fatal(code)
	}
	before := srv.Creates.Load()
	if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert)); code != 404 {
		t.Fatalf("replayed sign: %d", code)
	}
	if srv.Creates.Load() != before {
		t.Fatal("replay reached upstream")
	}
}

func TestBadRequests(t *testing.T) {
	h, srv := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	before := srv.Creates.Load()
	bad := map[string]any{
		"unknown field":  map[string]string{"certificate": cert, "digest": digest, "hash_algorithm": "SHA-256", "signature_algorithm": "rsassa-pss", "display_text": "x", "extra": "1"},
		"short digest":   map[string]string{"certificate": cert, "digest": "AAAA", "hash_algorithm": "SHA-256", "signature_algorithm": "rsassa-pss", "display_text": "x"},
		"bad algorithm":  map[string]string{"certificate": cert, "digest": digest, "hash_algorithm": "SHA-256", "signature_algorithm": "md5", "display_text": "x"},
		"no text":        map[string]string{"certificate": cert, "digest": digest, "hash_algorithm": "SHA-256", "signature_algorithm": "rsassa-pss"},
		"not json":       "{",
		"oversized body": `{"display_text":"` + strings.Repeat("a", 20000) + `"}`,
	}
	for name, b := range bad {
		if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", b); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", map[string]string{"signer": "40404040009"}); code != 400 {
		t.Errorf("bad signer: %d", code)
	}
	if srv.Creates.Load() != before {
		t.Fatal("bad request reached upstream")
	}
	// The certificate is still usable after rejected requests.
	if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert)); code != 202 {
		t.Fatalf("valid sign after rejections: %d", code)
	}
}

func TestPendingCertificateCannotSign(t *testing.T) {
	h, srv := newAPI(t, nil)
	// Keep the upstream session pending: the fixture otherwise completes the
	// certificate choice on the first poll, which raced this request on CI.
	srv.FailPolls.Store(true)
	_, out := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", map[string]string{"signer": "PNOEE-40404040009"})
	if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(out["id"].(string))); code != 409 {
		t.Fatalf("sign with pending certificate: %d", code)
	}
}

func TestVerificationFailureReported(t *testing.T) {
	h, srv := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	srv.SetMutate(func(st map[string]any) { st["signatureProtocol"] = "ACSP_V2" })
	_, out := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert))
	res := wait(t, h, "a:secret-a", out["id"].(string))
	if res["status"] != "failed" || res["error"] != smartid.ReasonVerificationFailed || res["signature"] != nil {
		t.Fatalf("result %v", res)
	}
}

func TestRateLimitAndCapacity(t *testing.T) {
	h, _ := newAPI(t, func(c *Config) { c.PerClientPerMinute = 3; c.MaxJobs = 100 })
	for i := 0; i < 3; i++ {
		if code, _ := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", map[string]string{"signer": "PNOEE-40404040009"}); code != 202 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code, _ := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", map[string]string{"signer": "PNOEE-40404040009"}); code != 429 {
		t.Fatalf("over rate: %d", code)
	}
	if code, _ := call(h, "POST", "/api/v1/sign/certificate", "b:secret-b", map[string]string{"signer": "PNOEE-40404040009"}); code != 202 {
		t.Fatalf("other client limited: %d", code)
	}
	h2, _ := newAPI(t, func(c *Config) { c.MaxJobs = 1 })
	call(h2, "POST", "/api/v1/sign/certificate", "a:secret-a", map[string]string{"signer": "PNOEE-40404040009"})
	if code, _ := call(h2, "POST", "/api/v1/sign/certificate", "b:secret-b", map[string]string{"signer": "PNOEE-40404040009"}); code != 503 {
		t.Fatalf("over capacity: %d", code)
	}
}

func TestJobsExpire(t *testing.T) {
	now := time.Now()
	h, _ := newAPI(t, func(c *Config) { c.Now = func() time.Time { return now } })
	cert := certificate(t, h, "a:secret-a")
	now = now.Add(6 * time.Minute)
	if code, _ := call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert)); code != 404 {
		t.Fatalf("expired certificate used: %d", code)
	}
}

// Tests added for mutation survivors (gremlins, 2026-11-20).

func TestDefaults(t *testing.T) {
	h := New(Config{})
	defer h.Close()
	if h.cfg.PollTimeout != 30*time.Second || h.cfg.JobTTL != 5*time.Minute || h.cfg.MaxJobs != 1000 || h.cfg.PerClientPerMinute != 30 {
		t.Fatalf("defaults %+v", h.cfg)
	}
}

func TestDisplayText200AndPendingCode(t *testing.T) {
	h, srv := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	b := signBody(cert)
	b["display_text"] = strings.Repeat("õ", 200)
	srv.MaxWait = 2 * time.Second
	srv.FailPolls.Store(true) // keep the job pending
	code, out := call(h, "POST", "/api/v1/sign", "a:secret-a", b)
	if code != 202 {
		t.Fatalf("200 characters: %d %v", code, out)
	}
	_, st := call(h, "GET", "/api/v1/sign/"+out["id"].(string), "a:secret-a", nil)
	if st["status"] != "pending" || st["verification_code"] != out["verification_code"] {
		t.Fatalf("pending response %v", st)
	}
	// Retryable upstream errors do not fail the job; it completes after recovery.
	for start, end := srv.Polls.Load(), time.Now().Add(5*time.Second); srv.Polls.Load() < start+2; {
		if time.Now().After(end) {
			t.Fatal("job stopped polling after a retryable upstream error")
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.FailPolls.Store(false)
	if res := wait(t, h, "a:secret-a", out["id"].(string)); res["status"] != "complete" {
		t.Fatalf("after recovery %v", res)
	}
}

func TestRateWindowExactlyOneMinute(t *testing.T) {
	now := time.Now()
	h, _ := newAPI(t, func(c *Config) { c.PerClientPerMinute = 1; c.Now = func() time.Time { return now } })
	body := map[string]string{"signer": "PNOEE-40404040009"}
	if code, _ := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", body); code != 202 {
		t.Fatal(code)
	}
	now = now.Add(time.Minute)
	if code, _ := call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", body); code != 202 {
		t.Fatalf("after one minute: %d", code)
	}
}

func TestFailingUpstreamIsNotHammered(t *testing.T) {
	h, srv := newAPI(t, nil)
	cert := certificate(t, h, "a:secret-a")
	srv.FailPolls.Store(true)
	before := srv.Polls.Load()
	call(h, "POST", "/api/v1/sign", "a:secret-a", signBody(cert))
	time.Sleep(time.Second)
	if n := srv.Polls.Load() - before; n > 5 {
		t.Fatalf("%d polls in one second against a failing upstream", n)
	}
}

// Red-team #2 F7: Retry-After on 429/503; no control characters in the
// text shown on the phone.
func TestRetryAfterAndControlCharacters(t *testing.T) {
	h, _ := newAPI(t, func(c *Config) { c.PerClientPerMinute = 1 })
	body := map[string]string{"signer": "PNOEE-40404040009"}
	call(h, "POST", "/api/v1/sign/certificate", "a:secret-a", body)
	req := httptest.NewRequest("POST", "/api/v1/sign/certificate", strings.NewReader(`{"signer":"PNOEE-40404040009"}`))
	req.SetBasicAuth("a", "secret-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("429: %d %v", rec.Code, rec.Header())
	}
	h2, _ := newAPI(t, nil)
	cert := certificate(t, h2, "a:secret-a")
	for _, txt := range []string{"a\u0000b", "line\nbreak", "bidi\u202eoverride"} {
		b := signBody(cert)
		var s string
		json.Unmarshal([]byte(`"`+txt+`"`), &s)
		b["display_text"] = s
		if code, _ := call(h2, "POST", "/api/v1/sign", "a:secret-a", b); code != 400 {
			t.Errorf("%q: %d", txt, code)
		}
	}
}

// Privacy audit F2: expired jobs are swept without further API calls.
func TestExpiredJobsSweptInBackground(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	h, _ := newAPI(t, func(c *Config) {
		c.SweepEvery = 5 * time.Millisecond
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	certificate(t, h, "a:secret-a")
	mu.Lock()
	now = now.Add(6 * time.Minute)
	mu.Unlock()
	for i := 0; i < 200; i++ {
		h.mu.Lock()
		n := len(h.jobs)
		h.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expired job still held")
}
