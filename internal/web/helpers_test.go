package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/logx"
	"github.com/tomkabel/eidbridge/internal/oidc"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"github.com/tomkabel/eidbridge/internal/store"
)

const secret = "s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t"
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type wenv struct {
	t      *testing.T
	srv    *httptest.Server
	prov   *oidc.Provider
	web    *Server
	up     *smartidtest.Server
	upURL  string
	codes  *store.Codes
	logs   *syncBuf
	clk    clock.Clock
	issuer string
	fake   *authntest.Fake
}

type wopt struct {
	maxFlows, pollSlots, codeCap int
	flowTTL                      time.Duration
	perIP, perClient, perTarget  Bucket
	retry                        int
	fake                         bool // register the fake method next to smartid
	upstreamWait                 time.Duration
	codeTTL                      time.Duration
}

func newWeb(t *testing.T, o wopt) *wenv {
	t.Helper()
	if o.maxFlows == 0 {
		o.maxFlows = 100
	}
	if o.pollSlots == 0 {
		o.pollSlots = 50
	}
	if o.codeCap == 0 {
		o.codeCap = 200
	}
	if o.flowTTL == 0 {
		o.flowTTL = 90 * time.Second
	}
	if o.perIP.Burst == 0 {
		o.perIP = Bucket{Burst: 1000, Rate: 100}
	}
	if o.perClient.Burst == 0 {
		o.perClient = Bucket{Burst: 1000, Rate: 100}
	}
	if o.perTarget.Burst == 0 {
		o.perTarget = Bucket{Burst: 3, Rate: 0.01}
	}
	if o.retry == 0 {
		o.retry = 3
	}
	up := smartidtest.NewServer()
	up.MaxWait = 30 * time.Millisecond
	if o.upstreamWait != 0 {
		up.MaxWait = o.upstreamWait
	}
	uhs := httptest.NewServer(up)
	t.Cleanup(uhs.Close)
	logs := &syncBuf{}
	log := logx.New(logs, slog.LevelDebug)
	clk := clock.Real()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	issuer := srv.URL + "/demo"
	c, err := smartid.NewClient(smartid.Config{BaseURL: uhs.URL + "/smart-id-rp", RPUUID: smartid.DemoRPUUID, RPName: smartid.DemoRPName,
		SchemeName: smartid.SchemeDemo, Trust: smartid.NewTrustStore(up.PKI.Root, up.PKI.Inter), MinCertLevel: smartid.LevelQualified,
		Status: smartid.NoStatusCheck{}, PolicyOIDs: smartid.DemoPolicyOIDs})
	if err != nil {
		t.Fatal(err)
	}
	m, err := smartid.NewMethod(smartid.MethodConfig{Client: c, Flows: []string{authn.FlowQR, authn.FlowSameDevice, authn.FlowNotification},
		DisplayText: map[string]string{"en": "Log in"}, IsDemo: true, LongPoll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	methods := []authn.Method{m}
	e := &wenv{t: t, srv: srv, up: up, upURL: uhs.URL, logs: logs, clk: clk, issuer: issuer}
	if o.fake {
		e.fake = &authntest.Fake{MethodName: "fake", FlowList: []string{authn.FlowQR}, IsDemo: true, Delay: 50 * time.Millisecond}
		methods = append(methods, e.fake)
	}
	reg, _ := authn.NewRegistry(methods...)
	ks, err := oidc.LoadKeys(t.TempDir(), true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	codeTTL := 60 * time.Second
	if o.codeTTL > 0 {
		codeTTL = o.codeTTL
	}
	e.codes = store.NewCodes(store.CodesConfig{Cap: o.codeCap, CodeTTL: codeTTL, TombstoneTTL: 6 * time.Minute, Clock: clk})
	names := reg.Names()
	prov, err := oidc.New(oidc.Config{Issuer: issuer, Demo: true, Keys: ks, AccessTokenTTL: 5 * time.Minute, CodeTTL: codeTTL,
		ClockSkew: 30 * time.Second, Methods: names, Clock: clk, Codes: e.codes,
		Subjects: &oidc.Subjects{Keys: map[int][]byte{1: bytes.Repeat([]byte{7}, 32)}, Current: 1},
		Clients:  []oidc.Client{{ID: "rp", Secret: secret, AuthMethod: oidc.AuthBasic, RedirectURIs: []string{"https://rp.example/cb"}, SubMode: "pairwise"}}})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := New(Config{Provider: prov, Registry: reg, Clock: clk, Log: log, PublicOrigin: srv.URL, Demo: true, FlowTTL: o.flowTTL,
		MaxFlows: o.maxFlows, PollSlots: o.pollSlots, UpstreamRate: Bucket{Burst: 1000, Rate: 1000}, PerIP: o.perIP, PerClient: o.perClient,
		PerTarget: o.perTarget, BucketCap: 1000, RetryAttempts: o.retry, RetryBase: 10 * time.Millisecond, DefaultLocale: "en",
		TargetKey: bytes.Repeat([]byte{9}, 32), LongPollGap: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ws.Close)
	prov.SetFrontend(ws)
	mux := http.NewServeMux()
	prov.Register(mux)
	ws.Register(mux)
	srv.Config.Handler = AccessLog(log, mux)
	e.prov, e.web = prov, ws
	return e
}

// browser is one cookie jar.
type browser struct {
	e  *wenv
	c  *http.Client
	nr *http.Client
}

func (e *wenv) browser() *browser {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &browser{e: e,
		c: &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if !strings.HasPrefix(r.URL.String(), e.srv.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		}},
		nr: &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func authQuery(extra url.Values) url.Values {
	q := url.Values{"client_id": {"rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"}, "scope": {"openid profile"},
		"state": {"st"}, "nonce": {"nn"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

func readAll(r *http.Response) string { b, _ := io.ReadAll(r.Body); r.Body.Close(); return string(b) }

// begin runs /authorize and returns the flow ID and the choose page.
func (b *browser) begin(extra url.Values) (string, string, *http.Response) {
	b.e.t.Helper()
	resp, err := b.nr.Get(b.e.issuer + "/authorize?" + authQuery(extra).Encode())
	if err != nil {
		b.e.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		return "", readAll(resp), resp
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	id := loc[strings.LastIndex(loc, "/")+1:]
	page, err := b.c.Get(b.e.srv.URL + loc)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return id, readAll(page), resp
}

var ftRe = regexp.MustCompile(`name="ft" value="([^"]+)"`)

func formToken(t *testing.T, page string) string {
	m := ftRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no form token in page: %.300s", page)
	}
	return m[1]
}

func (b *browser) start(id, page, method, flow string, extra url.Values) *http.Response {
	b.e.t.Helper()
	f := url.Values{"ft": {formToken(b.e.t, page)}, "method": {method}, "flow": {flow}}
	for k, v := range extra {
		f[k] = v
	}
	resp, err := b.nr.PostForm(b.e.issuer+"/flow/"+id+"/start", f)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return resp
}

func (e *wenv) flow(id string) *flow { return e.web.flows.get(id) }

func (e *wenv) waitState(id string, want ...string) string {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		f := e.flow(id)
		if f == nil {
			return "gone"
		}
		f.mu.Lock()
		st := f.state
		f.mu.Unlock()
		for _, w := range want {
			if st == w {
				return st
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("flow %s did not reach %v", id, want)
	return ""
}

// scan submits the current QR link to the fake upstream for document.
func (e *wenv) scan(id, document string) {
	e.t.Helper()
	f := e.flow(id)
	f.mu.Lock()
	ui, err := f.pending.UI(time.Now())
	f.mu.Unlock()
	if err != nil {
		e.t.Fatal(err)
	}
	link := ui.QRPayload
	if link == "" {
		link = ui.AppLink
	}
	if err := smartid.MockSubmit(context.Background(), "http://127.0.0.1"+strings.TrimPrefix(e.upURL, "http://127.0.0.1")+"/mock",
		smartid.MockDeviceLink{DocumentNumber: document, DeviceLink: link, DisableCallbackGetRequest: true}, nil); err != nil {
		e.t.Fatal(err)
	}
}

// login runs a complete QR login and returns the client redirect URL.
func (b *browser) login() *url.URL {
	b.e.t.Helper()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	b.e.scan(id, "PNOEE-40404040009-MOCK-Q")
	b.e.waitState(id, StateVerified)
	resp, err := b.nr.Get(b.e.issuer + "/flow/" + id + "/continue")
	if err != nil {
		b.e.t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	return u
}

func (e *wenv) exchange(code string) (int, string) {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp.example/cb"}, "code_verifier": {verifier}}
	req, _ := http.NewRequest(http.MethodPost, e.issuer+"/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("rp", secret)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, readAll(resp)
}

func (e *wenv) stateOf(id string) string {
	f := e.flow(id)
	if f == nil {
		return "gone"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (e *wenv) reasonOf(id string) string {
	f := e.flow(id)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reason
}
