package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func TestFullQRLoginAndCodeExchange(t *testing.T) {
	e := newWeb(t, wopt{})
	u := e.browser().login()
	if u.Query().Get("code") == "" || u.Query().Get("iss") != e.issuer || u.Query().Get("state") != "st" {
		t.Fatalf("redirect %s", u)
	}
	st, body := e.exchange(u.Query().Get("code"))
	if st != 200 || !strings.Contains(body, "id_token") {
		t.Fatalf("%d %s", st, body)
	}
}

// FR-010: after a completed login and after TTL expiry, the store holds no
// entry for that flow.
func TestStoreZeroEntriesAfterLoginAndTTL(t *testing.T) {
	e := newWeb(t, wopt{flowTTL: 31 * time.Second})
	b := e.browser()
	u := b.login()
	if n := e.web.FlowCount(); n != 0 {
		t.Fatalf("%d flow entries after completed login", n)
	}
	if st, _ := e.exchange(u.Query().Get("code")); st != 200 {
		t.Fatal("exchange")
	}
	id, _, _ := b.begin(nil)
	f := e.flow(id)
	f.mu.Lock()
	f.startBy, f.deadline = 0, 0 // force both deadlines into the past
	f.mu.Unlock()
	e.web.Sweep()
	e.web.Sweep()
	if e.web.FlowCount() != 0 {
		t.Fatal("expired flow still stored")
	}
	r, l, _ := e.codes.Counts()
	if r != 0 || l != 0 {
		t.Fatalf("reservations %d codes %d remain", r, l)
	}
}

func TestFlowCookieAttributes(t *testing.T) {
	e := newWeb(t, wopt{})
	_, _, resp := e.browser().begin(nil)
	var c *http.Cookie
	for _, x := range resp.Cookies() {
		if strings.HasPrefix(x.Name, cookiePrefix) {
			c = x
		}
	}
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v", c)
	}
	if c.MaxAge != int((90*time.Second+30*time.Second)/time.Second) {
		t.Fatalf("Max-Age %d, want flow_ttl+30s", c.MaxAge)
	}
	if strings.Contains(resp.Header.Get("Set-Cookie"), "Domain") {
		t.Fatal("Domain attribute set")
	}
}

func TestAbsoluteFlowDeadlineAndEvictionRace(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, _, _ := b.begin(nil)
	f := e.flow(id)
	f.mu.Lock()
	d := f.deadline
	f.mu.Unlock()
	for i := 0; i < 3; i++ { // reloads never extend the deadline
		resp, _ := b.c.Get(e.issuer + "/flow/" + id)
		resp.Body.Close()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deadline != d {
		t.Fatal("reload extended the flow deadline")
	}
}

func TestResponseHeadersAndQRRelay(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	check := func(h http.Header, where string) {
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s headers: %v", where, h)
		}
		if h.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS on a login page", where)
		}
	}
	resp, _ := b.c.Get(e.issuer + "/flow/" + id)
	check(resp.Header, "choose")
	resp.Body.Close()
	if strings.Contains(page, "<script>") || strings.Contains(page, " style=") {
		t.Fatal("inline script or style")
	}
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	q1, _ := b.c.Get(e.issuer + "/flow/" + id + "/qr.png")
	check(q1.Header, "qr")
	if q1.Header.Get("Cache-Control") != "no-store" || q1.Header.Get("Content-Type") != "image/png" {
		t.Fatal("qr must be a no-store PNG")
	}
	q1.Body.Close()
	// The QR payload is regenerated per request: elapsedSeconds is current,
	// so no served QR is older than the request time.
	f := e.flow(id)
	f.mu.Lock()
	ui1, _ := f.pending.UI(time.Now())
	ui2, _ := f.pending.UI(time.Now().Add(3 * time.Second))
	f.mu.Unlock()
	if ui1.QRPayload == ui2.QRPayload || !strings.Contains(ui2.QRPayload, "elapsedSeconds=3") {
		t.Fatal("QR payload does not change with elapsed time")
	}
	// Template autoescaping: a hostile state cannot inject markup.
	b2 := e.browser()
	_, p2, _ := b2.begin(url.Values{"state": {"abc"}})
	if strings.Contains(p2, "<script") {
		t.Fatal("unexpected script")
	}
}

func TestFlowTypeChosenBeforeSessionCreation(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	if e.up.Creates.Load() != 0 {
		t.Fatal("upstream session created before the user chose a flow")
	}
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	f := e.flow(id)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.offered != authn.FlowQR || e.up.Creates.Load() != 1 {
		t.Fatalf("offered %q creates %d", f.offered, e.up.Creates.Load())
	}
}

func TestConcurrentQRPageLoadsCreateOneSession(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close() }()
	}
	wg.Wait()
	if n := e.up.Creates.Load(); n != 1 {
		t.Fatalf("%d upstream sessions", n)
	}
}

func TestReloadRendersStoredStateAndCancelNeedsBindingToken(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	for i := 0; i < 3; i++ {
		r, _ := b.c.Get(e.issuer + "/flow/" + id)
		r.Body.Close()
	}
	if e.up.Creates.Load() != 1 {
		t.Fatal("reload created a new upstream session")
	}
	// Cancel by GET is not a route; POST without form token restarts.
	r, _ := b.nr.PostForm(e.issuer+"/flow/"+id+"/cancel", url.Values{})
	r.Body.Close()
	if e.stateOf(id) != StatePending {
		t.Fatal("cancel without binding token changed state")
	}
	r, _ = b.nr.PostForm(e.issuer+"/flow/"+id+"/cancel", url.Values{"ft": {formToken(t, page)}})
	r.Body.Close()
	if e.waitState(id, StateCancelled) != StateCancelled {
		t.Fatal("cancel")
	}
}

func TestEveryFlowScopedEndpointRequiresCookie(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	stranger := e.browser()
	before := e.up.Creates.Load()
	for _, ep := range []struct{ m, p string }{{"GET", ""}, {"GET", "/qr.png"}, {"GET", "/status"}, {"POST", "/cancel"}, {"GET", "/continue"}, {"POST", "/start"}} {
		req, _ := http.NewRequest(ep.m, e.issuer+"/flow/"+id+ep.p, strings.NewReader("ft="+url.QueryEscape(formToken(t, page))+"&method=smartid&flow=qr"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := stranger.nr.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(resp)
		if resp.StatusCode < 400 || strings.Contains(body, "elapsedSeconds") {
			t.Errorf("%s %s without cookie: %d", ep.m, ep.p, resp.StatusCode)
		}
	}
	if e.stateOf(id) != StatePending || e.up.Creates.Load() != before {
		t.Fatal("cookieless request changed state or created upstream work")
	}
}

func TestOverflowReturns503WithRetryAfter(t *testing.T) {
	e := newWeb(t, wopt{maxFlows: 2, pollSlots: 2})
	b := e.browser()
	b.begin(nil)
	b.begin(nil)
	_, _, resp := e.browser().begin(nil)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("overflow: %d", resp.StatusCode)
	}
	if e.up.Creates.Load() != 0 {
		t.Fatal("overflow created upstream work")
	}
	// Per-client and per-IP buckets.
	e2 := newWeb(t, wopt{perClient: Bucket{Burst: 1, Rate: 0.001}})
	e2.browser().begin(nil)
	if _, _, r := e2.browser().begin(nil); r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("per-client: %d", r.StatusCode)
	}
	e3 := newWeb(t, wopt{perIP: Bucket{Burst: 1, Rate: 0.001}})
	e3.browser().begin(nil)
	if _, _, r := e3.browser().begin(nil); r.StatusCode != 503 {
		t.Fatalf("per-ip: %d", r.StatusCode)
	}
}

func TestStoreFullNeverEvicts(t *testing.T) {
	e := newWeb(t, wopt{maxFlows: 1, pollSlots: 1})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	if _, _, r := e.browser().begin(nil); r.StatusCode != 503 {
		t.Fatal("full store admitted a flow")
	}
	if e.flow(id) == nil || e.stateOf(id) != StatePending {
		t.Fatal("pending flow evicted")
	}
}

func TestCodeSlotReservedAtFlowCreation(t *testing.T) {
	e := newWeb(t, wopt{codeCap: 1})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	// TestTombstoneCapReturns503AtFlowCreation: no free code slot → 503.
	if _, _, r := e.browser().begin(nil); r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("code store full: %d", r.StatusCode)
	}
	e.scan(id, "PNOEE-40404040009-MOCK-Q")
	if e.waitState(id, StateVerified, StateFailed) != StateVerified {
		t.Fatal("reserved slot did not yield a code at capacity")
	}
}

func TestNoPollSlotReturns503AndFlowStaysCreated(t *testing.T) {
	e := newWeb(t, wopt{pollSlots: 1})
	b := e.browser()
	id1, p1, _ := b.begin(nil)
	b.start(id1, p1, "smartid", authn.FlowQR, nil).Body.Close()
	id2, p2, _ := e.browser().begin(nil)
	b2 := e.browser()
	_ = b2
	// second browser's flow
	bb := e.browser()
	id3, p3, _ := bb.begin(nil)
	_, _ = id2, p2
	r := bb.start(id3, p3, "smartid", authn.FlowQR, nil)
	r.Body.Close()
	if r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("no poll slot: %d", r.StatusCode)
	}
	if e.stateOf(id3) != StateCreated {
		t.Fatal("flow left created without a poll slot")
	}
}

func TestSinglePollerBoundsUpstreamConcurrency(t *testing.T) {
	e := newWeb(t, wopt{pollSlots: 3, upstreamWait: 200 * time.Millisecond})
	var ids []string
	for i := 0; i < 5; i++ {
		b := e.browser()
		id, page, _ := b.begin(nil)
		b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
		ids = append(ids, id)
	}
	time.Sleep(600 * time.Millisecond)
	if m := e.up.MaxInflight.Load(); m > 3 {
		t.Fatalf("%d concurrent upstream polls with 3 slots", m)
	}
	// The browser status endpoint never reaches upstream.
	before := e.up.Polls.Load()
	b := e.browser()
	id, page, _ := b.begin(nil)
	_ = page
	for i := 0; i < 5; i++ {
		r, _ := b.c.Get(e.issuer + "/flow/" + id + "/status")
		r.Body.Close()
	}
	if e.up.Creates.Load() != 3 {
		t.Fatalf("creates %d", e.up.Creates.Load())
	}
	_ = before
	// An abandoned (cancelled) flow stops polling.
	f := e.flow(ids[0])
	f.mu.Lock()
	e.web.finishLocked(f, StateCancelled, authn.ReasonCancelled, nil)
	f.mu.Unlock()
}

func TestCreatedFlowTerminatesOnInitFailOrAbandon(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	e.up.RPUUID = "11111111-1111-4111-8111-111111111111" // upstream rejects: init error
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	if e.waitState(id, StateFailed) != StateFailed {
		t.Fatal("init error must fail the flow")
	}
	if r, _, _ := e.codes.Counts(); r != 0 {
		t.Fatal("init failure kept its reservation")
	}
	id2, _, _ := b.begin(nil)
	f := e.flow(id2)
	f.mu.Lock()
	f.startBy = 0
	f.mu.Unlock()
	e.web.Sweep()
	if e.stateOf(id2) != StateExpired {
		t.Fatal("abandoned created flow did not expire")
	}
}

func TestPollRetryExhaustionFailsFlow(t *testing.T) {
	e := newWeb(t, wopt{retry: 2})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
	f := e.flow(id)
	// Break the upstream: every poll now fails with a retryable 5xx.
	e.upBreak()
	if e.waitState(id, StateFailed) != StateFailed || e.reasonOf(id) != authn.ReasonRetriesExhausted {
		t.Fatalf("reason %q", e.reasonOf(id))
	}
	// A later upstream result is never accepted.
	e.upFix()
	f.mu.Lock()
	st := f.state
	f.mu.Unlock()
	if st != StateFailed {
		t.Fatal("state changed after exhaustion")
	}
	b2 := e.browser()
	r, _ := b2.c.Get(e.issuer + "/flow/" + id + "/status")
	r.Body.Close()
	page2 := e.browser()
	_ = page2
	resp, _ := b.c.Get(e.issuer + "/flow/" + id)
	if body := readAll(resp); !strings.Contains(body, "cancel the request on your device") {
		t.Fatal("user not told to cancel on the device")
	}
}

func TestTerminalResponseReturnsErrorAndClearsCookie(t *testing.T) {
	for doc, want := range map[string]string{"PNOEE-30403039917-MOCK-Q": "access_denied", "PNOEE-30403039983-MOCK-Q": "access_denied", "PNOEE-30403039972-MOCK-Q": "server_error"} {
		e := newWeb(t, wopt{})
		b := e.browser()
		id, page, _ := b.begin(nil)
		b.start(id, page, "smartid", authn.FlowQR, nil).Body.Close()
		e.scan(id, doc)
		e.waitState(id, StateRefused, StateExpired, StateFailed)
		resp, _ := b.nr.Get(e.issuer + "/flow/" + id + "/continue")
		resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		if u.Query().Get("error") != want || u.Query().Get("iss") != e.issuer || u.Query().Get("state") != "st" {
			t.Fatalf("%s: %s", doc, u)
		}
		cleared := false
		for _, c := range resp.Cookies() {
			cleared = cleared || (c.Name == cookiePrefix+id && c.MaxAge < 0)
		}
		if !cleared {
			t.Fatalf("%s: cookie not cleared", doc)
		}
		if e.web.FlowCount() != 0 {
			t.Fatal("terminal flow entry kept after response")
		}
	}
}

// TestCookiesClearedOnEveryTerminalState covers cancelled as well.
func TestCookiesClearedOnEveryTerminalState(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, page, _ := b.begin(nil)
	r, _ := b.nr.PostForm(e.issuer+"/flow/"+id+"/cancel", url.Values{"ft": {formToken(t, page)}})
	r.Body.Close()
	resp, _ := b.nr.Get(e.issuer + "/flow/" + id + "/continue")
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookiePrefix+id && c.MaxAge < 0 {
			return
		}
	}
	t.Fatal("cancelled flow cookie not cleared")
}

func TestUnknownFlowHandleRedirectsAccessDenied(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, _, _ := b.begin(nil)
	e.web.flows.remove(e.flow(id)) // simulates a restart
	resp, _ := b.nr.Get(e.issuer + "/flow/" + id)
	resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 303 || u.Host != "rp.example" || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st" {
		t.Fatalf("%d %s", resp.StatusCode, u)
	}
	// A forged cookie naming an unregistered redirect never redirects there.
	b2 := e.browser()
	cv, _ := encodeCookie(cookieValue{B: "x", C: "rp", R: "https://evil.example/cb", S: "s"})
	su, _ := url.Parse(e.srv.URL)
	b2.c.Jar.SetCookies(su, []*http.Cookie{{Name: cookiePrefix + "abc", Value: cv, Path: "/", Secure: true}})
	r2, _ := b2.nr.Get(e.issuer + "/flow/abc")
	r2.Body.Close()
	if strings.Contains(r2.Header.Get("Location"), "evil") {
		t.Fatal("open redirect via cookie")
	}
}

func TestTwoTabsRunIndependentFlows(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id1, p1, _ := b.begin(nil)
	id2, p2, _ := b.begin(nil)
	b.start(id1, p1, "smartid", authn.FlowQR, nil).Body.Close()
	b.start(id2, p2, "smartid", authn.FlowQR, nil).Body.Close()
	e.scan(id2, "PNOEE-30403039917-MOCK-Q")
	e.scan(id1, "PNOEE-40404040009-MOCK-Q")
	if e.waitState(id1, StateVerified) != StateVerified || e.waitState(id2, StateRefused) != StateRefused {
		t.Fatal("tabs interfered")
	}
}

func TestFlowCookieCapFour(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	var ids []string
	for i := 0; i < 5; i++ {
		id, _, _ := b.begin(nil)
		ids = append(ids, id)
	}
	f := e.flow(ids[0])
	if f != nil {
		f.mu.Lock()
		st := f.state
		f.mu.Unlock()
		if st != StateCancelled {
			t.Fatalf("oldest flow state %s, want cancelled", st)
		}
	}
	for _, id := range ids[1:] {
		if e.flow(id) == nil || e.stateOf(id) != StateCreated {
			t.Fatal("newer flows disturbed")
		}
	}
	if r, _, _ := e.codes.Counts(); r != 4 {
		t.Fatalf("reservations %d, want 4 (cancelled flow released its slot)", r)
	}
}

func statusOf(t *testing.T, b *browser, issuer, id string) statusResp {
	r, err := b.c.Get(issuer + "/flow/" + id + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var s statusResp
	json.NewDecoder(r.Body).Decode(&s)
	r.Body.Close()
	return s
}

func (e *wenv) web2app(b *browser) (string, string) {
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowSameDevice, nil).Body.Close()
	e.scan(id, "PNOEE-40404040009-MOCK-Q")
	f := e.flow(id)
	f.mu.Lock()
	ui, _ := f.pending.UI(time.Now())
	f.mu.Unlock()
	u, _ := url.Parse(ui.AppLink)
	cb, err := smartid.MockCallbackURL(context.Background(), "http://127.0.0.1"+strings.TrimPrefix(e.upURL, "http://127.0.0.1")+"/mock", u.Query().Get("sessionToken"), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	// The fake app appends its parameters to the bridge callback URL.
	return id, cb
}

func TestWeb2AppCallbackBinding(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, cb := e.web2app(b)
	// Callback in another browser: restart page, flow unchanged.
	other := e.browser()
	r, _ := other.nr.Get(cb)
	r.Body.Close()
	if e.stateOf(id) != StatePending {
		t.Fatal("callback without cookie changed state")
	}
	// Correct browser: verified, 303 to continue → client.
	r, _ = b.nr.Get(cb)
	r.Body.Close()
	if r.StatusCode != 303 {
		t.Fatalf("callback %d", r.StatusCode)
	}
	if e.waitState(id, StateVerified) != StateVerified {
		t.Fatal("web2app not verified")
	}
	// Replay of the callback value: restart.
	r, _ = b.nr.Get(cb)
	body := readAll(r)
	if r.StatusCode != 400 || !strings.Contains(body, "Start the login again") {
		t.Fatalf("replayed callback: %d", r.StatusCode)
	}
}

func TestWeb2AppTamperedCallbackFails(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, cb := e.web2app(b)
	u, _ := url.Parse(cb)
	q := u.Query()
	q.Set("sessionSecretDigest", strings.Repeat("A", 43))
	u.RawQuery = q.Encode()
	r, _ := b.nr.Get(u.String())
	r.Body.Close()
	if e.waitState(id, StateFailed) != StateFailed {
		t.Fatal("tampered digest did not fail the flow")
	}
	e2 := newWeb(t, wopt{})
	b2 := e2.browser()
	id2, cb2 := e2.web2app(b2)
	u2, _ := url.Parse(cb2)
	q2 := u2.Query()
	q2.Set("value", "forged")
	u2.RawQuery = q2.Encode()
	r2, _ := b2.nr.Get(u2.String())
	r2.Body.Close()
	if e2.stateOf(id2) != StatePending {
		t.Fatal("forged callback value changed state")
	}
}

func TestOnlyCallbackResponseRedirects(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	// The original tab keeps the pre-callback cookie: emulate it by
	// snapshotting the cookie before the callback.
	id, cb := e.web2app(b)
	su, _ := url.Parse(e.srv.URL)
	old := b.c.Jar.Cookies(su)
	oldTab := e.browser()
	oldTab.c.Jar.SetCookies(su, cookiesWithPath(old))
	r, _ := b.nr.Get(cb)
	r.Body.Close()
	e.waitState(id, StateVerified)
	// TestRetiredBindingCannotDisruptCompletion
	s := statusOf(t, oldTab, e.issuer, id)
	if s.State != "other_tab" || s.Next != "" {
		t.Fatalf("old tab status %+v", s)
	}
	resp, _ := oldTab.nr.Get(e.issuer + "/flow/" + id + "/continue")
	body := readAll(resp)
	if resp.StatusCode == 303 || !strings.Contains(body, "other tab") {
		t.Fatalf("old tab obtained the redirect: %d", resp.StatusCode)
	}
	r2, _ := oldTab.nr.PostForm(e.issuer+"/flow/"+id+"/cancel", url.Values{"ft": {"x"}})
	r2.Body.Close()
	if e.stateOf(id) != StateVerified {
		t.Fatal("retired binding mutated completion")
	}
	resp, _ = b.nr.Get(e.issuer + "/flow/" + id + "/continue")
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatal("callback tab did not get the code redirect")
	}
}

func cookiesWithPath(cs []*http.Cookie) []*http.Cookie {
	for _, c := range cs {
		c.Path, c.Secure = "/", true
	}
	return cs
}

func TestWeb2AppOKAndCallbackOrderEitherWay(t *testing.T) {
	// Poll-first is TestWeb2AppCallbackBinding (the poller sees OK before the
	// callback arrives). Callback-first: stop the poller, deliver the
	// callback, then let polling resume.
	e := newWeb(t, wopt{})
	b := e.browser()
	id, cb := e.web2app(b)
	_ = id
	r, _ := b.nr.Get(cb)
	r.Body.Close()
	if e.waitState(id, StateVerified) != StateVerified {
		t.Fatal("not verified")
	}
}

func TestCallbackFirstRetainsVerifierUntilSignedResult(t *testing.T) {
	e := newWeb(t, wopt{upstreamWait: 300 * time.Millisecond})
	b := e.browser()
	id, page, _ := b.begin(nil)
	b.start(id, page, "smartid", authn.FlowSameDevice, nil).Body.Close()
	f := e.flow(id)
	f.mu.Lock()
	ui, _ := f.pending.UI(time.Now())
	f.mu.Unlock()
	// Deliver the callback before the upstream session resolves: compute a
	// valid digest via the fake app after scanning, but hold the result.
	e.scan(id, "PNOEE-40404040009-MOCK-Q")
	u, _ := url.Parse(ui.AppLink)
	cb, _ := smartid.MockCallbackURL(context.Background(), "http://127.0.0.1"+strings.TrimPrefix(e.upURL, "http://127.0.0.1")+"/mock", u.Query().Get("sessionToken"), nil)
	r, _ := b.nr.Get(cb)
	r.Body.Close()
	if e.waitState(id, StateVerified) != StateVerified {
		t.Fatal("verification after both events failed")
	}
}

func TestPerTargetIdentityBucket(t *testing.T) {
	e := newWeb(t, wopt{perTarget: Bucket{Burst: 2, Rate: 0.0001}})
	in := url.Values{"country": {"EE"}, "personal_code": {"40404040009"}}
	for i := 0; i < 3; i++ {
		b := e.browser() // many browsers, one target
		id, page, _ := b.begin(nil)
		r := b.start(id, page, "smartid", authn.FlowNotification, in)
		body := readAll(r)
		if i < 2 && e.stateOf(id) == StateCreated {
			t.Fatalf("attempt %d not started", i)
		}
		if i == 2 {
			if e.stateOf(id) != StateCreated || e.up.Creates.Load() != 2 || !strings.Contains(body, "Too many attempts") {
				t.Fatalf("third push to one target was sent (creates %d)", e.up.Creates.Load())
			}
		}
	}
	// Invalid input never reaches upstream and shows the generic message.
	b := e.browser()
	id, page, _ := b.begin(nil)
	before := e.up.Creates.Load()
	r := b.start(id, page, "smartid", authn.FlowNotification, url.Values{"country": {"EE"}, "personal_code": {"40404040008"}})
	body := readAll(r)
	if e.up.Creates.Load() != before || !strings.Contains(body, "Check the entered details") {
		t.Fatal("invalid code sent upstream or no generic message")
	}
}

func TestTargetBucketFullMapAndChurn(t *testing.T) {
	clk := newClockFake()
	bs := newBuckets(Bucket{Burst: 2, Rate: 1}, 2, clk)
	bs.allow("a")
	bs.allow("b")
	if ok, full := bs.allow("c"); ok || !full {
		t.Fatal("unseen target admitted at capacity")
	}
	bs.allow("a")
	bs.allow("a") // a is in debt
	clk.Advance(500 * time.Millisecond)
	if ok, full := bs.allow("c"); ok || !full {
		t.Fatal("active bucket reclaimed before full refill")
	}
	clk.Advance(5 * time.Second)
	if ok, _ := bs.allow("c"); !ok {
		t.Fatal("idle buckets not reclaimed after full refill")
	}
}

func TestReadinessIgnoresSaturation(t *testing.T) {
	e := newWeb(t, wopt{maxFlows: 1, pollSlots: 1})
	e.browser().begin(nil)
	if _, _, r := e.browser().begin(nil); r.StatusCode != 503 {
		t.Fatal("not saturated")
	}
	// TestReadinessIgnoresTransientCapacity
	r, _ := e.srv.Client().Get(e.srv.URL + "/readyz")
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("readiness failed on saturation")
	}
	e.web.Drain()
	r, _ = e.srv.Client().Get(e.srv.URL + "/readyz")
	r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal("readiness ok during drain")
	}
}

func TestSigtermDrainsUntilCodeTTL(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	u := b.login() // verified just now: its code lives 60 s
	done := make(chan struct{})
	go func() {
		e.web.DrainAndWait(200*time.Millisecond, e.codes.LiveCodeDeadline)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	// TestDrainKeepsTokenAndUserinfoServing: exchange still works.
	if st, _ := e.exchange(u.Query().Get("code")); st != 200 {
		t.Fatalf("token during drain: %d", st)
	}
	// New authorizations are refused.
	if _, _, r := e.browser().begin(nil); r.StatusCode != 503 {
		t.Fatalf("authorize during drain: %d", r.StatusCode)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not end at grace")
	}
}

func TestAccessLogOmitsCallbackQueryAndFlowIDs(t *testing.T) {
	e := newWeb(t, wopt{})
	b := e.browser()
	id, cb := e.web2app(b)
	r, _ := b.nr.Get(cb)
	r.Body.Close()
	e.waitState(id, StateVerified)
	logs := e.logs.String()
	u, _ := url.Parse(cb)
	for _, s := range []string{id, u.Query().Get("value"), u.Query().Get("userChallengeVerifier"), "127.0.0.1"} {
		if s != "" && strings.Contains(logs, s) {
			t.Fatalf("access log contains %q", s)
		}
	}
	if !strings.Contains(logs, `"route":"GET /demo/flow/callback"`) {
		t.Fatalf("route template missing: %.500s", logs)
	}
}

func TestProxyTrustWarningWhenAllPeersPrivate(t *testing.T) {
	e := newWeb(t, wopt{})
	for i := 0; i < 20; i++ {
		e.browser().begin(nil)
	}
	if !strings.Contains(e.logs.String(), "trusted_proxies is empty") {
		t.Fatal("no proxy warning")
	}
	if strings.Count(e.logs.String(), "trusted_proxies is empty") != 1 {
		t.Fatal("warning repeated")
	}
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.7")
	if clientIP(req, nil) != "10.0.0.5" {
		t.Fatal("forwarded header trusted without configuration")
	}
}
