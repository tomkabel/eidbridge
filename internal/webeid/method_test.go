package webeid

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
)

type clk struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clk) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clk) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type harness struct {
	e   *venv
	m   *Method
	clk *clk
}

func newHarness(t *testing.T) *harness {
	e := newVEnv(t)
	c := &clk{t: time.Now()}
	e.v.Now = c.now
	m, err := NewMethod(MethodConfig{Validator: e.v, IsDemo: true, LongPoll: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{e: e, m: m, clk: c}
}

func (h *harness) Method() authn.Method { return h.m }

func (h *harness) Requests() []authn.StartRequest {
	return []authn.StartRequest{{Flow: authn.FlowBrowser, Lang: "en", Origin: origin + "/"}}
}

func (h *harness) Drive(t *testing.T, p authn.Pending, _ authn.StartRequest, o authntest.Outcome) authn.Result {
	t.Helper()
	ui, _ := p.UI(time.Now())
	leaf := h.e.pki.NewLeaf(webeidtest.LeafOptions{})
	switch o {
	case authntest.Success:
		return p.Callback(context.Background(), nil, leaf.Token("ES384", origin, ui.Challenge))
	case authntest.Refuse:
		return p.Callback(context.Background(), nil, []byte(`{"code":"ERR_WEBEID_USER_CANCELLED"}`))
	case authntest.Timeout:
		h.clk.add(6 * time.Minute)
		defer h.clk.add(-6 * time.Minute)
		return p.Poll(context.Background())
	}
	return p.Callback(context.Background(), nil, leaf.Token("ES384", "https://evil.example", ui.Challenge))
}

// Story 5.1 AC: authntest.Run passes.
func TestMethodContract(t *testing.T) { authntest.Run(t, newHarness(t)) }

// Story 5.1 test vector: a replayed nonce (a second token for the same
// flow, or a token made for another flow's nonce) is refused.
func TestReplayedNonce(t *testing.T) {
	h := newHarness(t)
	leaf := h.e.pki.NewLeaf(webeidtest.LeafOptions{})
	p1, _ := h.m.Start(context.Background(), h.Requests()[0])
	ui1, _ := p1.UI(time.Now())
	tok := leaf.Token("ES384", origin, ui1.Challenge)
	if r := p1.Callback(context.Background(), nil, tok); r.Identity == nil {
		t.Fatalf("first use: %+v", r)
	}
	if r := p1.Callback(context.Background(), nil, tok); r.Identity != nil || !r.Done {
		t.Fatal("token replayed into the same flow")
	}
	p2, _ := h.m.Start(context.Background(), h.Requests()[0])
	if r := p2.Callback(context.Background(), nil, tok); r.Identity != nil || authn.ReasonOf(r.Err) != authn.ReasonVerificationFailed {
		t.Fatalf("token replayed into another flow: %+v", r)
	}
	ui2, _ := p2.UI(time.Now())
	if ui2.Challenge != "" || ui1.Challenge == "" {
		t.Fatal("nonce not cleared after use")
	}
}

// A failed token consumes the nonce; a correct token afterwards is refused.
func TestFailedTokenConsumesNonce(t *testing.T) {
	h := newHarness(t)
	leaf := h.e.pki.NewLeaf(webeidtest.LeafOptions{})
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	ui, _ := p.UI(time.Now())
	p.Callback(context.Background(), nil, []byte(`{"format":"web-eid:1.0"}`))
	if r := p.Callback(context.Background(), nil, leaf.Token("ES384", origin, ui.Challenge)); r.Identity != nil {
		t.Fatal("nonce reusable after a failed token")
	}
}

func TestNonceProperties(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for range 50 {
		p, _ := h.m.Start(context.Background(), h.Requests()[0])
		ui, _ := p.UI(time.Now())
		if len(ui.Challenge) != 44 || seen[ui.Challenge] {
			t.Fatalf("nonce %q", ui.Challenge)
		}
		seen[ui.Challenge] = true
	}
	if _, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowBrowser, Origin: "http://login.example.com"}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
		t.Fatal("http origin accepted")
	}
	if _, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowQR, Origin: origin}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
		t.Fatal("QR flow accepted")
	}
}

func TestBrowserErrors(t *testing.T) {
	h := newHarness(t)
	for body, want := range map[string]string{`{"code":"ERR_WEBEID_USER_CANCELLED"}`: authn.ReasonRefused,
		`{"code":"ERR_WEBEID_USER_TIMEOUT"}`: authn.ReasonExpired, `{"code":"ERR_WEBEID_EXTENSION_UNAVAILABLE"}`: authn.ReasonUpstreamError,
		`{"code":"x","format":"web-eid:1.0"}`: authn.ReasonVerificationFailed, strings.Repeat("x", 300): authn.ReasonVerificationFailed} {
		p, _ := h.m.Start(context.Background(), h.Requests()[0])
		if r := p.Callback(context.Background(), nil, []byte(body)); authn.ReasonOf(r.Err) != want || r.Identity != nil {
			t.Errorf("%.40s: %+v", body, r)
		}
	}
}

// Poll waits for the browser and wakes as soon as a token is validated.
func TestPollWakesOnCallback(t *testing.T) {
	h := newHarness(t)
	h.m.cfg.LongPoll = 5 * time.Second
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	ui, _ := p.UI(time.Now())
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.Callback(context.Background(), nil, h.e.pki.NewLeaf(webeidtest.LeafOptions{}).Token("ES384", origin, ui.Challenge))
	}()
	start := time.Now()
	r := p.Poll(context.Background())
	if !r.Done || r.Identity == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}
}
