package eudi

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
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
	id, err := NewSelfSignedIdentity("bridge.example")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMethod(MethodConfig{Identity: id, Verifier: e.v, Flows: []string{authn.FlowQR, authn.FlowSameDevice}, IsDemo: true, LongPoll: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{e: e, m: m, clk: c}
}

func (h *harness) Method() authn.Method { return h.m }

const respURI = "https://bridge.example/demo/wallet/response/FLOWID"

func (h *harness) Requests() []authn.StartRequest {
	return []authn.StartRequest{{Flow: authn.FlowQR, Lang: "en", CallbackURL: respURI}, {Flow: authn.FlowSameDevice, Lang: "en", CallbackURL: respURI}}
}

// wallet resolves the pending's request the way a wallet would.
func wallet(t *testing.T, p authn.Pending) *walletsim.Request {
	t.Helper()
	ui, err := p.UI(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	link := ui.QRPayload + ui.AppLink
	ro, err := p.(*pending).RequestObject()
	if err != nil {
		t.Fatal(err)
	}
	r, err := walletsim.ParseRequest(link, ro)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func post(r *walletsim.Request, vp string, extra url.Values) url.Values {
	f := url.Values{"vp_token": {vp}, "state": {r.State}}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

func (h *harness) Drive(t *testing.T, p authn.Pending, _ authn.StartRequest, o authntest.Outcome) authn.Result {
	t.Helper()
	r := wallet(t, p)
	w := h.e.prov.Issue(walletsim.IssueOptions{})
	switch o {
	case authntest.Success:
		return p.Callback(context.Background(), post(r, walletsim.VPToken(w.Present(r.Nonce, r.ClientID, walletsim.PresentOptions{})), nil), nil)
	case authntest.Refuse:
		return p.Callback(context.Background(), url.Values{"error": {"access_denied"}, "state": {r.State}}, nil)
	case authntest.Timeout:
		h.clk.add(6 * time.Minute)
		defer h.clk.add(-6 * time.Minute)
		return p.Poll(context.Background())
	}
	return p.Callback(context.Background(), post(r, walletsim.VPToken(w.Present("other-nonce", r.ClientID, walletsim.PresentOptions{})), nil), nil)
}

// Story 6.1: the method passes the contract suite.
func TestMethodContract(t *testing.T) { authntest.Run(t, newHarness(t)) }

// The request object carries what the wallet needs and nothing else.
func TestRequestObject(t *testing.T) {
	h := newHarness(t)
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	r := wallet(t, p)
	if r.ResponseURI != respURI || r.ResponseMode != "direct_post" || len(r.Nonce) != 43 || len(r.State) != 43 || !strings.HasPrefix(r.ClientID, "x509_hash:") {
		t.Fatalf("%+v", r)
	}
	if strings.Join(r.Claims, ",") != strings.Join(requestedClaims, ",") {
		t.Fatalf("claims %v", r.Claims)
	}
	ui, _ := p.UI(time.Now())
	if !strings.HasPrefix(ui.QRPayload, "openid4vp://?") || !strings.Contains(ui.QRPayload, "request_uri=https%3A%2F%2Fbridge.example%2Fdemo%2Fwallet%2Frequest%2FFLOWID") {
		t.Fatalf("link %s", ui.QRPayload)
	}
	p2, _ := h.m.Start(context.Background(), h.Requests()[0])
	if wallet(t, p2).Nonce == r.Nonce {
		t.Fatal("nonce reused across flows")
	}
	for _, bad := range []string{"http://bridge.example/demo/wallet/response/x", "https://bridge.example/flow/callback"} {
		if _, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowQR, CallbackURL: bad}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Story 6.1 / red-team list: VP-token replay and holder-binding bypass.
func TestResponseNegatives(t *testing.T) {
	h := newHarness(t)
	w := h.e.prov.Issue(walletsim.IssueOptions{})
	stranger := h.e.prov.Issue(walletsim.IssueOptions{})
	p1, _ := h.m.Start(context.Background(), h.Requests()[0])
	r1 := wallet(t, p1)
	vp1 := walletsim.VPToken(w.Present(r1.Nonce, r1.ClientID, walletsim.PresentOptions{}))
	if res := p1.Callback(context.Background(), post(r1, vp1, nil), nil); res.Identity == nil {
		t.Fatalf("valid: %+v", res)
	}
	// Replay of a used presentation into another flow (other nonce/state).
	p2, _ := h.m.Start(context.Background(), h.Requests()[0])
	r2 := wallet(t, p2)
	if res := p2.Callback(context.Background(), post(r2, vp1, nil), nil); res.Identity != nil || authn.ReasonOf(res.Err) != authn.ReasonVerificationFailed {
		t.Fatalf("replay into another flow: %+v", res)
	}
	// Replay into the same flow after completion.
	if res := p1.Callback(context.Background(), post(r1, vp1, nil), nil); res.Identity != nil {
		t.Fatal("replay into the same flow")
	}
	// Holder-binding bypass: KB-JWT signed by another holder's key.
	p3, _ := h.m.Start(context.Background(), h.Requests()[0])
	r3 := wallet(t, p3)
	if res := p3.Callback(context.Background(), post(r3, walletsim.VPToken(w.Present(r3.Nonce, r3.ClientID, walletsim.PresentOptions{KBKey: stranger.HolderKey})), nil), nil); res.Identity != nil {
		t.Fatal("holder binding bypassed")
	}
	// Wrong state is ignored (the flow continues), then malformed vp_tokens end it.
	p4, _ := h.m.Start(context.Background(), h.Requests()[0])
	r4 := wallet(t, p4)
	if res := p4.Callback(context.Background(), url.Values{"vp_token": {vp1}, "state": {"forged"}}, nil); res.Done {
		t.Fatal("wrong state ended the flow")
	}
	for _, vp := range []string{"", "[]", `{"pid":[]}`, `{"pid":["a","b"]}`, `{"other":["x"]}`, `{"pid":["x"],"x":["y"]}`} {
		p, _ := h.m.Start(context.Background(), h.Requests()[0])
		r := wallet(t, p)
		if res := p.Callback(context.Background(), post(r, vp, nil), nil); res.Identity != nil || !res.Done {
			t.Errorf("vp_token %q: %+v", vp, res)
		}
	}
	p5, _ := h.m.Start(context.Background(), h.Requests()[0])
	r5 := wallet(t, p5)
	if res := p5.Callback(context.Background(), url.Values{"vp_token": {vp1, vp1}, "state": {r5.State}}, nil); res.Identity != nil {
		t.Fatal("repeated vp_token accepted")
	}
	_ = r4
}

// Claim ceiling: only requested PID claims reach the identity; a PID with
// no personal identifier cannot log in.
func TestIdentityMapping(t *testing.T) {
	id, err := identityFrom(&Presentation{Claims: map[string]any{"given_name": "A", "family_name": "B", "birthdate": "1990-05-17",
		"personal_administrative_number": "49005170005", "issuing_country": "ee", "nationalities": []any{"EE"}, "address": "x"}})
	if err != nil || id.Code != "49005170005" || id.Country != "EE" || id.Extra["birthdate"] != "1990-05-17" || len(id.Extra) != 1 || id.AMR[0] != "eudi_pid" {
		t.Fatalf("%+v %v", id, err)
	}
	if id, _ := identityFrom(&Presentation{Claims: map[string]any{"personal_administrative_number": "1", "issuing_country": "EE", "birthdate": "17.05.1990"}}); id.Extra != nil {
		t.Fatal("malformed birthdate passed through")
	}
	for _, c := range []map[string]any{{"issuing_country": "EE"}, {"personal_administrative_number": "1"}, {"personal_administrative_number": "1", "issuing_country": "EST"}} {
		if _, err := identityFrom(&Presentation{Claims: c}); authn.ReasonOf(err) != authn.ReasonAccountUnusable {
			t.Errorf("%v accepted", c)
		}
	}
}
