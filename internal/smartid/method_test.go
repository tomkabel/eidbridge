package smartid

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

type harness struct {
	srv  *smartidtest.Server
	mock string
	m    *Method
}

func newHarness(t *testing.T) *harness {
	srv := smartidtest.NewServer()
	srv.MaxWait = 50 * time.Millisecond
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	c, err := NewClient(Config{BaseURL: hs.URL + "/smart-id-rp", RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
		Trust: NewTrustStore(srv.PKI.Root, srv.PKI.Inter), MinCertLevel: LevelQualified, Status: NoStatusCheck{}, PolicyOIDs: DemoPolicyOIDs})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMethod(MethodConfig{Client: c, Flows: []string{authn.FlowQR, authn.FlowSameDevice, authn.FlowNotification},
		DisplayText: map[string]string{"en": "Log in", "et": "Sisene"}, IsDemo: true, LongPoll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, mock: hs.URL + "/mock", m: m}
}

func (h *harness) Method() authn.Method { return h.m }

func (h *harness) Requests() []authn.StartRequest {
	return []authn.StartRequest{
		{Flow: authn.FlowQR, Lang: "et"},
		{Flow: authn.FlowSameDevice, Lang: "en", CallbackURL: "https://bridge.example/flow/cb?value=v1"},
		{Flow: authn.FlowNotification, Lang: "en", Input: map[string]string{"country": "EE", "personal_code": "40404040009"}},
	}
}

var docFor = map[authntest.Outcome]string{authntest.Success: "PNOEE-40404040009-MOCK-Q", authntest.VerifyFail: "PNOEE-40404040009-MOCK-Q",
	authntest.Refuse: "PNOEE-30403039917-MOCK-Q", authntest.Timeout: "PNOEE-30403039983-MOCK-Q"}

func (h *harness) Drive(t *testing.T, p authn.Pending, r authn.StartRequest, o authntest.Outcome) authn.Result {
	t.Helper()
	ctx := context.Background()
	h.srv.Mutate = nil
	if o == authntest.VerifyFail {
		h.srv.Mutate = func(st map[string]any) {
			if s, ok := st["signature"].(map[string]any); ok {
				v := s["value"].(string)
				s["value"] = "AAAA" + v[4:]
			}
		}
	}
	defer func() { h.srv.Mutate = nil }()
	pp := p.(*pending)
	switch r.Flow {
	case authn.FlowNotification:
		// The fake upstream resolves notification by target identity.
		code := strings.TrimSuffix(strings.TrimPrefix(docFor[o], "PNOEE-"), "-MOCK-Q")
		if o != authntest.Success && o != authntest.VerifyFail {
			// Restart toward the scripted identity.
			np, err := h.m.Start(ctx, authn.StartRequest{Flow: authn.FlowNotification, Input: map[string]string{"country": "EE", "personal_code": code}})
			if err != nil {
				t.Fatal(err)
			}
			p.Destroy()
			pp = np.(*pending)
		}
	default:
		ui, _ := pp.UI(time.Now())
		link := ui.QRPayload
		if link == "" {
			link = ui.AppLink
		}
		if err := MockSubmit(ctx, "http://127.0.0.1"+strings.TrimPrefix(h.mock, "http://127.0.0.1"), MockDeviceLink{DocumentNumber: docFor[o], DeviceLink: link, DisableCallbackGetRequest: true}, nil); err != nil {
			t.Fatal(err)
		}
	}
	var res authn.Result
	for i := 0; i < 100; i++ {
		res = pp.Poll(ctx)
		if res.Done {
			return res
		}
		if res.Waiting == "callback" {
			cb, err := MockCallbackURL(ctx, "http://127.0.0.1"+strings.TrimPrefix(h.mock, "http://127.0.0.1"), pp.s.SessionToken(), nil)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(cb)
			return pp.Callback(ctx, u.Query(), nil)
		}
	}
	return res
}

func TestSmartIDMethodContract(t *testing.T) {
	authntest.Run(t, newHarness(t))
}

func TestWeb2AppOKAndCallbackOrderEitherWay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, callbackFirst := range []bool{false, true} {
		p, err := h.m.Start(ctx, authn.StartRequest{Flow: authn.FlowSameDevice, CallbackURL: "https://b.example/cb?value=x"})
		if err != nil {
			t.Fatal(err)
		}
		pp := p.(*pending)
		ui, _ := p.UI(time.Now())
		MockSubmit(ctx, "http://127.0.0.1"+strings.TrimPrefix(h.mock, "http://127.0.0.1"), MockDeviceLink{DocumentNumber: "PNOEE-40404040009-MOCK-Q", DeviceLink: ui.AppLink, DisableCallbackGetRequest: true}, nil)
		cbURL, err := MockCallbackURL(ctx, "http://127.0.0.1"+strings.TrimPrefix(h.mock, "http://127.0.0.1"), pp.s.SessionToken(), nil)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(cbURL)
		var res authn.Result
		if callbackFirst {
			if r := p.Callback(ctx, u.Query(), nil); r.Done || r.Waiting != "device" {
				t.Fatalf("callback first: %+v", r)
			}
			if r := p.Callback(ctx, u.Query(), nil); r.Done {
				t.Fatal("duplicate callback changed state")
			}
			for !res.Done {
				res = p.Poll(ctx)
			}
		} else {
			for res.Waiting != "callback" {
				res = p.Poll(ctx)
				if res.Done {
					t.Fatalf("ok without callback finished: %+v", res)
				}
			}
			res = p.Callback(ctx, u.Query(), nil)
		}
		if !res.Done || res.Identity == nil {
			t.Fatalf("callbackFirst=%v: %+v", callbackFirst, res)
		}
		// Second use after completion never yields another identity.
		if r := p.Callback(ctx, u.Query(), nil); r.Identity != nil {
			t.Fatal("callback replay produced identity")
		}
		if r := p.Poll(ctx); r.Identity != nil {
			t.Fatal("poll after success produced identity")
		}
	}
}

func TestNotificationInvalidInputNoEgress(t *testing.T) {
	h := newHarness(t)
	for _, in := range []map[string]string{{"country": "EE", "personal_code": "40404040008"}, {"country": "FI", "personal_code": "x"}, {}} {
		if _, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowNotification, Input: in}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
			t.Fatalf("%v: %v", in, err)
		}
	}
	if h.srv.Creates.Load() != 0 {
		t.Fatal("outbound request for invalid input")
	}
}

func TestIdentityMismatchFailsWithoutCode(t *testing.T) {
	h := newHarness(t)
	// Upstream answers with another person's certificate.
	other := h.srv.Leaf("PNOEE-39901012239")
	h.srv.Mutate = func(st map[string]any) {
		if c, ok := st["cert"].(map[string]any); ok {
			c["value"] = b64std(other.Cert.Raw)
		}
	}
	p, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowNotification, Input: map[string]string{"country": "EE", "personal_code": "40404040009"}})
	if err != nil {
		t.Fatal(err)
	}
	var r authn.Result
	for !r.Done {
		r = p.Poll(context.Background())
	}
	if r.Identity != nil || authn.ReasonOf(r.Err) != authn.ReasonIdentityMismatch {
		t.Fatalf("got %+v", r)
	}
}

func TestLateResultDiscardedAndSecretsZeroed(t *testing.T) {
	h := newHarness(t)
	p, _ := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowQR})
	pp := p.(*pending)
	secret := pp.s.secret
	p.Destroy()
	for _, b := range secret {
		if b != 0 {
			t.Fatal("secret not zeroed")
		}
	}
	if r := p.Poll(context.Background()); r.Identity != nil || r.Err == nil {
		t.Fatalf("late poll: %+v", r)
	}
	if _, err := p.UI(time.Now()); err == nil {
		t.Fatal("UI after destroy")
	}
}

func TestMethodConfigValidation(t *testing.T) {
	h := newHarness(t)
	c := h.m.cfg.Client
	for _, cfg := range []MethodConfig{{}, {Client: c}, {Client: c, Flows: []string{"x"}, DisplayText: map[string]string{"en": "a"}},
		{Client: c, Flows: []string{authn.FlowQR}}, {Client: c, Flows: []string{authn.FlowQR}, DisplayText: map[string]string{"en": strings.Repeat("a", 61)}}} {
		if _, err := NewMethod(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	m, _ := NewMethod(MethodConfig{Client: c, Flows: []string{authn.FlowQR}, DisplayText: map[string]string{"en": "a"}})
	if _, err := m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowNotification}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
		t.Fatal("disabled flow started")
	}
}
