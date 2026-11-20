package mobileid

import (
	"context"
	"encoding/asn1"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/mobileid/mobileidtest"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

type harness struct {
	srv *mobileidtest.Server
	m   *Method
}

func newHarness(t *testing.T) *harness {
	p := mobileidtest.NewPKI("contract")
	srv := mobileidtest.NewServer(p)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	c, err := NewClient(Config{BaseURL: hs.URL, RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO", HTTP: hs.Client(),
		Trust: smartid.NewTrustStore(p.Root, p.Inter), PolicyOIDs: []asn1.ObjectIdentifier{MIDPolicyOID}, Status: smartid.NoStatusCheck{}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMethod(MethodConfig{Client: c, DisplayText: map[string]string{"en": "Log in"}, IsDemo: true, LongPoll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, m: m}
}

func (h *harness) Method() authn.Method { return h.m }

func (h *harness) Requests() []authn.StartRequest {
	return []authn.StartRequest{{Flow: authn.FlowNotification, Lang: "et",
		Input: map[string]string{"country": "EE", "personal_code": mobileidtest.DefaultCode, "phone": mobileidtest.DefaultPhone}}}
}

func (h *harness) Drive(t *testing.T, p authn.Pending, _ authn.StartRequest, o authntest.Outcome) authn.Result {
	t.Helper()
	ok := &mobileidtest.Scenario{Result: "OK", Leaf: h.srv.PKI.NewLeaf(mobileidtest.LeafOptions{}), Polls: 1}
	switch o {
	case authntest.Refuse:
		ok = &mobileidtest.Scenario{Result: "USER_CANCELLED"}
	case authntest.Timeout:
		ok = &mobileidtest.Scenario{Result: "TIMEOUT"}
	case authntest.VerifyFail:
		ok.Mutate = func(m map[string]any) {
			s := m["signature"].(map[string]string)
			b, _ := base64.StdEncoding.DecodeString(s["value"])
			b[0] ^= 0xff
			s["value"] = base64.StdEncoding.EncodeToString(b)
		}
	}
	h.srv.Set(mobileidtest.DefaultPhone, ok)
	for range 10 {
		if r := p.Poll(context.Background()); r.Done {
			return r
		}
	}
	t.Fatal("no result after 10 polls")
	return authn.Result{}
}

// Story 4.2: the method passes the method-neutral contract suite.
func TestMethodContract(t *testing.T) { authntest.Run(t, newHarness(t)) }

func TestMethodStartValidation(t *testing.T) {
	h := newHarness(t)
	for name, in := range map[string]map[string]string{
		"bad phone":        {"phone": "+37129930366", "personal_code": mobileidtest.DefaultCode},
		"bad code":         {"phone": mobileidtest.DefaultPhone, "personal_code": "51307149561"},
		"country mismatch": {"phone": mobileidtest.DefaultPhone, "personal_code": mobileidtest.DefaultCode, "country": "LT"},
		"missing phone":    {"personal_code": mobileidtest.DefaultCode},
	} {
		_, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowNotification, Input: in})
		if authn.ReasonOf(err) != authn.ReasonInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if h.srv.Starts != 0 {
		t.Fatal("invalid input reached the upstream")
	}
	if _, err := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowQR}); authn.ReasonOf(err) != authn.ReasonInvalidInput {
		t.Fatal("QR flow accepted")
	}
}

// The page shows the verification code derived from the hash; the
// identity mismatch reason survives to the web layer.
func TestMethodUIAndIdentityMismatch(t *testing.T) {
	h := newHarness(t)
	p, err := h.m.Start(context.Background(), h.Requests()[0])
	if err != nil {
		t.Fatal(err)
	}
	ui, _ := p.UI(time.Now())
	if len(ui.VC) != 4 || ui.VC != p.(*pending).s.VC || ui.QRPayload != "" {
		t.Fatalf("ui %+v", ui)
	}
	h.srv.Set(mobileidtest.DefaultPhone, &mobileidtest.Scenario{Result: "OK", Leaf: h.srv.PKI.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-60001017869"})})
	r := p.Poll(context.Background())
	if !r.Done || authn.ReasonOf(r.Err) != authn.ReasonIdentityMismatch || r.Identity != nil {
		t.Fatalf("%+v", r)
	}
	if _, err := p.UI(time.Now()); err == nil {
		t.Fatal("UI after finish")
	}
	if r := p.Callback(context.Background(), nil, nil); r.Identity != nil {
		t.Fatal("callback produced identity")
	}
}
