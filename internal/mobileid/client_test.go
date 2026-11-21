package mobileid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/mobileid/mobileidtest"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func TestValidateInput(t *testing.T) {
	for _, tc := range []struct{ phone, code, country, reason string }{
		{"+37269930366", "51307149560", "EE", ""},
		{"+37060000666", "50001018865", "LT", ""},
		{"37269930366", "51307149560", "", authn.ReasonInvalidInput},      // no plus
		{"+37129930366", "51307149560", "", authn.ReasonInvalidInput},     // Latvia: no Mobile-ID in the API
		{"+3726993036612", "51307149560", "", authn.ReasonInvalidInput},   // too long
		{"+372 6993 0366", "51307149560", "", authn.ReasonInvalidInput},   // spaces
		{"+37269930366", "51307149561", "", authn.ReasonInvalidInput},     // checksum
		{"+37269930366", "5130714956", "", authn.ReasonInvalidInput},      // length
		{"+37269930366", "51307149560\n", "", authn.ReasonInvalidInput},   // control
		{"+37269930366\x00", "51307149560", "", authn.ReasonInvalidInput}, // NUL
	} {
		c, err := ValidateInput(tc.phone, tc.code)
		if tc.reason == "" && (err != nil || c != tc.country) || tc.reason != "" && authn.ReasonOf(err) != tc.reason {
			t.Errorf("%q %q: %q %v", tc.phone, tc.code, c, err)
		}
	}
}

func TestNewClientRejectsBadConfig(t *testing.T) {
	p := mobileidtest.NewPKI("cfg")
	good := Config{BaseURL: "https://mid.example", RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO", HTTP: http.DefaultClient,
		Trust: smartid.NewTrustStore(p.Root, p.Inter), Status: &statusRec{}}
	if _, err := NewClient(good); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"http":       func(c *Config) { c.BaseURL = "http://mid.example" },
		"upper uuid": func(c *Config) { c.RPUUID = "00000000-0000-0000-0000-00000000000A" },
		"no name":    func(c *Config) { c.RPName = "" },
		"no trust":   func(c *Config) { c.Trust = smartid.NewTrustStore() },
		"no status":  func(c *Config) { c.Status = nil },
	} {
		c := good
		mod(&c)
		if _, err := NewClient(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The start request carries a fresh 32-byte hash, SHA256, the RP identity
// and the language; the session's verification code derives from that hash.
func TestStartRequestShape(t *testing.T) {
	var got map[string]string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.Write([]byte(`{"sessionID":"de305d54-75b4-431b-adb2-eb6b9e546015"}`))
	}))
	defer hs.Close()
	c := testClient(t, hs)
	s, err := c.Start(context.Background(), StartRequest{Phone: "+37269930366", Code: "51307149560", Lang3: "EST", DisplayText: "Log in"})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := base64.StdEncoding.DecodeString(got["hash"])
	if got["hashType"] != "SHA256" || len(h) != 32 || got["language"] != "EST" || got["relyingPartyName"] != "DEMO" ||
		got["phoneNumber"] != "+37269930366" || got["nationalIdentityNumber"] != "51307149560" || got["displayTextFormat"] != "GSM-7" {
		t.Fatalf("%v", got)
	}
	if s.VC != VerificationCode(h) || string(s.Hash) != string(h) {
		t.Fatal("VC/hash do not match the sent hash")
	}
	s2, _ := c.Start(context.Background(), StartRequest{Phone: "+37269930366", Code: "51307149560", Lang3: "XXX"})
	if got["language"] != "ENG" || string(s2.Hash) == string(s.Hash) {
		t.Fatal("unknown language not defaulted or hash reused")
	}
	if _, err := c.Start(context.Background(), StartRequest{Phone: "+37269930366", Code: "51307149560", DisplayText: strings.Repeat("x", 41)}); err == nil {
		t.Fatal("long display text accepted")
	}
}

func testClient(t *testing.T, hs *httptest.Server) *Client {
	p := mobileidtest.NewPKI("c")
	c, err := NewClient(Config{BaseURL: hs.URL, RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO", HTTP: hs.Client(),
		Trust: smartid.NewTrustStore(p.Root, p.Inter), Status: &statusRec{}, MaxBody: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHTTPErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		method    string
		status    int
		body      string
		reason    string
		retryable bool
	}{
		{"POST", 400, `{"error":"x"}`, authn.ReasonInvalidInput, false},
		{"POST", 401, `{"error":"x"}`, authn.ReasonUpstreamError, false},
		{"POST", 500, `{}`, authn.ReasonUpstreamError, false},
		{"GET", 404, `{}`, authn.ReasonExpired, false},
		{"GET", 500, `{}`, authn.ReasonUpstreamError, true},
		{"GET", 200, strings.Repeat("x", 2<<10), authn.ReasonUpstreamError, false},
		{"GET", 200, `{"state":"FROZEN"}`, authn.ReasonUpstreamError, false},
		{"GET", 200, `{"state":"COMPLETE","result":"MAYBE"}`, authn.ReasonUnknownEndResult, false},
		{"GET", 200, `not json`, authn.ReasonUpstreamError, false},
		{"POST", 200, `{"sessionID":"not-a-uuid"}`, authn.ReasonUpstreamError, false},
	} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		c := testClient(t, hs)
		var err error
		if tc.method == "POST" {
			_, err = c.Start(context.Background(), StartRequest{Phone: "+37269930366", Code: "51307149560"})
		} else {
			_, err = c.Poll(context.Background(), "de305d54-75b4-431b-adb2-eb6b9e546015", time.Second)
		}
		var ae *authn.Error
		if authn.ReasonOf(err) != tc.reason || (asErr(err, &ae) && ae.Retryable != tc.retryable) {
			t.Errorf("%s %d %.20q: %v", tc.method, tc.status, tc.body, err)
		}
		hs.Close()
	}
}

func asErr(err error, out **authn.Error) bool {
	e, ok := err.(*authn.Error)
	*out = e
	return ok
}

func TestPollRejectsBadSessionID(t *testing.T) {
	c := testClient(t, httptest.NewServer(http.NotFoundHandler()))
	if _, err := c.Poll(context.Background(), "../../etc", time.Second); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestOutcomeMapsEveryResult(t *testing.T) {
	want := map[string]string{"TIMEOUT": authn.ReasonExpired, "NOT_MID_CLIENT": authn.ReasonAccountUnusable, "USER_CANCELLED": authn.ReasonRefused,
		"SIGNATURE_HASH_MISMATCH": authn.ReasonAccountUnusable, "PHONE_ABSENT": authn.ReasonAccountUnusable,
		"DELIVERY_ERROR": authn.ReasonUpstreamError, "SIM_ERROR": authn.ReasonAccountUnusable}
	for r, reason := range want {
		if got := authn.ReasonOf(Outcome(&Status{State: "COMPLETE", Result: r})); got != reason {
			t.Errorf("%s: %s", r, got)
		}
	}
	if Outcome(&Status{State: "COMPLETE", Result: "OK"}) != nil || Outcome(&Status{State: "RUNNING"}) == nil || Outcome(nil) == nil {
		t.Fatal("OK/RUNNING/nil")
	}
	if len(results) != len(want)+1 {
		t.Fatal("result table and test disagree")
	}
}

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(`{"state":"COMPLETE","result":"OK","signature":{"value":"AA==","algorithm":"SHA256WithECEncryption"},"cert":"AA=="}`))
	f.Add([]byte(`{"state":"RUNNING"}`))
	f.Add([]byte(`{"state":"COMPLETE","result":"USER_CANCELLED"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ParseStatus(b)
		if err == nil && st.State != "RUNNING" && st.State != "COMPLETE" {
			t.Fatal("bad state accepted")
		}
		if err == nil && st.State == "COMPLETE" {
			if _, ok := results[st.Result]; !ok {
				t.Fatal("unknown result accepted")
			}
		}
	})
}
