package smartid

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func fakeUpstream(t *testing.T) (*smartidtest.Server, *Client) {
	t.Helper()
	srv := smartidtest.NewServer()
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	c, err := NewClient(Config{BaseURL: hs.URL + "/smart-id-rp", RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
		Trust: NewTrustStore(srv.PKI.Root, srv.PKI.Inter), MinCertLevel: LevelQualified, Status: NoStatusCheck{},
		PolicyOIDs: DemoPolicyOIDs, HTTP: hs.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func complete(t *testing.T, c *Client, id string) *Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		st, err := c.Poll(ctx, id, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == "COMPLETE" {
			return st
		}
	}
}

func TestFixtureUpstreamQRAndWeb2App(t *testing.T) {
	srv, c := fakeUpstream(t)
	ctx := context.Background()
	s, err := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "x"})
	if err != nil {
		t.Fatal(err)
	}
	link, _ := s.QRLink(time.Now().Add(3 * time.Second))
	if !strings.Contains(link, "elapsedSeconds=3&") {
		t.Fatalf("elapsedSeconds missing: %s", link)
	}
	hs := strings.TrimSuffix(c.cfg.BaseURL, "/smart-id-rp")
	if err := MockSubmit(ctx, "http://127.0.0.1"+strings.TrimPrefix(hs, "http://127.0.0.1")+"/mock", MockDeviceLink{DocumentNumber: "PNOEE-40404040009-MOCK-Q", DeviceLink: link}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(s, complete(t, c, s.ID), nil); err != nil {
		t.Fatal(err)
	}
	// A link with a forged authCode is refused by the fake upstream.
	s2, _ := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "x"})
	l2, _ := s2.QRLink(time.Now())
	if err := MockSubmit(ctx, "http://127.0.0.1"+strings.TrimPrefix(hs, "http://127.0.0.1")+"/mock", MockDeviceLink{DocumentNumber: "PNOEE-40404040009-MOCK-Q", DeviceLink: l2[:len(l2)-2] + "AA"}, nil); err == nil {
		t.Fatal("forged authCode accepted")
	}
	// Web2App
	s3, err := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowWeb2App, DisplayText60: "x", InitialCallbackURL: "https://b.example/cb?value=abc"})
	if err != nil {
		t.Fatal(err)
	}
	l3, _ := s3.Web2AppLink()
	if strings.Contains(l3, "elapsedSeconds") {
		t.Fatal("web2app link must not carry elapsedSeconds")
	}
	mock := "http://127.0.0.1" + strings.TrimPrefix(hs, "http://127.0.0.1") + "/mock"
	if err := MockSubmit(ctx, mock, MockDeviceLink{DocumentNumber: "PNOEE-40404040009-MOCK-Q", DeviceLink: l3, DisableCallbackGetRequest: true}, nil); err != nil {
		t.Fatal(err)
	}
	st := complete(t, c, s3.ID)
	cbURL, err := MockCallbackURL(ctx, mock, s3.SessionToken(), nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cbURL)
	if _, err := c.Verify(s3, st, &Callback{u.Query().Get("sessionSecretDigest"), u.Query().Get("userChallengeVerifier")}); err != nil {
		t.Fatal(err)
	}
	_ = srv
}

func TestFixtureUpstreamNotification(t *testing.T) {
	_, c := fakeUpstream(t)
	s, err := c.StartNotification(context.Background(), NotificationRequest{SemanticsID: "PNOEE-40404040009", DisplayText60: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.VC) != 4 {
		t.Fatalf("vc %q", s.VC)
	}
	id, err := c.Verify(s, complete(t, c, s.ID), nil)
	if err != nil || id.Code != "40404040009" {
		t.Fatalf("%v", err)
	}
	s2, _ := c.StartNotification(context.Background(), NotificationRequest{SemanticsID: "PNOEE-30403039917", DisplayText60: "x"})
	if _, err := c.Verify(s2, complete(t, c, s2.ID), nil); ReasonOf(err) != ReasonRefused {
		t.Fatalf("refused: %v", err)
	}
}

func TestInvalidIdentityRejectedLocallyWithoutRequest(t *testing.T) {
	srv, c := fakeUpstream(t)
	for _, id := range []string{"PNOEE-40404040008", "PNOEE-4040404000", "PASEE-40404040009", "PNOXX-40404040009", "PNOLV-040404-10004", "", "PNOEE-4040404000x"} {
		if _, err := c.StartNotification(context.Background(), NotificationRequest{SemanticsID: id, DisplayText60: "x"}); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
	if _, err := c.StartNotification(context.Background(), NotificationRequest{DocumentNumber: "bad doc", DisplayText60: "x"}); err == nil {
		t.Error("bad document accepted")
	}
	if n := srv.Creates.Load(); n != 0 {
		t.Fatalf("%d outbound creates for invalid input", n)
	}
}

func TestPersonalCodeChecksums(t *testing.T) {
	valid := [][2]string{{"EE", "40404040009"}, {"EE", "39901012239"}, {"LT", "61101019999"}, {"EE", "30403039917"},
		{"LV", "040404-10003"}, {"LV", "320000-00008"}, {"LV", "311299-19993"}}
	for _, v := range valid {
		if !ValidPersonalCode(v[0], v[1]) {
			t.Errorf("valid %v rejected", v)
		}
	}
	invalid := [][2]string{{"EE", "40404040008"}, {"EE", "70404040009"}, {"LV", "040404-10004"}, {"LV", "04040410003"}, {"FI", "010101-123N"}, {"EE", "4040404000a"}}
	for _, v := range invalid {
		if ValidPersonalCode(v[0], v[1]) {
			t.Errorf("invalid %v accepted", v)
		}
	}
}

func TestNotificationVCDerivation(t *testing.T) {
	ch := []byte("eidbridge-known-answer-challenge-32b")
	sum := sha256.Sum256(ch)
	want := (int(sum[30])<<8 | int(sum[31])) % 10000
	if got, _ := strconv.Atoi(NotificationVC(ch)); got != want || len(NotificationVC(ch)) != 4 {
		t.Fatalf("vc %s want %04d", NotificationVC(ch), want)
	}
}

func TestHTTPErrorMappingAndLimits(t *testing.T) {
	codes := map[int]struct {
		retry  bool
		reason string
	}{400: {false, ReasonUpstreamError}, 401: {false, ReasonUpstreamError}, 403: {false, ReasonUpstreamError},
		404: {false, ReasonExpired}, 429: {true, ReasonUpstreamError}, 480: {false, ReasonUpstreamError},
		500: {true, ReasonUpstreamError}, 580: {true, ReasonUpstreamError}}
	for code, want := range codes {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(code)
		}))
		c := mustClient(t, hs)
		_, err := c.Poll(context.Background(), DemoRPUUID, time.Second)
		he, ok := err.(*HTTPError)
		if !ok || he.Retryable != want.retry || ReasonOf(err) != want.reason {
			t.Errorf("%d: %v", code, err)
		}
		if code == 429 && he.RetryAfter != 7*time.Second {
			t.Errorf("429 Retry-After %v", he.RetryAfter)
		}
		hs.Close()
	}
	// Redirects are never followed; 3xx is not success.
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", 302) }))
	if _, err := mustClient(t, hs).Poll(context.Background(), DemoRPUUID, time.Second); err == nil {
		t.Error("redirect accepted")
	}
	hs.Close()
	// Oversized and empty bodies fail.
	hs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 70<<10)) }))
	if _, err := mustClient(t, hs).Poll(context.Background(), DemoRPUUID, time.Second); ReasonOf(err) != ReasonUpstreamError {
		t.Errorf("oversize: %v", err)
	}
	hs.Close()
	hs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if _, err := mustClient(t, hs).Poll(context.Background(), DemoRPUUID, time.Second); ReasonOf(err) != ReasonUnknownEndResult {
		t.Errorf("empty: %v", err)
	}
	hs.Close()
	// Network error is retryable; timeoutMs is clamped.
	c := mustClient(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("timeoutMs") != "120000" {
			t.Errorf("timeoutMs %s", r.URL.Query().Get("timeoutMs"))
		}
		w.Write([]byte(`{"state":"RUNNING"}`))
	})))
	if _, err := c.Poll(context.Background(), DemoRPUUID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(context.Background(), "not-a-uuid", time.Second); err == nil {
		t.Fatal("bad session id accepted")
	}
	dead := mustClient(t, httptest.NewServer(nil))
	dead.cfg.BaseURL = "http://127.0.0.1:1"
	if _, err := dead.Poll(context.Background(), DemoRPUUID, time.Second); err == nil || !err.(*HTTPError).Retryable {
		t.Fatalf("network error: %v", err)
	}
}

func mustClient(t *testing.T, hs *httptest.Server) *Client {
	t.Helper()
	p := smartidtest.NewPKI("x")
	c, err := NewClient(Config{BaseURL: hs.URL, RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
		Trust: NewTrustStore(p.Root), MinCertLevel: LevelQualified, Status: NoStatusCheck{}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewClientValidation(t *testing.T) {
	p := smartidtest.NewPKI("x")
	good := Config{BaseURL: "https://x.example", RPUUID: DemoRPUUID, RPName: "R", SchemeName: SchemeDemo,
		Trust: NewTrustStore(p.Root), MinCertLevel: LevelQualified, Status: NoStatusCheck{}}
	if _, err := NewClient(good); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Config){
		func(c *Config) { c.BaseURL = "http://x.example" },
		func(c *Config) { c.RPUUID = "x" },
		func(c *Config) { c.RPName = "" },
		func(c *Config) { c.SchemeName = "other" },
		func(c *Config) { c.Trust = nil },
		func(c *Config) { c.Trust = NewTrustStore(p.Inter) },
		func(c *Config) { c.MinCertLevel = "LOW" },
		func(c *Config) { c.Status = nil },
		func(c *Config) { c.HashAlgorithm = "MD5" },
	}
	for i, f := range bad {
		c := good
		f(&c)
		if _, err := NewClient(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestStartValidation(t *testing.T) {
	_, c := fakeUpstream(t)
	ctx := context.Background()
	for _, r := range []DeviceLinkRequest{
		{Flow: FlowQR, DisplayText60: "x", InitialCallbackURL: "https://x"},
		{Flow: FlowWeb2App, DisplayText60: "x", InitialCallbackURL: "http://x"},
		{Flow: FlowWeb2App, DisplayText60: "x", InitialCallbackURL: "https://x/#frag"},
		{Flow: FlowWeb2App, DisplayText60: "x", InitialCallbackURL: "https://x/" + strings.Repeat("a", 1800)},
		{Flow: "App2App", DisplayText60: "x"},
		{Flow: FlowQR, DisplayText60: ""},
		{Flow: FlowQR, DisplayText60: strings.Repeat("a", 61)},
		{Flow: FlowQR, DisplayText60: "x", Lang: "en"},
	} {
		if _, err := c.StartDeviceLink(ctx, r); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	s, _ := c.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: "x"})
	if _, err := s.Web2AppLink(); err == nil {
		t.Error("web2app link for QR")
	}
	s.Destroy()
	if _, err := s.QRLink(time.Now()); err != ErrDestroyed {
		t.Error("destroyed session produced a link")
	}
	if s.SecretDigestMatches("x") {
		t.Error("destroyed session matched digest")
	}
}

func TestMalformedCreateResponsesFail(t *testing.T) {
	for _, body := range []string{`{}`, `{"sessionID":"x"}`, `not json`,
		`{"sessionID":"` + DemoRPUUID + `","sessionToken":"short","sessionSecret":"AAAAAAAAAAAAAAAAAAAAAAAA","deviceLinkBase":"https://x"}`,
		`{"sessionID":"` + DemoRPUUID + `","sessionToken":"abcdefghijklmnopqrstuvwx","sessionSecret":"AAAA","deviceLinkBase":"https://x"}`,
		`{"sessionID":"` + DemoRPUUID + `","sessionToken":"abcdefghijklmnopqrstuvwx","sessionSecret":"AAAAAAAAAAAAAAAAAAAAAAAA","deviceLinkBase":"http://x"}`,
		`{"sessionID":"` + DemoRPUUID + `","sessionToken":"abcdefghijklmnopqrstuvwx","sessionSecret":"AAAAAAAAAAAAAAAAAAAAAAAA","deviceLinkBase":"https://x?q=1"}`,
	} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		if _, err := mustClient(t, hs).StartDeviceLink(context.Background(), DeviceLinkRequest{Flow: FlowQR, DisplayText60: "x"}); err == nil {
			t.Errorf("accepted %s", body)
		}
		hs.Close()
	}
}
