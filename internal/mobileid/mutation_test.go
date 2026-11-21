package mobileid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/mobileid/mobileidtest"
)

// Tests added to kill surviving mutants (gremlins, 2026-11-20).

// A leaf issued directly by a trusted root is a valid two-certificate chain.
func TestVerifyTwoCertificateChain(t *testing.T) {
	e := newEnv(t)
	e.srv.Set(mobileidtest.DefaultPhone, &mobileidtest.Scenario{Result: "OK", Leaf: e.pki.NewLeaf(mobileidtest.LeafOptions{ByRoot: true})})
	if _, err := e.login(t, mobileidtest.DefaultPhone, mobileidtest.DefaultCode); err != nil {
		t.Fatal(err)
	}
}

// Poll clamps timeoutMs to 1–60 s and waits up to timeoutMs + 1.5 s.
func TestPollTimeoutClampAndClientDeadline(t *testing.T) {
	var got string
	delay := time.Duration(0)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("timeoutMs")
		time.Sleep(delay)
		w.Write([]byte(`{"state":"RUNNING"}`))
	}))
	defer hs.Close()
	c := testClient(t, hs)
	id := "de305d54-75b4-431b-adb2-eb6b9e546015"
	for in, want := range map[time.Duration]string{10 * time.Millisecond: "1000", 20 * time.Second: "20000", 5 * time.Minute: "60000"} {
		if _, err := c.Poll(context.Background(), id, in); err != nil || got != want {
			t.Errorf("%v: timeoutMs=%s err=%v", in, got, err)
		}
	}
	delay = 2 * time.Second // inside 1 s + 1.5 s
	if _, err := c.Poll(context.Background(), id, 0); err != nil {
		t.Fatalf("client gave up before timeoutMs + 1.5 s: %v", err)
	}
}

// A body of exactly MaxBody bytes is accepted; one more byte is not.
func TestResponseSizeCapBoundary(t *testing.T) {
	body := `{"state":"RUNNING"}`
	body += strings.Repeat(" ", 1<<10-len(body))
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer hs.Close()
	c := testClient(t, hs)
	if _, err := c.Poll(context.Background(), "de305d54-75b4-431b-adb2-eb6b9e546015", time.Second); err != nil {
		t.Fatalf("exact cap refused: %v", err)
	}
	body += " "
	if _, err := c.Poll(context.Background(), "de305d54-75b4-431b-adb2-eb6b9e546015", time.Second); err == nil {
		t.Fatal("cap + 1 accepted")
	}
}

func TestMethodDefaultsAndLanguage(t *testing.T) {
	h := newHarness(t)
	m0, _ := NewMethod(MethodConfig{Client: h.m.cfg.Client})
	m3, _ := NewMethod(MethodConfig{Client: h.m.cfg.Client, LongPoll: 3 * time.Second})
	if m0.cfg.LongPoll != 10*time.Second || m3.cfg.LongPoll != 3*time.Second {
		t.Fatal("long poll default")
	}
	m, _ := NewMethod(MethodConfig{Client: h.m.cfg.Client, DisplayText: map[string]string{"en": "Log in", "et": "Sisene"}})
	in := map[string]string{"phone": mobileidtest.DefaultPhone, "personal_code": mobileidtest.DefaultCode}
	for lang, want := range map[string][2]string{"et": {"EST", "Sisene"}, "lv": {"ENG", "Log in"}, "ru": {"RUS", "Log in"}} {
		if _, err := m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowNotification, Lang: lang, Input: in}); err != nil {
			t.Fatal(err)
		}
		if h.srv.LastStart["language"] != want[0] || h.srv.LastStart["displayText"] != want[1] {
			t.Errorf("%s: %v", lang, h.srv.LastStart)
		}
	}
}

// After a success the flow erases its session, a second poll never repeats
// the identity and a late callback does not overwrite the result.
func TestPendingAfterSuccess(t *testing.T) {
	h := newHarness(t)
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	pp := p.(*pending)
	s := pp.s
	if r := p.Poll(context.Background()); r.Identity == nil {
		t.Fatalf("%+v", r)
	}
	if s.Hash != nil || s.Code != "" || s.Phone != "" {
		t.Fatal("session not erased after success")
	}
	if r := p.Poll(context.Background()); r.Identity != nil || !r.Done || authn.ReasonOf(r.Err) != authn.ReasonUpstreamError {
		t.Fatalf("second poll: %+v", r)
	}
	if r := p.Callback(context.Background(), nil, nil); authn.ReasonOf(r.Err) != authn.ReasonUpstreamError {
		t.Fatalf("late callback: %+v", r)
	}
	if pp.final.Identity == nil {
		t.Fatal("late callback overwrote the result")
	}
}

func TestDestroyBeforeResult(t *testing.T) {
	h := newHarness(t)
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	s := p.(*pending).s
	p.Destroy()
	if s.Hash != nil || s.Code != "" {
		t.Fatal("Destroy did not erase the session")
	}
	if r := p.Poll(context.Background()); authn.ReasonOf(r.Err) != authn.ReasonCancelled || r.Identity != nil {
		t.Fatalf("%+v", r)
	}
	p.Destroy() // idempotent
}

// A transport failure is retryable unless the caller's context ended.
func TestTransportErrorRetryable(t *testing.T) {
	hs := httptest.NewServer(http.NotFoundHandler())
	c := testClient(t, hs)
	hs.Close()
	_, err := c.Poll(context.Background(), "de305d54-75b4-431b-adb2-eb6b9e546015", time.Second)
	if ae, ok := err.(*authn.Error); !ok || !ae.Retryable {
		t.Fatalf("live context: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Poll(ctx, "de305d54-75b4-431b-adb2-eb6b9e546015", time.Second)
	if ae, ok := err.(*authn.Error); !ok || ae.Retryable {
		t.Fatalf("cancelled context: %v", err)
	}
}
