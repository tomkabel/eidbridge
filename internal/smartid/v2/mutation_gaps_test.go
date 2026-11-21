package v2

// Tests added for gremlins survivors (2026-11-21).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func baseCfg(e *env, base string) Config {
	return Config{BaseURL: base, RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO", HTTP: http.DefaultClient,
		Trust: smartid.NewTrustStore(e.srv.PKI.Root), MinCertLevel: "QUALIFIED", Status: &statusRec{}}
}

func TestNewClientBounds(t *testing.T) {
	e := newEnv(t)
	for base, ok := range map[string]bool{"http://localhost:1/x": true, "http://127.0.0.1:1/x": true, "http://[::1]:1/x": true,
		"http://example.com/x": false, "http://10.0.0.1/x": false, "https://example.com/x": true} {
		if _, err := NewClient(baseCfg(e, base)); (err == nil) != ok {
			t.Errorf("%s: %v", base, err)
		}
	}
	c := baseCfg(e, "https://example.com")
	c.RPName = strings.Repeat("A", 32)
	if _, err := NewClient(c); err != nil {
		t.Errorf("32-byte RP name: %v", err)
	}
	c.RPName += "A"
	if _, err := NewClient(c); err == nil {
		t.Error("33-byte RP name accepted")
	}
}

func TestDisplayText60(t *testing.T) {
	e := newEnv(t)
	if _, err := e.c.Start(context.Background(), "PNOEE-40404040009", strings.Repeat("õ", 60)); err != nil {
		t.Fatalf("60 characters: %v", err)
	}
	if _, err := e.c.Start(context.Background(), "PNOEE-40404040009", strings.Repeat("õ", 61)); err == nil {
		t.Fatal("61 characters accepted")
	}
}

func TestUnknownStateRefused(t *testing.T) {
	e := newEnv(t)
	e.srv.Mutate = func(m map[string]any) { m["state"] = "PAUSED" }
	s, _ := e.c.Start(context.Background(), "PNOEE-40404040009", "Log in")
	if _, err := e.c.Poll(context.Background(), s.ID, time.Second); err == nil {
		t.Fatal("unknown session state accepted")
	}
}

func TestTwoCertificateChain(t *testing.T) {
	e := newEnv(t)
	e.srv.SetLeaf("PNOEE-40404040009", e.srv.PKI.NewLeaf(smartidtest.LeafOptions{SerialNumber: "PNOEE-40404040009", ByRoot: true}))
	if _, err := e.login(t, "PNOEE-40404040009"); err != nil {
		t.Fatalf("leaf issued by the root: %v", err)
	}
}

func TestMaxBodyBoundary(t *testing.T) {
	e := newEnv(t)
	body := `{"state":"RUNNING"}`
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer hs.Close()
	cfg := baseCfg(e, hs.URL)
	cfg.MaxBody = int64(len(body))
	c, _ := NewClient(cfg)
	if _, err := c.Poll(context.Background(), "00000000-0000-4000-8000-000000000000", 0); err != nil {
		t.Fatalf("body exactly MaxBody: %v", err)
	}
	cfg.MaxBody--
	c, _ = NewClient(cfg)
	if _, err := c.Poll(context.Background(), "00000000-0000-4000-8000-000000000000", 0); err == nil {
		t.Fatal("body over MaxBody accepted")
	}
}

func TestDeliveredResultNotRepeated(t *testing.T) {
	h := &harness{e: newEnv(t)}
	m := h.Method()
	p, err := m.Start(context.Background(), h.Requests()[0])
	if err != nil {
		t.Fatal(err)
	}
	var r = p.Poll(context.Background())
	for i := 0; i < 50 && !r.Done; i++ {
		r = p.Poll(context.Background())
	}
	if r.Identity == nil {
		t.Fatalf("first result %+v", r)
	}
	if again := p.Poll(context.Background()); again.Identity != nil || again.Err == nil {
		t.Fatalf("identity delivered twice: %+v", again)
	}
	p.Destroy()
	if again := p.Poll(context.Background()); again.Identity != nil {
		t.Fatal("identity after Destroy")
	}
}

func TestDestroyBeforeResult(t *testing.T) {
	h := &harness{e: newEnv(t)}
	p, err := h.Method().Start(context.Background(), h.Requests()[0])
	if err != nil {
		t.Fatal(err)
	}
	p.Destroy()
	if r := p.Poll(context.Background()); r.Identity != nil || !r.Done {
		t.Fatalf("result after Destroy: %+v", r)
	}
}
