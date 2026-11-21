package web

// Tests added for gremlins survivors (2026-11-21).

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
)

func TestCookieSizeBoundary(t *testing.T) {
	var at string
	for n := 600; n < 800 && at == ""; n++ {
		s, _ := encodeCookie(cookieValue{B: strings.Repeat("b", n), T: 1})
		if len(s) == maxCookie {
			at = s
		}
	}
	if at == "" {
		t.Skip("no padding hits maxCookie exactly")
	}
	if _, ok := decodeCookie(at); !ok {
		t.Fatal("cookie of exactly maxCookie refused")
	}
	v, _ := decodeCookie(at)
	if _, ok := encodeCookie(v); !ok {
		t.Fatal("encode refused exactly maxCookie")
	}
	if _, ok := decodeCookie(at + "A"); ok {
		t.Fatal("cookie over maxCookie accepted")
	}
}

func TestFlowCookieMaxAge(t *testing.T) {
	for d, want := range map[time.Duration]int{10 * time.Second: 10, 500 * time.Millisecond: 1, 0: 1} {
		rec := httptest.NewRecorder()
		setFlowCookie(rec, "id", "v", d)
		if c := rec.Result().Cookies(); len(c) != 1 || c[0].MaxAge != want {
			t.Errorf("remaining %v: %+v", d, c)
		}
	}
}

func TestFlowCeilingFreedOnTermination(t *testing.T) {
	s := newFlows(2)
	if !s.admit(&flow{id: "a"}) || !s.admit(&flow{id: "b"}) || s.admit(&flow{id: "c"}) {
		t.Fatal("ceiling of 2")
	}
	s.terminated()
	if !s.admit(&flow{id: "c"}) {
		t.Fatal("terminated flow did not free its slot")
	}
}

func TestClientIPThroughTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for name, tc := range map[string]struct{ peer, xff, want string }{
		"single hop":        {"10.0.0.1:1", "203.0.113.7", "203.0.113.7"},
		"chain of proxies":  {"10.0.0.1:1", "203.0.113.7, 10.0.0.2", "203.0.113.7"},
		"spoofed left part": {"10.0.0.1:1", "198.51.100.1, 203.0.113.7", "203.0.113.7"},
		"untrusted peer":    {"192.0.2.9:1", "203.0.113.7", "192.0.2.9"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.xff)
		if got := clientIP(r, trusted); got != tc.want {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestTokenBucket(t *testing.T) {
	clk := clock.NewFake(time.Now())
	b := newBuckets(Bucket{Rate: 1, Burst: 2}, 1, clk)
	for i, want := range []bool{true, true, false} {
		if ok, _ := b.allow("a"); ok != want {
			t.Fatalf("request %d: %v", i, ok)
		}
	}
	clk.Advance(time.Second)
	if ok, _ := b.allow("a"); !ok {
		t.Fatal("refill after 1 s")
	}
	if ok, _ := b.allow("a"); ok {
		t.Fatal("more than one token after 1 s")
	}
	clk.Advance(time.Hour) // refill caps at Burst
	for i, want := range []bool{true, true, false} {
		if ok, _ := b.allow("a"); ok != want {
			t.Fatalf("after idle, request %d: %v", i, ok)
		}
	}
	// Map full: an idle key is evicted only after Burst/Rate + 1 s.
	if _, full := b.allow("b"); !full {
		t.Fatal("second key admitted into a full map")
	}
	clk.Advance(3 * time.Second)
	if ok, full := b.allow("b"); !ok || full {
		t.Fatal("idle key not evicted after Burst/Rate + 1 s")
	}
}

func TestBucketIdleEviction(t *testing.T) {
	clk := clock.NewFake(time.Now())
	b := newBuckets(Bucket{Rate: 2, Burst: 4}, 1, clk) // idle = Burst/Rate + 1 s = 3 s
	b.allow("a")
	clk.Advance(3*time.Second - time.Millisecond)
	if _, full := b.allow("b"); !full {
		t.Fatal("key evicted before the idle time")
	}
	clk.Advance(3 * time.Second)
	if ok, _ := b.allow("b"); !ok {
		t.Fatal("key not evicted after the idle time")
	}
}

// web.go:262 – a created flow must start within 60 s, inside its deadline.
func TestCreatedFlowStartWindow(t *testing.T) {
	e := newWeb(t, wopt{})
	id, _, _ := e.browser().begin(nil)
	f := e.flow(id)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startBy-f.created != 60*time.Second || f.deadline <= f.startBy {
		t.Fatalf("startBy %v deadline %v after creation", f.startBy-f.created, f.deadline-f.created)
	}
}
