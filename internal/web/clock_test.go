package web

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/oidc"
)

func newClockFake() *clock.Fake { return clock.NewFake(time.Now()) }

// upBreak makes the fake upstream fail every poll with HTTP 500.
func (e *wenv) upBreak() { e.up.FailPolls.Store(true) }
func (e *wenv) upFix()   { e.up.FailPolls.Store(false) }

func TestClientIPTrustedProxies(t *testing.T) {
	tp := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.9, 10.0.0.7")
	if got := clientIP(r, tp); got != "203.0.113.9" {
		t.Fatalf("rightmost untrusted hop: %s", got)
	}
	r.RemoteAddr = "[2001:db8::1]:1"
	if got := clientIP(r, tp); got != "2001:db8::/64" {
		t.Fatalf("ipv6 /64: %s", got)
	}
	r.RemoteAddr = "198.51.100.7:1"
	if got := clientIP(r, tp); got != "198.51.100.7" {
		t.Fatalf("untrusted peer must not be overridden: %s", got)
	}
}

func TestMain(m *testing.M) {
	oidc.DemoRSABits = 2048
	os.Exit(m.Run())
}

// Story 3.3 AC 1: every key in en.json exists in all other catalogs and
// no catalog has keys en.json lacks.
func TestLocaleCatalogParity(t *testing.T) {
	en := catalogs["en"]
	for _, l := range Locales {
		for k := range en {
			if _, ok := catalogs[l][k]; !ok {
				t.Errorf("%s.json lacks %q", l, k)
			}
		}
		for k := range catalogs[l] {
			if _, ok := en[k]; !ok {
				t.Errorf("%s.json has extra key %q", l, k)
			}
		}
	}
}
