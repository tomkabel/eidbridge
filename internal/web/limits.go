package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
)

// Bucket parameters: Burst tokens, refilled at Rate per second.
type Bucket struct {
	Burst float64
	Rate  float64
}

// buckets is a bounded map of token buckets. At capacity, unseen keys are
// refused (503) and active buckets are preserved; only idle buckets whose
// debt has fully refilled are reclaimed (ADR-009 notification abuse rule).
type buckets struct {
	mu   sync.Mutex
	b    Bucket
	cap  int
	m    map[string]*bucket
	clk  clock.Clock
	idle time.Duration // ≥ Burst/Rate
}

type bucket struct {
	tokens float64
	last   time.Duration
}

func newBuckets(b Bucket, cap int, clk clock.Clock) *buckets {
	idle := time.Duration(b.Burst/b.Rate*float64(time.Second)) + time.Second
	return &buckets{b: b, cap: cap, m: map[string]*bucket{}, clk: clk, idle: idle}
}

// allow charges one token for key. It returns false when the bucket is
// empty or, for an unseen key, when the map is full.
func (s *buckets) allow(key string) (ok bool, full bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Mono()
	e := s.m[key]
	if e == nil {
		if len(s.m) >= s.cap {
			for k, v := range s.m {
				if now-v.last >= s.idle {
					delete(s.m, k)
				}
			}
			if len(s.m) >= s.cap {
				return false, true
			}
		}
		e = &bucket{tokens: s.b.Burst, last: now}
		s.m[key] = e
	}
	e.tokens += s.b.Rate * (now - e.last).Seconds()
	if e.tokens > s.b.Burst {
		e.tokens = s.b.Burst
	}
	e.last = now // retained from the last charge, even when denied
	if e.tokens < 1 {
		return false, false
	}
	e.tokens--
	return true, false
}

// clientIP resolves the rate-limit key: the IPv4 address or IPv6 /64 of the
// rightmost X-Forwarded-For hop not in trusted; with no trusted proxies the
// peer address is used and forwarding headers are ignored.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "invalid"
	}
	addr := peer.Unmap()
	if len(trusted) > 0 && inAny(addr, trusted) {
		var hops []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for _, h := range strings.Split(v, ",") {
				if h = strings.TrimSpace(h); h != "" {
					hops = append(hops, h)
				}
			}
		}
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(hops[i])
			if err != nil {
				break
			}
			addr = a.Unmap()
			if !inAny(addr, trusted) {
				break
			}
		}
	}
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}
	return addr.String()
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isPrivatePeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	return err == nil && (a.IsPrivate() || a.IsLoopback())
}
