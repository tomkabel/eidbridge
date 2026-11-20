package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/oidc"
	"github.com/tomkabel/eidbridge/internal/store"
)

// Flow states (architecture ADR-002 state machine).
const (
	StateCreated   = "created"
	StatePending   = "pending"
	StateVerified  = "verified"
	StateRefused   = "refused"
	StateExpired   = "expired"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

func terminal(s string) bool { return s != StateCreated && s != StatePending }

// flow is one bounded browser transaction. Every transition holds mu.
type flow struct {
	mu        sync.Mutex
	id        string
	binding   [32]byte   // SHA-256 of the current binding token
	retired   [][32]byte // hashes of rotated bindings (other-tab notice only)
	created   time.Duration
	deadline  time.Duration // created + flow_ttl + 30 s, never extended
	startBy   time.Duration // a created flow must start before this
	req       *oidc.AuthRequest
	res       *store.Reservation
	state     string
	reason    string
	method    string
	offered   string // authn flow name, fixed before the upstream session
	lang      string
	pending   authn.Pending
	cancel    context.CancelFunc
	callback  [32]byte // SHA-256 of the unpredictable callback value
	cbUsed    bool
	waiting   string
	redirect  string // client redirect for the terminal state
	slot      bool   // holds a poll slot
	clientIP  string
	createdAt time.Time
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashOf(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func eq(a, b [32]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

// flows is the bounded flow store. It never evicts a pending or verified
// flow; overflow is the caller's 503.
type flows struct {
	mu      sync.Mutex
	cap     int
	m       map[string]*flow
	byCB    map[[32]byte]string
	nonTerm int
}

func newFlows(cap int) *flows {
	return &flows{cap: cap, m: map[string]*flow{}, byCB: map[[32]byte]string{}}
}

func (s *flows) get(id string) *flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

// admit inserts f if the pending-flow ceiling allows it.
func (s *flows) admit(f *flow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nonTerm >= s.cap {
		return false
	}
	s.m[f.id] = f
	s.nonTerm++
	return true
}

// terminated records that a flow left the non-terminal set (once).
func (s *flows) terminated() {
	s.mu.Lock()
	s.nonTerm--
	s.mu.Unlock()
}

func (s *flows) indexCallback(h [32]byte, id string) {
	s.mu.Lock()
	s.byCB[h] = id
	s.mu.Unlock()
}

func (s *flows) byCallback(value string) *flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byCB[hashOf(value)]; ok {
		return s.m[id]
	}
	return nil
}

func (s *flows) remove(f *flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[f.id] == f {
		delete(s.m, f.id)
		delete(s.byCB, f.callback)
	}
}

func (s *flows) all() []*flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow, 0, len(s.m))
	for _, f := range s.m {
		out = append(out, f)
	}
	return out
}

// Len returns stored flows (tests and lifecycle assertions).
func (s *flows) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.m) }
