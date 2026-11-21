// Package store holds the bridge's bounded in-memory state. Nothing here is
// persisted. Capacity is reserved up front and never reclaimed by evicting an
// unexpired entry; overflow is reported to the caller (HTTP 503).
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
)

var (
	// ErrFull means no capacity is free; callers answer 503 with Retry-After.
	ErrFull = errors.New("store: capacity exhausted")
	// ErrInvalidGrant covers unknown, expired, consumed and replayed codes.
	ErrInvalidGrant = errors.New("store: invalid grant")
)

// CodesConfig sizes the code store. One slot covers a flow's reservation,
// its authorization code and the code's tombstone (architecture capacity
// model): replay revocation never needs new capacity.
type CodesConfig struct {
	Cap          int
	CodeTTL      time.Duration // at most 60 s
	TombstoneTTL time.Duration // max access-token lifetime plus skew
	Clock        clock.Clock
}

type state uint8

const (
	reserved state = iota
	live
	tombstone
)

type entry struct {
	st       state
	deadline time.Duration // monotonic
	hash     [32]byte
	claims   any
	binding  any
	family   string // set when the first exchange succeeded
	revoked  bool
}

// Codes is the authorization-code store.
type Codes struct {
	cfg      CodesConfig
	mu       sync.Mutex
	used     int
	slots    map[*entry]struct{}
	byHash   map[[32]byte]*entry
	families map[string]*entry
}

// NewCodes returns an empty store.
func NewCodes(cfg CodesConfig) *Codes {
	if cfg.Clock == nil {
		cfg.Clock = clock.Real()
	}
	return &Codes{cfg: cfg, slots: map[*entry]struct{}{}, byHash: map[[32]byte]*entry{}, families: map[string]*entry{}}
}

// Reservation is one reserved slot, filled when the flow verifies.
type Reservation struct {
	c *Codes
	e *entry
}

func (c *Codes) sweepLocked() {
	now := c.cfg.Clock.Mono()
	for e := range c.slots {
		if now < e.deadline {
			continue
		}
		c.removeLocked(e)
	}
}

func (c *Codes) removeLocked(e *entry) {
	if _, ok := c.slots[e]; !ok {
		return
	}
	delete(c.slots, e)
	if e.st != reserved {
		delete(c.byHash, e.hash)
	}
	if e.family != "" {
		delete(c.families, e.family)
	}
	e.claims, e.binding = nil, nil
	c.used--
}

// Reserve claims a slot for a new flow; ttl bounds how long an unfilled
// reservation may live (the flow's absolute deadline).
func (c *Codes) Reserve(ttl time.Duration) (*Reservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used >= c.cfg.Cap {
		c.sweepLocked()
		if c.used >= c.cfg.Cap {
			return nil, ErrFull
		}
	}
	e := &entry{st: reserved, deadline: c.cfg.Clock.Mono() + ttl}
	c.slots[e] = struct{}{}
	c.used++
	return &Reservation{c: c, e: e}, nil
}

// Issue fills the reservation with a fresh code bound to binding.
func (r *Reservation) Issue(claims, binding any) (string, error) {
	c := r.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.slots[r.e]; !ok || r.e.st != reserved {
		return "", errors.New("store: reservation not available")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	r.e.hash = sha256.Sum256([]byte(code))
	r.e.st, r.e.claims, r.e.binding = live, claims, binding
	r.e.deadline = c.cfg.Clock.Mono() + c.cfg.CodeTTL
	c.byHash[r.e.hash] = r.e
	return code, nil
}

// Release frees an unfilled reservation (terminal flow without a code).
func (r *Reservation) Release() {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	if r.e.st == reserved {
		r.c.removeLocked(r.e)
	}
}

// Grant is a successful exchange.
type Grant struct {
	Family   string
	Claims   any
	Binding  any
	Deadline time.Duration // monotonic family deadline
}

// Exchange atomically consumes code. check validates the stored binding
// (client, redirect URI, PKCE); its failure still consumes the code and
// leaves a familyless tombstone. A second presentation of a code whose first
// exchange succeeded revokes that family, whatever its credentials.
func (c *Codes) Exchange(code string, check func(binding any) error) (Grant, error) {
	h := sha256.Sum256([]byte(code))
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.byHash[h]
	now := c.cfg.Clock.Mono()
	if e == nil || code == "" {
		return Grant{}, ErrInvalidGrant
	}
	if now >= e.deadline {
		c.removeLocked(e)
		return Grant{}, ErrInvalidGrant
	}
	if e.st == tombstone {
		if e.family != "" {
			e.revoked = true // deny-list: flag on the existing tombstone, no allocation
		}
		return Grant{}, ErrInvalidGrant
	}
	claims, binding := e.claims, e.binding
	e.st, e.claims, e.binding = tombstone, nil, nil
	e.deadline = now + c.cfg.TombstoneTTL
	if err := check(binding); err != nil {
		return Grant{}, err
	}
	fam := make([]byte, 16)
	if _, err := rand.Read(fam); err != nil {
		return Grant{}, err
	}
	e.family = base64.RawURLEncoding.EncodeToString(fam)
	c.families[e.family] = e
	return Grant{Family: e.family, Claims: claims, Binding: binding, Deadline: e.deadline}, nil
}

// FamilyActive reports whether a token family exists, is unrevoked and has
// not passed its monotonic deadline.
func (c *Codes) FamilyActive(family string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.families[family]
	if e == nil || e.revoked {
		return false
	}
	if c.cfg.Clock.Mono() >= e.deadline {
		c.removeLocked(e)
		return false
	}
	return true
}

// RevokeAll marks every family revoked (emergency key revocation).
func (c *Codes) RevokeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.families {
		e.revoked = true
	}
}

// Len reports stored entries without sweeping (tests and metrics).
func (c *Codes) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.slots) }

// StartSweeper sweeps every interval until the returned stop is called, so
// expired codes, tombstones and their claim sets leave memory on time
// (privacy audit F1), not only under capacity pressure.
func (c *Codes) StartSweeper(interval time.Duration) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				c.Sweep()
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// Sweep drops expired entries.
func (c *Codes) Sweep() { c.mu.Lock(); c.sweepLocked(); c.mu.Unlock() }

// Counts returns reservations, live codes and tombstones.
func (c *Codes) Counts() (reservations, codes, tombstones int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	for e := range c.slots {
		switch e.st {
		case reserved:
			reservations++
		case live:
			codes++
		default:
			tombstones++
		}
	}
	return
}

// LiveCodeDeadline returns the latest monotonic deadline of any live code
// (SIGTERM drain waits for it).
func (c *Codes) LiveCodeDeadline() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var d time.Duration
	for e := range c.slots {
		if e.st == live && e.deadline > d {
			d = e.deadline
		}
	}
	return d
}
