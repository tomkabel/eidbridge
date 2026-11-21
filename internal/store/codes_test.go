package store

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
)

var errBad = errors.New("bad binding")

func newCodes(t *testing.T, cap int) (*Codes, *clock.Fake) {
	clk := clock.NewFake(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	return NewCodes(CodesConfig{Cap: cap, CodeTTL: 60 * time.Second, TombstoneTTL: 5*time.Minute + 30*time.Second, Clock: clk}), clk
}

func issue(t *testing.T, c *Codes, claims string) string {
	t.Helper()
	r, err := c.Reserve(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	code, err := r.Issue(claims, "binding")
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func ok(any) error  { return nil }
func bad(any) error { return errBad }

func TestCodeSlotReservedAtFlowCreation(t *testing.T) {
	c, _ := newCodes(t, 2)
	r1, _ := c.Reserve(time.Minute)
	r2, _ := c.Reserve(time.Minute)
	if _, err := c.Reserve(time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("third reservation: %v", err)
	}
	// Full store: the reserved slot still yields a code for the verified user.
	if _, err := r1.Issue("claims", "b"); err != nil {
		t.Fatalf("issue at capacity: %v", err)
	}
	if _, err := r1.Issue("again", "b"); err == nil {
		t.Fatal("double issue")
	}
	r2.Release()
	if _, err := c.Reserve(time.Minute); err != nil {
		t.Fatalf("released slot not reusable: %v", err)
	}
}

func TestStoreFullNeverEvicts(t *testing.T) {
	c, clk := newCodes(t, 3)
	a := issue(t, c, "a")
	b := issue(t, c, "b")
	g, _ := c.Exchange(b, ok) // b becomes a tombstone
	_, _ = c.Reserve(time.Minute)
	if _, err := c.Reserve(time.Minute); !errors.Is(err, ErrFull) {
		t.Fatal("overflow not refused")
	}
	clk.Advance(30 * time.Second)
	if _, err := c.Exchange(a, ok); err != nil {
		t.Fatalf("live code evicted: %v", err)
	}
	if !c.FamilyActive(g.Family) {
		t.Fatal("tombstone family evicted")
	}
}

func TestClaimSetKeyedByCodeHash(t *testing.T) {
	c, _ := newCodes(t, 4)
	code := issue(t, c, "claims")
	c.mu.Lock()
	for k, e := range c.byHash {
		if string(k[:]) == code || e.claims != "claims" {
			t.Fatal("store must key by code hash and hold the claim set until exchange")
		}
	}
	c.mu.Unlock()
	g, err := c.Exchange(code, ok)
	if err != nil || g.Claims != "claims" {
		t.Fatalf("exchange: %v", err)
	}
	c.mu.Lock()
	for _, e := range c.byHash {
		if e.claims != nil {
			t.Fatal("claims retained after exchange")
		}
	}
	c.mu.Unlock()
}

func TestFailedExchangeStillConsumesCode(t *testing.T) {
	c, _ := newCodes(t, 4)
	code := issue(t, c, "x")
	if _, err := c.Exchange(code, bad); !errors.Is(err, errBad) {
		t.Fatalf("first: %v", err)
	}
	if _, err := c.Exchange(code, ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("retry after failed exchange: %v", err)
	}
}

func TestFailedExchangeLeavesFamilylessTombstone(t *testing.T) {
	c, _ := newCodes(t, 4)
	// wrong then correct
	code := issue(t, c, "x")
	c.Exchange(code, bad)
	if _, err := c.Exchange(code, ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("wrong-then-correct succeeded")
	}
	// correct then wrong: family preserved and revoked
	code2 := issue(t, c, "y")
	g, err := c.Exchange(code2, ok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(code2, bad); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("replay accepted")
	}
	if c.FamilyActive(g.Family) {
		t.Fatal("replay with wrong credentials did not revoke the family")
	}
}

func TestConcurrentCodeExchangeSingleWinner(t *testing.T) {
	for i := 0; i < 50; i++ {
		c, _ := newCodes(t, 4)
		code := issue(t, c, "x")
		var wins atomic.Int32
		var fam atomic.Value
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if g, err := c.Exchange(code, ok); err == nil {
					wins.Add(1)
					fam.Store(g.Family)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d winners", wins.Load())
		}
		// TestConcurrentExchangeLoserDenyListsWinnerFamily
		if c.FamilyActive(fam.Load().(string)) {
			t.Fatal("losing presentation did not revoke the winner's family")
		}
	}
}

func TestReplayAtFullCapacityUsesReservedTombstone(t *testing.T) {
	c, _ := newCodes(t, 1)
	code := issue(t, c, "x")
	g, _ := c.Exchange(code, ok)
	if _, err := c.Reserve(time.Minute); !errors.Is(err, ErrFull) {
		t.Fatal("tombstone must keep its slot")
	}
	if _, err := c.Exchange(code, ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("replay")
	}
	if c.FamilyActive(g.Family) || c.FamilyActive("") || c.FamilyActive("unknown") {
		t.Fatal("revocation at full capacity failed")
	}
}

func TestTTLsUseMonotonicClock(t *testing.T) {
	c, clk := newCodes(t, 4)
	code := issue(t, c, "x")
	clk.StepWall(-time.Hour) // wall jumps back: code must still expire on time
	clk.Advance(59 * time.Second)
	code2 := issue(t, c, "y")
	clk.StepWall(48 * time.Hour) // wall jumps forward: no early expiry
	if _, err := c.Exchange(code2, ok); err != nil {
		t.Fatalf("early expiry on wall jump: %v", err)
	}
	clk.Advance(2 * time.Second) // mono 61 s for the first code
	if _, err := c.Exchange(code, ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("code outlived 60 s monotonic")
	}
}

func TestTombstoneAndReservationExpiryFreeSlots(t *testing.T) {
	c, clk := newCodes(t, 2)
	code := issue(t, c, "x")
	g, _ := c.Exchange(code, ok)
	if _, err := c.Reserve(time.Second); err != nil { // second slot, short deadline
		t.Fatal(err)
	}
	if _, err := c.Reserve(time.Minute); !errors.Is(err, ErrFull) {
		t.Fatal("full")
	}
	clk.Advance(2 * time.Second)
	if _, err := c.Reserve(time.Minute); err != nil {
		t.Fatalf("expired reservation not reclaimed: %v", err)
	}
	clk.Advance(5*time.Minute + 31*time.Second)
	if c.FamilyActive(g.Family) {
		t.Fatal("family outlived tombstone TTL")
	}
	if _, err := c.Reserve(time.Minute); err != nil {
		t.Fatalf("expired tombstone not reclaimed: %v", err)
	}
	r, l, tb := c.Counts()
	if r+l+tb > 2 {
		t.Fatalf("counts %d %d %d", r, l, tb)
	}
}

func TestUnknownCodeInvalidGrant(t *testing.T) {
	c, _ := newCodes(t, 1)
	if _, err := c.Exchange("nope", ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal(err)
	}
	if _, err := c.Exchange("", ok); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal(err)
	}
}

func TestCodeEntropy(t *testing.T) {
	c, _ := newCodes(t, 2)
	code := issue(t, c, "x")
	if len(code) != 43 { // 32 bytes base64url
		t.Fatalf("code length %d", len(code))
	}
}

// Privacy audit F1: expired codes and tombstones (and their claim sets)
// are dropped by the periodic sweeper, not only under capacity pressure.
func TestSweeperDropsExpiredEntries(t *testing.T) {
	c, clk := newCodes(t, 10)
	issue(t, c, "claims")
	code := issue(t, c, "claims2")
	c.Exchange(code, ok)
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
	stop := c.StartSweeper(5 * time.Millisecond)
	defer stop()
	clk.Advance(61 * time.Second) // the unexchanged code expires; the tombstone lives on
	waitLen(t, c, 1)
	clk.Advance(5*time.Minute + 30*time.Second)
	waitLen(t, c, 0)
}

func waitLen(t *testing.T, c *Codes, n int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if c.Len() == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("len %d, want %d", c.Len(), n)
}
