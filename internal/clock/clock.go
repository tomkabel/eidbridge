// Package clock separates wall time from the process monotonic clock. All
// TTLs and acceptance deadlines use Mono; wall time is only for token iat/exp
// and certificate validity.
package clock

import (
	"sync"
	"time"
)

// Clock provides wall and monotonic time.
type Clock interface {
	Now() time.Time      // wall clock
	Mono() time.Duration // monotonic time since process start
}

type real struct{ start time.Time }

// Real returns the system clock. Mono derives from Go's monotonic reading.
func Real() Clock { return real{start: time.Now()} }

func (r real) Now() time.Time      { return time.Now() }
func (r real) Mono() time.Duration { return time.Since(r.start) }

// Fake is a test clock whose wall and monotonic readings move independently.
type Fake struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

// NewFake returns a fake clock at wall.
func NewFake(wall time.Time) *Fake { return &Fake{wall: wall} }

// Now implements Clock.
func (f *Fake) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.wall }

// Mono implements Clock.
func (f *Fake) Mono() time.Duration { f.mu.Lock(); defer f.mu.Unlock(); return f.mono }

// Advance moves both clocks forward.
func (f *Fake) Advance(d time.Duration) { f.mu.Lock(); f.wall = f.wall.Add(d); f.mono += d; f.mu.Unlock() }

// StepWall moves only the wall clock (either direction).
func (f *Fake) StepWall(d time.Duration) { f.mu.Lock(); f.wall = f.wall.Add(d); f.mu.Unlock() }
