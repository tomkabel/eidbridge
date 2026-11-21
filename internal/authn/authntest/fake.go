package authntest

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// Fake is a scripted method for registry, OIDC and web tests. It produces
// synthetic identities; it is never registered outside tests.
type Fake struct {
	MethodName string
	FlowList   []string
	IsDemo     bool
	// Next decides the outcome of each started pending (default Success).
	Next func(r authn.StartRequest) Outcome
	// Identity returned on success.
	ID authn.Identity
	// Delay before a poll resolves.
	Delay time.Duration
	// AppLink overrides the same-device link the pending UI shows.
	AppLink string

	mu      sync.Mutex
	Started int
}

// Name implements authn.Method.
func (f *Fake) Name() string {
	if f.MethodName == "" {
		return "fake"
	}
	return f.MethodName
}

// Flows implements authn.Method.
func (f *Fake) Flows() []string {
	if len(f.FlowList) == 0 {
		return []string{authn.FlowQR}
	}
	return f.FlowList
}

// Demo implements authn.Method.
func (f *Fake) Demo() bool { return f.IsDemo }

// Start implements authn.Method.
func (f *Fake) Start(ctx context.Context, r authn.StartRequest) (authn.Pending, error) {
	f.mu.Lock()
	f.Started++
	f.mu.Unlock()
	o := Success
	if f.Next != nil {
		o = f.Next(r)
	}
	id := f.ID
	if id.Code == "" {
		id = authn.Identity{IDType: "PNO", Country: "EE", Code: "40404040009", GivenName: "OK", FamilyName: "TEST", CertLevel: "QUALIFIED"}
	}
	id.Method = f.Name()
	id.AMR = []string{f.Name()}
	return &fakePending{o: o, id: id, delay: f.Delay, start: time.Now(), link: f.AppLink}, nil
}

type fakePending struct {
	mu        sync.Mutex
	o         Outcome
	id        authn.Identity
	delay     time.Duration
	start     time.Time
	destroyed bool
	done      bool
	link      string
}

func (p *fakePending) UI(time.Time) (authn.UI, error) {
	link := "https://fake.invalid/app"
	if p.link != "" {
		link = p.link
	}
	return authn.UI{QRPayload: "https://fake.invalid/qr", AppLink: link, Refresh: time.Second}, nil
}

func (p *fakePending) Poll(ctx context.Context) authn.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "destroyed"}}
	}
	if time.Since(p.start) < p.delay {
		return authn.Result{Waiting: "device"}
	}
	first := !p.done
	p.done = true
	switch p.o {
	case Success:
		if !first {
			return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "already consumed"}}
		}
		id := p.id
		return authn.Result{Done: true, Identity: &id}
	case Refuse:
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonRefused, Detail: "fake"}}
	case Timeout:
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "fake"}}
	}
	return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: "fake"}}
}

func (p *fakePending) Callback(ctx context.Context, q url.Values, body []byte) authn.Result {
	return p.Poll(ctx)
}

func (p *fakePending) Destroy() {
	p.mu.Lock()
	p.destroyed = true
	p.mu.Unlock()
}

// FakeHarness runs the contract suite against Fake.
type FakeHarness struct{ F *Fake }

// Method implements Harness.
func (h FakeHarness) Method() authn.Method { return h.F }

// Requests implements Harness.
func (h FakeHarness) Requests() []authn.StartRequest {
	return []authn.StartRequest{{Flow: authn.FlowQR}}
}

// Drive implements Harness.
func (h FakeHarness) Drive(t *testing.T, p authn.Pending, r authn.StartRequest, o Outcome) authn.Result {
	p.(*fakePending).o = o
	return p.Poll(context.Background())
}
