// Package authntest is the contract suite every authn.Method must pass, plus
// a fake method for registry and OIDC tests.
package authntest

import (
	"context"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// Outcome is a scripted upstream result.
type Outcome int

const (
	Success Outcome = iota
	Refuse
	Timeout
	VerifyFail
)

func (o Outcome) String() string {
	return [...]string{"success", "refuse", "timeout", "verify-fail"}[o]
}

// Harness adapts a method and its fake upstream to the contract suite.
type Harness interface {
	Method() authn.Method
	// Requests returns the start requests to exercise (one per flow).
	Requests() []authn.StartRequest
	// Drive makes the upstream reach outcome for p and, for flows that
	// need it, performs the browser callback. It returns the final Result
	// the web layer would observe.
	Drive(t *testing.T, p authn.Pending, r authn.StartRequest, o Outcome) authn.Result
}

var wantReason = map[Outcome]string{Refuse: authn.ReasonRefused, Timeout: authn.ReasonExpired, VerifyFail: authn.ReasonVerificationFailed}

// Run executes the contract: start, poll to completion, refusal, timeout,
// verification failure, and no success after Destroy.
func Run(t *testing.T, h Harness) {
	t.Helper()
	m := h.Method()
	if m.Name() == "" || len(m.Flows()) == 0 {
		t.Fatal("method must have a name and at least one flow")
	}
	for _, req := range h.Requests() {
		req := req
		for _, o := range []Outcome{Success, Refuse, Timeout, VerifyFail} {
			o := o
			t.Run(req.Flow+"/"+o.String(), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				p, err := m.Start(ctx, req)
				if err != nil {
					t.Fatalf("start: %v", err)
				}
				defer p.Destroy()
				if _, err := p.UI(time.Now()); err != nil {
					t.Fatalf("ui: %v", err)
				}
				res := h.Drive(t, p, req, o)
				if !res.Done {
					t.Fatalf("outcome %s did not finish: %+v", o, res)
				}
				switch o {
				case Success:
					if res.Err != nil || res.Identity == nil {
						t.Fatalf("success: err=%v identity=%v", res.Err, res.Identity != nil)
					}
					id := res.Identity
					if id.Method != m.Name() || id.Country == "" || id.Code == "" || id.IDType == "" || len(id.AMR) == 0 {
						t.Fatalf("identity incomplete: method=%q country=%q type=%q amr=%v", id.Method, id.Country, id.IDType, id.AMR)
					}
				default:
					if res.Identity != nil {
						t.Fatalf("%s produced an identity", o)
					}
					if got := authn.ReasonOf(res.Err); got != wantReason[o] && !(o == VerifyFail && got == authn.ReasonIdentityMismatch) {
						t.Fatalf("%s: reason %q, want %q (%v)", o, got, wantReason[o], res.Err)
					}
				}
				// A terminal pending never later turns into a success.
				again := p.Poll(ctx)
				if o != Success && again.Identity != nil {
					t.Fatal("terminal flow produced an identity on a later poll")
				}
			})
		}
		t.Run(req.Flow+"/destroyed", func(t *testing.T) {
			p, err := m.Start(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			p.Destroy()
			if r := p.Poll(context.Background()); r.Identity != nil || (r.Done && r.Err == nil) {
				t.Fatal("destroyed pending must not succeed")
			}
		})
	}
}
