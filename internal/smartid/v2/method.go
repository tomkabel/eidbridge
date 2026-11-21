package v2

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// MethodConfig wraps a v2 Client as an authn.Method named "smartid-v2".
type MethodConfig struct {
	Client      *Client
	DisplayText string // ≤ 60 characters
	IsDemo      bool
	LongPoll    time.Duration
}

// Method is the legacy RP API v2 method (notification flow only).
type Method struct{ cfg MethodConfig }

// NewMethod validates cfg.
func NewMethod(cfg MethodConfig) (*Method, error) {
	if cfg.Client == nil || cfg.DisplayText == "" {
		return nil, errors.New("smartid v2: client and display text required")
	}
	if cfg.LongPoll == 0 {
		cfg.LongPoll = 10 * time.Second
	}
	return &Method{cfg: cfg}, nil
}

func (m *Method) Name() string    { return "smartid-v2" }
func (m *Method) Flows() []string { return []string{authn.FlowNotification} }
func (m *Method) Demo() bool      { return m.cfg.IsDemo }

// Start validates the typed identity and starts the session.
func (m *Method) Start(ctx context.Context, r authn.StartRequest) (authn.Pending, error) {
	if r.Flow != authn.FlowNotification {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "flow not enabled"}
	}
	s, err := m.cfg.Client.Start(ctx, "PNO"+r.Input["country"]+"-"+r.Input["personal_code"], m.cfg.DisplayText)
	if err != nil {
		return nil, err
	}
	return &pending{m: m, s: s}, nil
}

type pending struct {
	m     *Method
	mu    sync.Mutex
	s     *Session
	final *authn.Result
}

func (p *pending) UI(time.Time) (authn.UI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.UI{}, errors.New("smartid v2: flow finished")
	}
	return authn.UI{VC: p.s.VC}, nil
}

func (p *pending) finish(r authn.Result) authn.Result {
	r.Done = true
	if r.Err != nil {
		r.Identity = nil
	}
	p.final = &r
	p.s.Destroy()
	return r
}

func (p *pending) Poll(ctx context.Context) authn.Result {
	p.mu.Lock()
	if p.final != nil {
		r := *p.final
		p.mu.Unlock()
		if r.Identity != nil {
			return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "result already delivered"}}
		}
		return r
	}
	id := p.s.ID
	p.mu.Unlock()
	st, err := p.m.cfg.Client.Poll(ctx, id, p.m.cfg.LongPoll)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil || p.s.Hash == nil {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "late result discarded"}}
	}
	if err != nil {
		var ae *authn.Error
		if errors.As(err, &ae) && ae.Retryable {
			return authn.Result{Waiting: "device", Err: ae}
		}
		return p.finish(authn.Result{Err: err})
	}
	if st.State == "RUNNING" {
		return authn.Result{Waiting: "device"}
	}
	id2, err := p.m.cfg.Client.Verify(ctx, p.s, st)
	if err != nil {
		return p.finish(authn.Result{Err: err})
	}
	return p.finish(authn.Result{Identity: &authn.Identity{Method: "smartid-v2", AMR: []string{"smartid"}, IDType: id2.IDType,
		Country: id2.Country, Code: id2.Code, GivenName: id2.GivenName, FamilyName: id2.Surname, CertLevel: id2.CertLevel}})
}

func (p *pending) Callback(context.Context, url.Values, []byte) authn.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "flow finished"}}
	}
	return p.finish(authn.Result{Err: &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "no callback expected"}})
}

func (p *pending) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.s.Destroy()
	if p.final == nil {
		p.final = &authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonCancelled, Detail: "destroyed"}}
	}
}
