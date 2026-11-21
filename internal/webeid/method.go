package webeid

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// MethodConfig wraps a Validator as an authn.Method.
type MethodConfig struct {
	Validator *Validator
	IsDemo    bool
	NonceTTL  time.Duration // default 5 minutes
	LongPoll  time.Duration // how long Poll waits for the browser, default 10 s
}

// Method is the Web eID (ID-card) authn.Method with the browser flow.
type Method struct{ cfg MethodConfig }

// NewMethod validates cfg.
func NewMethod(cfg MethodConfig) (*Method, error) {
	if cfg.Validator == nil || cfg.Validator.Trust == nil || cfg.Validator.Trust.Empty() || cfg.Validator.Status == nil || cfg.Validator.Now == nil {
		return nil, errors.New("webeid: validator with trust, status checker and clock required")
	}
	if cfg.NonceTTL == 0 {
		cfg.NonceTTL = 5 * time.Minute
	}
	if cfg.LongPoll == 0 {
		cfg.LongPoll = 10 * time.Second
	}
	return &Method{cfg: cfg}, nil
}

// Name implements authn.Method.
func (m *Method) Name() string { return "webeid" }

// Flows implements authn.Method.
func (m *Method) Flows() []string { return []string{authn.FlowBrowser} }

// Demo implements authn.Method.
func (m *Method) Demo() bool { return m.cfg.IsDemo }

// Start issues a fresh 256-bit challenge nonce bound to this pending flow.
// The origin is the bridge's configured public origin.
func (m *Method) Start(_ context.Context, r authn.StartRequest) (authn.Pending, error) {
	if r.Flow != authn.FlowBrowser {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "flow not enabled"}
	}
	origin, err := ASCIIOrigin(r.Origin)
	if err != nil {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "Web eID needs an https public origin"}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &pending{m: m, origin: origin, nonce: base64.StdEncoding.EncodeToString(b), issued: m.cfg.Validator.Now(),
		done: make(chan struct{})}, nil
}

type pending struct {
	m      *Method
	mu     sync.Mutex
	origin string
	nonce  string // single use: cleared at the first token or on Destroy
	issued time.Time
	final  *authn.Result
	done   chan struct{}
}

func (p *pending) UI(time.Time) (authn.UI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil || p.nonce == "" {
		return authn.UI{}, errors.New("webeid: flow finished")
	}
	return authn.UI{Challenge: p.nonce}, nil
}

func (p *pending) finishLocked(r authn.Result) authn.Result {
	r.Done = true
	if r.Err != nil {
		r.Identity = nil
	}
	p.final = &r
	p.nonce = ""
	close(p.done)
	return r
}

// Poll waits for the browser to post a token (there is no upstream).
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
	if p.m.cfg.Validator.Now().Sub(p.issued) > p.m.cfg.NonceTTL {
		r := p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "challenge nonce expired"}})
		p.mu.Unlock()
		return r
	}
	p.mu.Unlock()
	t := time.NewTimer(p.m.cfg.LongPoll)
	defer t.Stop()
	select {
	case <-p.done:
		p.mu.Lock()
		r := *p.final
		p.mu.Unlock()
		return r
	case <-ctx.Done():
	case <-t.C:
	}
	return authn.Result{Waiting: "browser"}
}

// Callback validates the token the page posted. The nonce is consumed by
// the first token, valid or not; a second token is refused.
func (p *pending) Callback(ctx context.Context, _ url.Values, body []byte) authn.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "flow finished"}}
	}
	nonce := p.nonce
	if p.m.cfg.Validator.Now().Sub(p.issued) > p.m.cfg.NonceTTL {
		return p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "challenge nonce expired"}})
	}
	if r, ok := browserError(body); ok {
		return p.finishLocked(r)
	}
	tok, err := ParseToken(body)
	if err != nil {
		return p.finishLocked(authn.Result{Err: err})
	}
	id, err := p.m.cfg.Validator.Validate(ctx, tok, p.origin, nonce)
	if err != nil {
		return p.finishLocked(authn.Result{Err: err})
	}
	return p.finishLocked(authn.Result{Identity: &authn.Identity{Method: "webeid", AMR: []string{"webeid"}, IDType: id.IDType,
		Country: id.Country, Code: id.Code, GivenName: id.GivenName, FamilyName: id.Surname}})
}

func (p *pending) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final == nil {
		p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonCancelled, Detail: "destroyed"}})
	}
	p.nonce = ""
}

// browserError maps an error the page reports instead of a token (the
// web-eid.js error code) to a terminal result. It carries no identity.
func browserError(body []byte) (authn.Result, bool) {
	var e struct {
		Code   string `json:"code"`
		Format string `json:"format"`
	}
	if len(body) > 256 || json.Unmarshal(body, &e) != nil || e.Code == "" || e.Format != "" {
		return authn.Result{}, false
	}
	switch e.Code {
	case "ERR_WEBEID_USER_CANCELLED":
		return authn.Result{Err: &authn.Error{Reason: authn.ReasonRefused, Detail: "user cancelled in the browser"}}, true
	case "ERR_WEBEID_USER_TIMEOUT":
		return authn.Result{Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "user did not respond"}}, true
	}
	return authn.Result{Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "browser extension or card not available"}}, true
}
