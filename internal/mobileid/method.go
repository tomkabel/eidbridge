package mobileid

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// MethodConfig wraps a Client as an authn.Method.
type MethodConfig struct {
	Client      *Client
	DisplayText map[string]string // per ISO 639-1 language, ≤ 40 GSM-7 characters; optional
	IsDemo      bool
	LongPoll    time.Duration // upstream timeoutMs per poll, default 10 s
}

// Method is the Mobile-ID authn.Method. It offers one flow: a push to the
// phone the user names (notification).
type Method struct{ cfg MethodConfig }

// NewMethod validates cfg.
func NewMethod(cfg MethodConfig) (*Method, error) {
	if cfg.Client == nil {
		return nil, errors.New("mobileid: method needs a client")
	}
	for _, t := range cfg.DisplayText {
		if !gsm7Re.MatchString(t) {
			return nil, errors.New("mobileid: display text must be ≤ 40 plain GSM-7 characters")
		}
	}
	if cfg.LongPoll == 0 {
		cfg.LongPoll = 10 * time.Second
	}
	return &Method{cfg: cfg}, nil
}

// Name implements authn.Method.
func (m *Method) Name() string { return "mobileid" }

// Flows implements authn.Method.
func (m *Method) Flows() []string { return []string{authn.FlowNotification} }

// Demo implements authn.Method.
func (m *Method) Demo() bool { return m.cfg.IsDemo }

var lang3 = map[string]string{"en": "ENG", "et": "EST", "ru": "RUS", "lt": "LIT"}

// Start validates the phone number and personal code locally, then starts
// the upstream session. The country select, if sent, must agree with the
// phone prefix.
func (m *Method) Start(ctx context.Context, r authn.StartRequest) (authn.Pending, error) {
	if r.Flow != authn.FlowNotification {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "flow not enabled"}
	}
	phone, code := r.Input["phone"], r.Input["personal_code"]
	country, err := ValidateInput(phone, code)
	if err != nil {
		return nil, err
	}
	if c := r.Input["country"]; c != "" && c != country {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "country does not match the phone number"}
	}
	text := m.cfg.DisplayText[r.Lang]
	if text == "" {
		text = m.cfg.DisplayText["en"]
	}
	l3 := lang3[r.Lang]
	if l3 == "" {
		l3 = "ENG"
	}
	s, err := m.cfg.Client.Start(ctx, StartRequest{Phone: phone, Code: code, Lang3: l3, DisplayText: text})
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
	if p.s == nil || p.final != nil {
		return authn.UI{}, errors.New("mobileid: flow finished")
	}
	return authn.UI{VC: p.s.VC}, nil
}

func (p *pending) finish(r authn.Result) authn.Result {
	r.Done = true
	if r.Err != nil {
		r.Identity = nil
	}
	p.final = &r
	if p.s != nil {
		p.s.Destroy()
	}
	return r
}

// Poll performs one upstream long poll outside the lock.
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
	if p.s == nil || p.s.Hash == nil {
		p.mu.Unlock()
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "destroyed"}}
	}
	id := p.s.ID
	p.mu.Unlock()

	st, err := p.m.cfg.Client.Poll(ctx, id, p.m.cfg.LongPoll)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil || p.s == nil || p.s.Hash == nil {
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
	return p.finish(authn.Result{Identity: &authn.Identity{Method: "mobileid", AMR: []string{"mobileid"}, IDType: "PNO",
		Country: id2.Country, Code: id2.Code, GivenName: id2.GivenName, FamilyName: id2.Surname}})
}

// Callback is not used by Mobile-ID.
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
	if p.s != nil {
		p.s.Destroy()
	}
	if p.final == nil {
		p.final = &authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonCancelled, Detail: "destroyed"}}
	}
}
