package smartid

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
	Client       *Client
	Flows        []string          // subset of authn.FlowQR, FlowSameDevice, FlowNotification
	DisplayText  map[string]string // per ISO 639-1 language; "en" required
	IsDemo       bool
	LongPoll     time.Duration                    // upstream timeoutMs per poll, default 10 s
	NotifyLookup func(country, code string) error // optional extra validation hook
}

// Method is the Smart-ID authn.Method.
type Method struct{ cfg MethodConfig }

// NewMethod validates cfg.
func NewMethod(cfg MethodConfig) (*Method, error) {
	if cfg.Client == nil || len(cfg.Flows) == 0 {
		return nil, errors.New("smartid: method needs a client and flows")
	}
	for _, f := range cfg.Flows {
		if f != authn.FlowQR && f != authn.FlowSameDevice && f != authn.FlowNotification {
			return nil, errors.New("smartid: unsupported flow " + f)
		}
	}
	if cfg.DisplayText["en"] == "" {
		return nil, errors.New("smartid: English display text required")
	}
	for _, t := range cfg.DisplayText {
		if _, err := Interactions(t); err != nil {
			return nil, err
		}
	}
	if cfg.LongPoll == 0 {
		cfg.LongPoll = 10 * time.Second
	}
	return &Method{cfg: cfg}, nil
}

// Name implements authn.Method.
func (m *Method) Name() string { return "smartid" }

// Flows implements authn.Method.
func (m *Method) Flows() []string { return append([]string(nil), m.cfg.Flows...) }

// Demo implements authn.Method.
func (m *Method) Demo() bool { return m.cfg.IsDemo }

var lang3 = map[string]string{"en": "eng", "et": "est", "lv": "lav", "lt": "lit", "ru": "rus"}

func (m *Method) offers(f string) bool {
	for _, x := range m.cfg.Flows {
		if x == f {
			return true
		}
	}
	return false
}

// Start implements authn.Method. Notification input is validated locally
// before any outbound request.
func (m *Method) Start(ctx context.Context, r authn.StartRequest) (authn.Pending, error) {
	if !m.offers(r.Flow) {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "flow not enabled"}
	}
	text := m.cfg.DisplayText[r.Lang]
	if text == "" {
		text = m.cfg.DisplayText["en"]
	}
	l3 := lang3[r.Lang]
	if l3 == "" {
		l3 = "eng"
	}
	var s *Session
	var err error
	switch r.Flow {
	case authn.FlowQR:
		s, err = m.cfg.Client.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowQR, DisplayText60: text, Lang: l3})
	case authn.FlowSameDevice:
		s, err = m.cfg.Client.StartDeviceLink(ctx, DeviceLinkRequest{Flow: FlowWeb2App, DisplayText60: text, Lang: l3, InitialCallbackURL: r.CallbackURL})
	case authn.FlowNotification:
		id := "PNO" + r.Input["country"] + "-" + r.Input["personal_code"]
		if ValidateSemanticsID(id) != nil {
			return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "identifier failed local validation"}
		}
		s, err = m.cfg.Client.StartNotification(ctx, NotificationRequest{SemanticsID: id, DisplayText60: text, Lang: l3})
	}
	if err != nil {
		return nil, toAuthn(err)
	}
	return &pending{m: m, s: s}, nil
}

type pending struct {
	m  *Method
	mu sync.Mutex
	s  *Session
	ok *Status   // OK status waiting for the Web2App callback (ok_seen)
	cb *Callback // validated callback waiting for the OK status (callback_seen)
	// terminal result, once reached
	final *authn.Result
}

func (p *pending) UI(now time.Time) (authn.UI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.s == nil || p.final != nil {
		return authn.UI{}, errors.New("smartid: flow finished")
	}
	switch p.s.Flow {
	case FlowQR:
		l, err := p.s.QRLink(now)
		return authn.UI{QRPayload: l, Refresh: time.Second}, err
	case FlowWeb2App:
		l, err := p.s.Web2AppLink()
		return authn.UI{AppLink: l}, err
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
	p.ok, p.cb = nil, nil
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
	if p.s == nil || p.s.secret == nil {
		p.mu.Unlock()
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "destroyed"}}
	}
	if p.ok != nil {
		p.mu.Unlock()
		return authn.Result{Waiting: "callback"}
	}
	id := p.s.ID
	p.mu.Unlock()

	st, err := p.m.cfg.Client.Poll(ctx, id, p.m.cfg.LongPoll)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil || p.s == nil || p.s.secret == nil {
		// Late result for a terminal or destroyed flow: discard.
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "late result discarded"}}
	}
	if err != nil {
		ae := toAuthn(err)
		if ae.Retryable {
			return authn.Result{Waiting: "device", Err: ae}
		}
		return p.finish(authn.Result{Err: ae})
	}
	if st.State == "RUNNING" {
		return authn.Result{Waiting: "device"}
	}
	if oerr := Outcome(st); oerr != nil {
		return p.finish(authn.Result{Err: toAuthn(oerr)})
	}
	if p.s.Flow == FlowWeb2App && p.cb == nil {
		p.ok = st
		return authn.Result{Waiting: "callback"}
	}
	return p.verify(ctx, st, p.cb)
}

func (p *pending) verify(ctx context.Context, st *Status, cb *Callback) authn.Result {
	id, err := p.m.cfg.Client.VerifyContext(ctx, p.s, st, cb)
	if err != nil {
		return p.finish(authn.Result{Err: toAuthn(err)})
	}
	return p.finish(authn.Result{Identity: &authn.Identity{Method: "smartid", AMR: []string{"smartid"}, IDType: id.IDType,
		Country: id.Country, Code: id.Code, GivenName: id.GivenName, FamilyName: id.Surname, CertLevel: id.CertLevel}})
}

// Callback handles the Web2App return. The web layer has already checked the
// flow cookie and consumed its own unpredictable value.
func (p *pending) Callback(ctx context.Context, q url.Values, _ []byte) authn.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "flow finished"}}
	}
	if p.s == nil || p.s.secret == nil || p.s.Flow != FlowWeb2App {
		return p.finish(authn.Result{Err: &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "no callback expected"}})
	}
	if p.cb != nil {
		return authn.Result{Waiting: "device"} // duplicate callback: ignored
	}
	cb := &Callback{SessionSecretDigest: q.Get("sessionSecretDigest"), UserChallengeVerifier: q.Get("userChallengeVerifier")}
	if !p.s.SecretDigestMatches(cb.SessionSecretDigest) || cb.UserChallengeVerifier == "" || len(cb.UserChallengeVerifier) > 256 {
		return p.finish(authn.Result{Err: &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: "callback digest or verifier invalid"}})
	}
	if p.ok == nil {
		p.cb = cb // callback_seen: wait for the signed result
		return authn.Result{Waiting: "device"}
	}
	st := p.ok
	return p.verify(ctx, st, cb)
}

func (p *pending) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.s != nil {
		p.s.Destroy()
	}
	p.ok, p.cb = nil, nil
}

func toAuthn(err error) *authn.Error {
	var he *HTTPError
	if errors.As(err, &he) {
		if he.Status == 404 {
			return &authn.Error{Reason: authn.ReasonExpired, Detail: "session not found upstream", Cause: err}
		}
		return &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "upstream http error", Retryable: he.Retryable, RetryIn: he.RetryAfter, Cause: err}
	}
	var se *Error
	if errors.As(err, &se) {
		return &authn.Error{Reason: se.Reason, Detail: se.Detail, Cause: err}
	}
	return &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "start failed", Cause: err}
}
