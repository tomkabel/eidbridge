// Package authn is the method-neutral contract between eID methods and the
// OIDC provider and login pages. It is internal and may change before v1.0:
// the second real method will reveal what it got wrong.
//
// A Method starts a Pending authentication. The web layer drives it with
// server-side Poll calls and browser Callback calls; only a Result carrying a
// verified Identity can lead to an authorization code. Methods produce an
// Identity only after their own full cryptographic verification.
package authn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// Flow names. A method offers a subset.
const (
	FlowQR           = "qr"           // cross-device: QR rendered by the bridge
	FlowSameDevice   = "same-device"  // app link plus callback (Smart-ID Web2App, wallet same-device)
	FlowNotification = "notification" // push to a known person (identifier typed by the user)
	FlowBrowser      = "browser"      // browser extension or JS (Web eID)
)

// Reason codes shared by every method (architecture ADR-002 state machine).
const (
	ReasonRefused            = "refused"
	ReasonExpired            = "expired"
	ReasonWrongCode          = "wrong_code"
	ReasonAccountUnusable    = "account_unusable"
	ReasonUpstreamError      = "upstream_error"
	ReasonVerificationFailed = "verification_failed"
	ReasonIdentityMismatch   = "identity_mismatch"
	ReasonUnknownEndResult   = "unknown_end_result"
	ReasonStatusUnavailable  = "status_unavailable"
	ReasonRetriesExhausted   = "retries_exhausted"
	ReasonInvalidInput       = "invalid_input"
	ReasonCancelled          = "cancelled"
)

// Error is a typed method failure. Detail names the failed check and never
// carries personal data.
type Error struct {
	Reason    string
	Detail    string
	Retryable bool          // transient upstream condition; caller may poll again
	RetryIn   time.Duration // upstream Retry-After, if any
	Cause     error
}

func (e *Error) Error() string { return fmt.Sprintf("authn: %s: %s", e.Reason, e.Detail) }
func (e *Error) Unwrap() error { return e.Cause }

// ReasonOf returns the reason code of err (upstream_error when untyped).
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonUpstreamError
}

// Identity is a verified person. Code is personal data; it reaches clients
// only through the sub HMAC or an allow-listed personal_code claim.
type Identity struct {
	Method     string   // registry name, e.g. "smartid"
	AMR        []string // RFC 8176 style method references, e.g. ["smartid"]
	IDType     string   // PNO, PAS, IDC
	Country    string   // ISO 3166-1 alpha-2
	Code       string
	GivenName  string // only when verified evidence carries it
	FamilyName string
	// CertLevel is the method's own level label (e.g. QUALIFIED). It is
	// evidence, not a legal assurance level (ADR-008).
	CertLevel string
	// Extra holds further verified attributes (for example a wallet
	// birthdate). Each reaches tokens only through an explicit allow-list.
	Extra map[string]string
}

// StartRequest is created by the web layer from a validated authorize
// request and the user's flow choice.
type StartRequest struct {
	Flow        string
	Lang        string            // ISO 639-1 (en, et, lv, lt, ru)
	CallbackURL string            // same-device: bridge URL with an unpredictable value
	Origin      string            // the bridge's public origin (Web eID, wallets)
	Input       map[string]string // user input for notification-style flows
	ClientID    string
}

// UI is what the login page shows for a pending authentication. The web
// layer renders it server-side; secrets never appear here.
type UI struct {
	QRPayload string            // content to encode as a QR image (refreshing)
	AppLink   string            // same-device link
	VC        string            // verification code to compare on the device
	Challenge string            // browser challenge (Web eID nonce)
	Refresh   time.Duration     // how often QRPayload changes (0: static)
	Extra     map[string]string // method-specific, non-secret page hints
}

// Result of a Poll or Callback. Done with nil Err means Identity is set.
type Result struct {
	Done     bool
	Identity *Identity
	Err      error
	// Waiting names what a not-done result waits for ("device", "callback").
	Waiting string
}

// Pending is one in-progress authentication. Implementations are safe for
// concurrent use; Poll may block up to the method's long-poll interval and
// must honor ctx.
type Pending interface {
	UI(now time.Time) (UI, error)
	Poll(ctx context.Context) Result
	// Callback handles a browser return (same-device callback, Web eID
	// token, wallet response). It returns Done only when verification is
	// complete. Methods without callbacks return a terminal invalid_input.
	Callback(ctx context.Context, q url.Values, body []byte) Result
	// Destroy erases secrets; later calls fail.
	Destroy()
}

// Method is an eID backend.
type Method interface {
	Name() string
	Flows() []string
	// Demo reports whether the method talks to a demo/test environment.
	Demo() bool
	Start(ctx context.Context, r StartRequest) (Pending, error)
}

// Registry is the ordered set of enabled methods.
type Registry struct {
	byName map[string]Method
	order  []string
}

// NewRegistry builds a registry; names must be unique and non-empty.
func NewRegistry(ms ...Method) (*Registry, error) {
	r := &Registry{byName: map[string]Method{}}
	for _, m := range ms {
		n := m.Name()
		if n == "" || r.byName[n] != nil {
			return nil, fmt.Errorf("authn: duplicate or empty method name %q", n)
		}
		r.byName[n] = m
		r.order = append(r.order, n)
	}
	if len(r.order) == 0 {
		return nil, errors.New("authn: no method enabled")
	}
	return r, nil
}

// Get returns a method by name.
func (r *Registry) Get(name string) (Method, bool) { m, ok := r.byName[name]; return m, ok }

// Names returns the enabled method names in configuration order.
func (r *Registry) Names() []string { return append([]string(nil), r.order...) }

// Sorted returns names sorted alphabetically (stable discovery output).
func (r *Registry) Sorted() []string { s := r.Names(); sort.Strings(s); return s }

// Len returns the number of methods.
func (r *Registry) Len() int { return len(r.order) }
