package eudi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// VerifierIdentity is the relying party's access certificate and key. The
// client identifier uses the x509_hash prefix (OpenID4VP 1.0 §5.9.3).
type VerifierIdentity struct {
	Key   *ecdsa.PrivateKey // P-256
	Chain []*x509.Certificate
}

// ClientID returns x509_hash:<base64url(SHA-256(leaf DER))>.
func (v *VerifierIdentity) ClientID() string {
	s := sha256.Sum256(v.Chain[0].Raw)
	return "x509_hash:" + b64.EncodeToString(s[:])
}

// PID claims the bridge requests and may pass on (claim ceiling).
var requestedClaims = []string{"given_name", "family_name", "birthdate", "personal_administrative_number", "issuing_country"}

// MethodConfig configures the EUDI Wallet method.
type MethodConfig struct {
	Identity *VerifierIdentity
	Verifier *Verifier
	Flows    []string // authn.FlowQR and/or authn.FlowSameDevice
	Scheme   string   // wallet invocation scheme, default openid4vp://
	IsDemo   bool
	TTL      time.Duration // request lifetime, default 5 min
	LongPoll time.Duration // default 10 s
}

// Method is the EUDI Wallet authn.Method.
type Method struct{ cfg MethodConfig }

// NewMethod validates cfg.
func NewMethod(cfg MethodConfig) (*Method, error) {
	if cfg.Identity == nil || cfg.Identity.Key == nil || len(cfg.Identity.Chain) == 0 || cfg.Verifier == nil || cfg.Verifier.Trust == nil || cfg.Verifier.Now == nil {
		return nil, errors.New("eudi: verifier identity, trust and clock required")
	}
	if !cfg.Identity.Chain[0].PublicKey.(*ecdsa.PublicKey).Equal(&cfg.Identity.Key.PublicKey) {
		return nil, errors.New("eudi: verifier key does not match its certificate")
	}
	for _, f := range cfg.Flows {
		if f != authn.FlowQR && f != authn.FlowSameDevice {
			return nil, errors.New("eudi: unsupported flow " + f)
		}
	}
	if len(cfg.Flows) == 0 {
		return nil, errors.New("eudi: no flow enabled")
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "openid4vp://"
	}
	if cfg.TTL == 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.LongPoll == 0 {
		cfg.LongPoll = 10 * time.Second
	}
	return &Method{cfg: cfg}, nil
}

// Name implements authn.Method.
func (m *Method) Name() string { return "eudi" }

// Flows implements authn.Method.
func (m *Method) Flows() []string { return append([]string(nil), m.cfg.Flows...) }

// Demo implements authn.Method.
func (m *Method) Demo() bool { return m.cfg.IsDemo }

func random() string {
	b := make([]byte, 32)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// Start creates the request for one flow. CallbackURL is the bridge's
// response URI for this flow (…/wallet/response/{id}); the request URI is
// its …/wallet/request/{id} sibling.
func (m *Method) Start(_ context.Context, r authn.StartRequest) (authn.Pending, error) {
	if !contains(m.cfg.Flows, r.Flow) {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "flow not enabled"}
	}
	ru, err := url.Parse(r.CallbackURL)
	if err != nil || ru.Scheme != "https" || !strings.Contains(ru.Path, "/wallet/response/") {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "wallet login needs an https response URI"}
	}
	reqURI := strings.Replace(r.CallbackURL, "/wallet/response/", "/wallet/request/", 1)
	p := &pending{m: m, flow: r.Flow, responseURI: r.CallbackURL, requestURI: reqURI, state: random(), nonce: random(),
		issued: m.cfg.Verifier.Now(), done: make(chan struct{})}
	return p, nil
}

type pending struct {
	m                       *Method
	mu                      sync.Mutex
	flow                    string
	responseURI, requestURI string
	state, nonce            string
	issued                  time.Time
	final                   *authn.Result
	done                    chan struct{}
	// Same-device: a verified result held until the login browser returns
	// with responseCode (OpenID4VP response_code, red-team #2 F3).
	held         *authn.Result
	responseCode string
	bad          int // rejected wallet responses (red-team #2 F4)
}

// maxBadResponses ends a flow after this many rejected wallet responses;
// fewer leave it pending, so a stranger who saw the QR cannot end it with
// one junk post.
const maxBadResponses = 5

// ResponseCode returns the code the login browser must present after a
// verified same-device response, or "" if none is held.
func (p *pending) ResponseCode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held == nil || p.final != nil {
		return ""
	}
	return p.responseCode
}

func (p *pending) rejectLocked(err error) authn.Result {
	p.bad++
	if p.bad >= maxBadResponses {
		return p.finishLocked(authn.Result{Err: err})
	}
	return authn.Result{Waiting: "wallet", Err: err}
}

func (p *pending) link() string {
	q := url.Values{"client_id": {p.m.cfg.Identity.ClientID()}, "request_uri": {p.requestURI}}
	return p.m.cfg.Scheme + "?" + q.Encode()
}

func (p *pending) UI(time.Time) (authn.UI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.UI{}, errors.New("eudi: flow finished")
	}
	if p.flow == authn.FlowQR {
		return authn.UI{QRPayload: p.link()}, nil
	}
	return authn.UI{AppLink: p.link()}, nil
}

// RequestObject returns the signed authorization request (JAR) the wallet
// fetches from the request URI.
func (p *pending) RequestObject() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return "", errors.New("eudi: flow finished")
	}
	id := p.m.cfg.Identity
	var x5c []string
	for _, c := range id.Chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	var claims []map[string]any
	for _, c := range requestedClaims {
		claims = append(claims, map[string]any{"path": []string{c}})
	}
	now := p.m.cfg.Verifier.Now()
	ro := map[string]any{
		"iss": id.ClientID(), "aud": "https://self-issued.me/v2", "client_id": id.ClientID(),
		"response_type": "vp_token", "response_mode": "direct_post", "response_uri": p.responseURI,
		"nonce": p.nonce, "state": p.state, "iat": now.Unix(), "exp": p.issued.Add(p.m.cfg.TTL).Unix(),
		"dcql_query": map[string]any{"credentials": []map[string]any{{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": p.m.cfg.Verifier.VCTs}, "claims": claims}}},
		"client_metadata": map[string]any{"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{
			"sd-jwt_alg_values": []string{"ES256", "ES384", "ES512"}, "kb-jwt_alg_values": []string{"ES256", "ES384", "ES512"}}}},
	}
	return signES(id.Key, header{Alg: "ES256", Typ: "oauth-authz-req+jwt", X5C: x5c}, ro)
}

func (p *pending) finishLocked(r authn.Result) authn.Result {
	r.Done = true
	if r.Err != nil {
		r.Identity = nil
	}
	p.final = &r
	p.nonce, p.state, p.responseCode, p.held = "", "", "", nil
	close(p.done)
	return r
}

// Poll waits for the wallet's response.
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
	if p.m.cfg.Verifier.Now().Sub(p.issued) > p.m.cfg.TTL {
		r := p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "wallet request expired"}})
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
	return authn.Result{Waiting: "wallet"}
}

// Callback handles the wallet's direct_post response. The first response
// with the right state ends the flow, valid or not; a response with
// another state is ignored (it cannot belong to this request).
func (p *pending) Callback(ctx context.Context, q url.Values, _ []byte) authn.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final != nil {
		return authn.Result{Done: true, Err: &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "flow finished"}}
	}
	if rc, ok := q["response_code"]; ok {
		// Browser return of a same-device flow (the web layer passes only
		// this parameter, from the request carrying the flow cookie).
		if len(q) != 1 || len(rc) != 1 || p.held == nil || subtle.ConstantTimeCompare([]byte(rc[0]), []byte(p.responseCode)) != 1 {
			return p.rejectLocked(&authn.Error{Reason: authn.ReasonVerificationFailed, Detail: "response_code mismatch"})
		}
		return p.finishLocked(*p.held)
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.state)) != 1 || len(q["state"]) != 1 {
		return authn.Result{Waiting: "wallet", Err: &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "state does not match"}}
	}
	if p.m.cfg.Verifier.Now().Sub(p.issued) > p.m.cfg.TTL {
		return p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonExpired, Detail: "wallet request expired"}})
	}
	if p.held != nil {
		return authn.Result{Waiting: "browser", Err: &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "wallet already answered"}}
	}
	if e := q.Get("error"); e != "" {
		reason := authn.ReasonUpstreamError
		if e == "access_denied" {
			reason = authn.ReasonRefused
		}
		return p.finishLocked(authn.Result{Err: &authn.Error{Reason: reason, Detail: "wallet error response"}})
	}
	if len(q["vp_token"]) != 1 {
		return p.rejectLocked(vfail("vp_token missing or repeated"))
	}
	var vp map[string][]string
	if len(q.Get("vp_token")) > MaxPresentation || json.Unmarshal([]byte(q.Get("vp_token")), &vp) != nil || len(vp) != 1 || len(vp["pid"]) != 1 {
		return p.rejectLocked(vfail("vp_token must hold exactly one pid presentation"))
	}
	pres, err := p.m.cfg.Verifier.Verify(ctx, vp["pid"][0], p.nonce, p.m.cfg.Identity.ClientID())
	if err != nil {
		return p.rejectLocked(err)
	}
	id, err := identityFrom(pres)
	if err != nil {
		return p.finishLocked(authn.Result{Err: err})
	}
	if p.flow == authn.FlowSameDevice {
		p.held, p.responseCode = &authn.Result{Identity: id}, random()
		return authn.Result{Waiting: "browser"}
	}
	return p.finishLocked(authn.Result{Identity: id})
}

// identityFrom maps PID claims to an identity. Only requested claims are
// read (claim ceiling); a PID without a personal identifier and issuing
// country cannot give a stable subject.
func identityFrom(p *Presentation) (*authn.Identity, error) {
	str := func(k string) string { s, _ := p.Claims[k].(string); return s }
	code, country := str("personal_administrative_number"), strings.ToUpper(str("issuing_country"))
	if code == "" || len(code) > 64 || len(country) != 2 {
		return nil, &authn.Error{Reason: authn.ReasonAccountUnusable, Detail: "PID lacks a personal identifier or issuing country"}
	}
	id := &authn.Identity{Method: "eudi", AMR: []string{"eudi_pid"}, IDType: "PNO", Country: country, Code: code,
		GivenName: str("given_name"), FamilyName: str("family_name")}
	if b := str("birthdate"); b != "" {
		if _, err := time.Parse("2006-01-02", b); err == nil {
			id.Extra = map[string]string{"birthdate": b}
		}
	}
	return id, nil
}

func (p *pending) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.final == nil {
		p.finishLocked(authn.Result{Err: &authn.Error{Reason: authn.ReasonCancelled, Detail: "destroyed"}})
	}
}

// NewSelfSignedIdentity creates a demo verifier identity: a P-256 key and a
// self-signed certificate for host. Production uses a configured access
// certificate.
func NewSelfSignedIdentity(host string) (*VerifierIdentity, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: host + " (eidbridge demo verifier)"},
		DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	d, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, _ := x509.ParseCertificate(d)
	return &VerifierIdentity{Key: k, Chain: []*x509.Certificate{c}}, nil
}
