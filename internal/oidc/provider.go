// Package oidc is eidbridge's narrow OpenID Connect provider: authorization
// code flow with mandatory PKCE S256, static clients, single-use codes with
// replay revocation, sealed opaque access tokens and a userinfo endpoint.
// It imports only internal/authn for identities (FR-005). Out of scope by
// design: dynamic registration, refresh tokens, implicit and hybrid flows,
// logout, request objects and the claims parameter (ADR-008).
package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/jose"
	"github.com/tomkabel/eidbridge/internal/store"
)

var b64url = base64.RawURLEncoding

// Config configures the provider.
type Config struct {
	Issuer         string // exact issuer string (demo issuers end in /demo)
	Demo           bool
	Clients        []Client
	Keys           *KeySet
	Subjects       *Subjects
	AccessTokenTTL time.Duration // 1–300 s
	CodeTTL        time.Duration // ≤ 60 s
	ClockSkew      time.Duration // 0–120 s
	// MethodACR maps a method name to the acr value the operator can back
	// with evidence. Unmapped methods get "urn:eidbridge:acr:<method>",
	// which asserts only the method used. Demo always uses "demo".
	MethodACR map[string]string
	Methods   []string // enabled method names
	Clock     clock.Clock
	Codes     *store.Codes
	JTICap    int
}

// Provider serves the OIDC endpoints.
type Provider struct {
	cfg     Config
	clients map[string]*Client
	sealer  *Sealer
	jti     *jtiStore
	front   Frontend
	base    string // issuer path prefix
}

// Frontend is the login UI (internal/web). Begin starts a bound flow for a
// fully validated request; ErrorPage renders an error without redirecting.
type Frontend interface {
	Begin(w http.ResponseWriter, r *http.Request, req *AuthRequest)
	ErrorPage(w http.ResponseWriter, r *http.Request, status int, reason string)
}

// AuthRequest is a validated authorization request.
type AuthRequest struct {
	ClientID      string
	RedirectURI   string
	State         string
	Nonce         string
	CodeChallenge string
	Scopes        []string
	Methods       []string // methods allowed for this request, in order
	LoginHint     string
	UILocales     []string
	Prompt        string
	MaxAge        int // -1 when absent
}

// New validates cfg and builds a provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.Real()
	}
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || strings.HasSuffix(cfg.Issuer, "/") {
		return nil, errors.New("oidc: issuer must be an absolute URL without query, fragment or trailing slash")
	}
	if u.Scheme != "https" && !(cfg.Demo && u.Scheme == "http" && u.Hostname() == "localhost") {
		return nil, errors.New("oidc: issuer must be https (demo: http://localhost only)")
	}
	if cfg.Demo != strings.HasSuffix(u.Path, "/demo") {
		return nil, errors.New("oidc: demo issuers, and only demo issuers, use the /demo path")
	}
	if cfg.AccessTokenTTL < time.Second || cfg.AccessTokenTTL > 300*time.Second {
		return nil, errors.New("oidc: access_token_lifetime must be 1 to 300 seconds")
	}
	if cfg.CodeTTL <= 0 || cfg.CodeTTL > 60*time.Second {
		return nil, errors.New("oidc: code TTL must be at most 60 seconds")
	}
	if cfg.ClockSkew < 0 || cfg.ClockSkew > 120*time.Second {
		return nil, errors.New("oidc: clock skew must be 0 to 120 seconds")
	}
	if cfg.Keys == nil || cfg.Codes == nil || cfg.Subjects == nil || len(cfg.Methods) == 0 {
		return nil, errors.New("oidc: keys, subjects, code store and methods are required")
	}
	if err := cfg.Subjects.Validate(); err != nil {
		return nil, err
	}
	if err := validateClients(cfg.Clients, cfg.Demo); err != nil {
		return nil, err
	}
	for _, c := range cfg.Clients {
		if _, ok := cfg.Keys.Active(c.IDTokenAlg); !ok {
			return nil, fmt.Errorf("oidc: client %s uses %s but no active %s key is configured", c.ID, c.IDTokenAlg, c.IDTokenAlg)
		}
	}
	if cfg.JTICap == 0 {
		cfg.JTICap = 10000
	}
	s, err := NewSealer()
	if err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, clients: map[string]*Client{}, sealer: s, base: u.Path,
		jti: &jtiStore{cap: cfg.JTICap, m: map[string]time.Duration{}, clk: cfg.Clock}}
	for i := range cfg.Clients {
		p.clients[cfg.Clients[i].ID] = &cfg.Clients[i]
	}
	return p, nil
}

// SetFrontend attaches the login UI.
func (p *Provider) SetFrontend(f Frontend) { p.front = f }

// Issuer returns the issuer string.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// BasePath returns the issuer path prefix where endpoints are mounted.
func (p *Provider) BasePath() string { return p.base }

// Client returns a registered client.
func (p *Provider) Client(id string) (*Client, bool) { c, ok := p.clients[id]; return c, ok }

// Sealer exposes the access-token sealer (emergency K_at rotation).
func (p *Provider) Sealer() *Sealer { return p.sealer }

// Register mounts the endpoints on mux under the issuer path.
func (p *Provider) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+p.base+"/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET "+p.base+"/jwks.json", p.jwks)
	mux.HandleFunc(p.base+"/authorize", p.authorize)
	mux.HandleFunc(p.base+"/token", p.token)
	mux.HandleFunc(p.base+"/userinfo", p.userinfo)
}

func (p *Provider) acrFor(method string) string {
	if p.cfg.Demo {
		return "demo"
	}
	if v := p.cfg.MethodACR[method]; v != "" {
		return v
	}
	return "urn:eidbridge:acr:" + method
}

// ACRValuesSupported lists the acr values the bridge can prove.
func (p *Provider) ACRValuesSupported() []string {
	seen, out := map[string]bool{}, []string{}
	for _, m := range p.cfg.Methods {
		if a := p.acrFor(m); !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	iss := p.cfg.Issuer
	doc := map[string]any{
		"issuer":                                           iss,
		"authorization_endpoint":                           iss + "/authorize",
		"token_endpoint":                                   iss + "/token",
		"userinfo_endpoint":                                iss + "/userinfo",
		"jwks_uri":                                         iss + "/jwks.json",
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query"},
		"grant_types_supported":                            []string{"authorization_code"},
		"subject_types_supported":                          []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported":            p.algs(),
		"token_endpoint_auth_methods_supported":            []string{AuthBasic, AuthPost, AuthPrivKey},
		"token_endpoint_auth_signing_alg_values_supported": []string{jose.RS256, jose.ES256},
		"scopes_supported":                                 []string{"openid", "profile", "personal_code"},
		"claims_supported":                                 ClaimNames(),
		"code_challenge_methods_supported":                 []string{"S256"},
		"acr_values_supported":                             p.ACRValuesSupported(),
		"authorization_response_iss_parameter_supported":   true,
		"claims_parameter_supported":                       false,
		"request_parameter_supported":                      false,
		"request_uri_parameter_supported":                  false,
		"require_request_uri_registration":                 false,
		"prompt_values_supported":                          []string{"none", "login"},
		"ui_locales_supported":                             []string{"en", "et", "lv", "lt", "ru"},
		"claims_locales_supported":                         []string{"en"},
	}
	writeJSON(w, http.StatusOK, doc, false)
}

func (p *Provider) algs() []string {
	out := []string{jose.RS256}
	if _, ok := p.cfg.Keys.Active(jose.ES256); ok {
		out = append(out, jose.ES256)
	}
	return out
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": p.cfg.Keys.JWKS()}, false)
}

// ClaimNames lists every claim the provider can emit. docs/data-flow.md is
// checked against this list in CI.
func ClaimNames() []string {
	return []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "country", "eid_method",
		"eid_env", "given_name", "family_name", "personal_code", "previous_sub", "birthdate"}
}

func writeJSON(w http.ResponseWriter, status int, v any, noStore bool) {
	w.Header().Set("Content-Type", "application/json")
	if noStore {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type oauthError struct {
	Status     int
	Code, Desc string
	RetryAfter int
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Desc }

func oauthErr(status int, code, desc string) *oauthError {
	return &oauthError{Status: status, Code: code, Desc: desc}
}

func (p *Provider) writeOAuthErr(w http.ResponseWriter, err error) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		oe = oauthErr(400, "invalid_request", "invalid request")
	}
	if oe.Status == 401 {
		w.Header().Set("WWW-Authenticate", `Basic realm="eidbridge"`)
	}
	if oe.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(oe.RetryAfter))
	}
	writeJSON(w, oe.Status, map[string]string{"error": oe.Code, "error_description": oe.Desc}, true)
}

var unreservedRe = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// params returns single-valued parameters from the query or the form; a
// repeated parameter is reported.
func params(r *http.Request) (url.Values, string, error) {
	var v url.Values
	switch r.Method {
	case http.MethodGet:
		v = r.URL.Query()
	case http.MethodPost:
		r.Body = http.MaxBytesReader(nil, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			return nil, "", err
		}
		v = r.PostForm
	default:
		return nil, "", errors.New("method not allowed")
	}
	for k, vals := range v {
		if len(vals) > 1 {
			return v, k, nil
		}
	}
	return v, "", nil
}

// CodeTTL is the authorization-code lifetime.
func (p *Provider) CodeTTL() time.Duration { return p.cfg.CodeTTL }

// ErrorRedirect builds an error response to a validated redirect URI with
// state and iss (RFC 9207).
func (p *Provider) ErrorRedirect(redirectURI, state, code string) string {
	q := url.Values{"error": {code}, "iss": {p.cfg.Issuer}}
	if state != "" {
		q.Set("state", state)
	}
	return appendQuery(redirectURI, q)
}

func appendQuery(base string, q url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode()
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	setPageHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	v, repeated, err := params(r)
	if err != nil {
		p.errorPage(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	// Client and redirect URI first: never redirect before both validate.
	if repeated == "client_id" || repeated == "redirect_uri" {
		p.errorPage(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	c, ok := p.clients[v.Get("client_id")]
	if !ok {
		p.errorPage(w, r, http.StatusBadRequest, "invalid_client")
		return
	}
	redirect := v.Get("redirect_uri")
	if !contains(c.RedirectURIs, redirect) {
		p.errorPage(w, r, http.StatusBadRequest, "invalid_redirect_uri")
		return
	}
	state := v.Get("state")
	fail := func(code string) {
		st := state
		if !unreservedRe.MatchString(st) || len(st) > 512 {
			st = ""
		}
		http.Redirect(w, r, p.ErrorRedirect(redirect, st, code), http.StatusSeeOther)
	}
	if repeated != "" {
		fail("invalid_request")
		return
	}
	if v.Get("response_type") != "code" {
		fail("unsupported_response_type")
		return
	}
	if v.Has("request") {
		fail("request_not_supported")
		return
	}
	if v.Has("request_uri") {
		fail("request_uri_not_supported")
		return
	}
	if v.Has("claims") {
		fail("invalid_request")
		return
	}
	if rm := v.Get("response_mode"); rm != "" && rm != "query" {
		fail("invalid_request")
		return
	}
	scopes := strings.Fields(v.Get("scope"))
	if !contains(scopes, "openid") || (contains(scopes, "personal_code") && !c.PersonalCode) {
		fail("invalid_scope")
		return
	}
	nonce := v.Get("nonce")
	if !unreservedRe.MatchString(state) || len(state) > 512 || !unreservedRe.MatchString(nonce) || len(nonce) > 512 {
		fail("invalid_request")
		return
	}
	cc := v.Get("code_challenge")
	if v.Get("code_challenge_method") != "S256" || len(cc) != 43 || !unreservedRe.MatchString(cc) {
		fail("invalid_request")
		return
	}
	prompt := strings.Fields(v.Get("prompt"))
	if contains(prompt, "none") {
		if len(prompt) > 1 {
			fail("invalid_request")
		} else {
			fail("login_required") // the bridge keeps no sessions
		}
		return
	}
	maxAge := -1
	if ma := v.Get("max_age"); ma != "" {
		n, err := strconv.Atoi(ma)
		if err != nil || n < 0 {
			fail("invalid_request")
			return
		}
		maxAge = n // always met: every login is fresh and auth_time is set
	}
	methods := p.methodsFor(c, strings.Fields(v.Get("acr_values")))
	if len(methods) == 0 {
		fail("unmet_authentication_requirements")
		return
	}
	req := &AuthRequest{ClientID: c.ID, RedirectURI: redirect, State: state, Nonce: nonce, CodeChallenge: cc,
		Scopes: dedupe(scopes), Methods: methods, LoginHint: v.Get("login_hint"),
		UILocales: strings.Fields(v.Get("ui_locales")), MaxAge: maxAge}
	if contains(prompt, "login") {
		req.Prompt = "login"
	}
	if p.front == nil {
		p.errorPage(w, r, http.StatusServiceUnavailable, "server_error")
		return
	}
	p.front.Begin(w, r, req)
}

// methodsFor applies the client's allowed methods and the acr_values
// filter: only methods whose acr the bridge can prove for a requested value
// remain, so assurance is never silently downgraded.
func (p *Provider) methodsFor(c *Client, acrValues []string) []string {
	var out []string
	for _, m := range p.cfg.Methods {
		if len(c.AllowedMethods) > 0 && !contains(c.AllowedMethods, m) {
			continue
		}
		if len(acrValues) > 0 && !contains(acrValues, p.acrFor(m)) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (p *Provider) errorPage(w http.ResponseWriter, r *http.Request, status int, reason string) {
	if p.front != nil {
		p.front.ErrorPage(w, r, status, reason)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	template.Must(template.New("e").Parse(`<!doctype html><title>Error</title><p>{{.}}</p>`)).Execute(w, reason)
}

// setPageHeaders applies the HTML security headers (threat model).
func setPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func dedupe(xs []string) []string {
	seen, out := map[string]bool{}, []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// codeBinding is stored with a code and checked at exchange.
type codeBinding struct {
	ClientID, RedirectURI, Challenge string
}

// claimSet is the plaintext claim set held, keyed by code hash, until
// exchange or code expiry (A01).
type claimSet struct {
	ID       map[string]any // ID token claims (without iss/aud/exp/iat)
	UserInfo map[string]any
	Scopes   []string
}

// Reserve reserves a code slot for a new flow (E05).
func (p *Provider) Reserve(flowTTL time.Duration) (*store.Reservation, error) {
	return p.cfg.Codes.Reserve(flowTTL)
}

// Complete issues a code for a verified identity and returns the client
// redirect URL (code, state, iss).
func (p *Provider) Complete(req *AuthRequest, res *store.Reservation, id *authn.Identity, authTime time.Time) (string, error) {
	c := p.clients[req.ClientID]
	if c == nil || id == nil || !contains(req.Methods, id.Method) {
		return "", errors.New("oidc: identity method not allowed for this request")
	}
	sub, err := p.cfg.Subjects.Sub(p.cfg.Subjects.Current, c.sector(), id.IDType, id.Country, id.Code)
	if err != nil {
		return "", err
	}
	idc := map[string]any{"sub": sub, "auth_time": authTime.Unix(), "nonce": req.Nonce, "acr": p.acrFor(id.Method),
		"amr": id.AMR, "country": id.Country, "eid_method": id.Method}
	ui := map[string]any{"sub": sub, "country": id.Country, "eid_method": id.Method}
	if p.cfg.Demo {
		idc["eid_env"], ui["eid_env"] = "demo", "demo"
	}
	if m := p.cfg.Subjects.Migration; m.Active(p.cfg.Clock.Now()) {
		if oldSector, ok := m.Clients[c.ID]; ok {
			if prev, err := p.cfg.Subjects.Sub(m.From, oldSector, id.IDType, id.Country, id.Code); err == nil && prev != sub {
				idc["previous_sub"] = prev
			}
		}
	}
	if contains(req.Scopes, "profile") {
		for k, val := range map[string]string{"given_name": id.GivenName, "family_name": id.FamilyName} {
			if val != "" {
				idc[k], ui[k] = val, val
			}
		}
		if bd := id.Extra["birthdate"]; bd != "" {
			idc["birthdate"], ui["birthdate"] = bd, bd
		}
	}
	if contains(req.Scopes, "personal_code") && c.PersonalCode {
		pc := id.IDType + id.Country + "-" + id.Code
		idc["personal_code"], ui["personal_code"] = pc, pc
	}
	code, err := res.Issue(&claimSet{ID: idc, UserInfo: ui, Scopes: req.Scopes},
		codeBinding{ClientID: c.ID, RedirectURI: req.RedirectURI, Challenge: req.CodeChallenge})
	if err != nil {
		return "", err
	}
	q := url.Values{"code": {code}, "state": {req.State}, "iss": {p.cfg.Issuer}}
	return appendQuery(req.RedirectURI, q), nil
}

var errPKCE = oauthErr(400, "invalid_grant", "PKCE verification failed")

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		p.writeOAuthErr(w, oauthErr(405, "invalid_request", "POST required"))
		return
	}
	v, repeated, err := params(r)
	if err != nil || repeated != "" {
		p.writeOAuthErr(w, oauthErr(400, "invalid_request", "malformed or repeated parameters"))
		return
	}
	if r.URL.RawQuery != "" {
		p.writeOAuthErr(w, oauthErr(400, "invalid_request", "parameters belong in the body"))
		return
	}
	if v.Get("grant_type") != "authorization_code" {
		p.writeOAuthErr(w, oauthErr(400, "unsupported_grant_type", "authorization_code only"))
		return
	}
	code := v.Get("code")
	verifier := v.Get("code_verifier")
	c, authErr := p.authenticateClient(r)
	// The code is consumed even when client authentication, PKCE or the
	// redirect URI fail (NFR-005, E08): a failed exchange leaves a
	// familyless tombstone, and a later presentation of a successfully
	// exchanged code revokes its family.
	var bindErr error
	grant, xerr := p.cfg.Codes.Exchange(code, func(b any) error {
		cb := b.(codeBinding)
		if authErr != nil {
			bindErr = authErr
			return authErr
		}
		if subtle.ConstantTimeCompare([]byte(cb.ClientID), []byte(c.ID)) != 1 {
			// Same answer as an unknown code: do not confirm the code exists.
			bindErr = oauthErr(400, "invalid_grant", "invalid, expired or used code")
			return bindErr
		}
		if v.Get("redirect_uri") != cb.RedirectURI {
			bindErr = oauthErr(400, "invalid_grant", "redirect_uri mismatch")
			return bindErr
		}
		if len(verifier) < 43 || len(verifier) > 128 || !unreservedRe.MatchString(verifier) {
			bindErr = errPKCE
			return bindErr
		}
		sum := sha256.Sum256([]byte(verifier))
		if subtle.ConstantTimeCompare([]byte(b64url.EncodeToString(sum[:])), []byte(cb.Challenge)) != 1 {
			bindErr = errPKCE
			return bindErr
		}
		return nil
	})
	if xerr != nil {
		switch {
		case bindErr != nil:
			p.writeOAuthErr(w, bindErr)
		case authErr != nil:
			p.writeOAuthErr(w, authErr)
		default:
			p.writeOAuthErr(w, oauthErr(400, "invalid_grant", "invalid, expired or used code"))
		}
		return
	}
	cs := grant.Claims.(*claimSet)
	now := p.cfg.Clock.Now()
	life := p.cfg.AccessTokenTTL
	at, err := p.sealer.seal(sealedPayload{ClientID: c.ID, Family: grant.Family, Deadline: int64(p.cfg.Clock.Mono() + life),
		IAT: now.Unix(), EXP: now.Add(life).Unix(), Claims: cs.UserInfo, Scope: cs.Scopes})
	if err != nil {
		p.writeOAuthErr(w, oauthErr(500, "server_error", "token sealing failed"))
		return
	}
	idc := map[string]any{}
	for k, val := range cs.ID {
		idc[k] = val
	}
	idc["iss"], idc["aud"], idc["iat"], idc["exp"] = p.cfg.Issuer, c.ID, now.Unix(), now.Add(life).Unix()
	k, ok := p.cfg.Keys.Active(c.IDTokenAlg)
	if !ok {
		p.writeOAuthErr(w, oauthErr(500, "server_error", "no signing key"))
		return
	}
	idt, err := jose.Sign(k, "JWT", idc)
	if err != nil {
		p.writeOAuthErr(w, oauthErr(500, "server_error", "signing failed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": at, "token_type": "Bearer",
		"expires_in": int(life / time.Second), "id_token": idt, "scope": strings.Join(cs.Scopes, " ")}, true)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bad := func() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"}, true)
	}
	// Bearer token in the Authorization header only (RFC 9700 §4.3.2).
	if r.URL.Query().Has("access_token") {
		bad()
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ParseForm() == nil && r.PostForm.Has("access_token") {
			bad()
			return
		}
	}
	h := r.Header.Get("Authorization")
	// The scheme name is case-insensitive (RFC 9110 §11.1).
	tok, ok := "", len(h) > 7 && strings.EqualFold(h[:7], "Bearer ")
	if ok {
		tok = h[7:]
	}
	if !ok || tok == "" {
		bad()
		return
	}
	pl, err := p.sealer.open(tok)
	if err != nil || checkLifetime(pl, p.cfg.AccessTokenTTL, p.cfg.Clock.Now(), p.cfg.Clock.Mono()) != nil ||
		!p.cfg.Codes.FamilyActive(pl.Family) || p.clients[pl.ClientID] == nil {
		bad()
		return
	}
	writeJSON(w, http.StatusOK, pl.Claims, true)
}
