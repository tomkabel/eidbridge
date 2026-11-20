// Package web serves the login pages and drives method flows. It is the
// oidc.Frontend: every flow is bound to one validated authorize request, one
// browser cookie, one reserved code slot and at most one upstream session.
// It imports internal/authn only; no method package (FR-005).
package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/oidc"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Config configures the web layer. Every numeric value is validated at
// startup by internal/config (ADR-008 bounds).
type Config struct {
	Provider       *oidc.Provider
	Registry       *authn.Registry
	Clock          clock.Clock
	Log            *slog.Logger
	PublicOrigin   string // scheme://host[:port] of the bridge
	Demo           bool
	FlowTTL        time.Duration // flow timeout; absolute deadline adds 30 s
	MaxFlows       int           // pending-flow ceiling (NFR-003 default 10,000)
	PollSlots      int           // upstream concurrency; ≤ MaxFlows
	UpstreamRate   Bucket        // global upstream request rate
	PerIP          Bucket
	PerClient      Bucket
	PerTarget      Bucket // notification targets
	BucketCap      int
	RetryAttempts  int
	RetryBase      time.Duration
	TrustedProxies []netip.Prefix
	DefaultLocale  string
	TargetKey      []byte // process key for notification target HMAC (not K_sub)
	RememberMethod bool   // opt-in chooser preference cookie (Story 4.1)
	LongPollGap    time.Duration
}

// Server implements oidc.Frontend and the flow endpoints.
type Server struct {
	cfg       Config
	flows     *flows
	ipB       *buckets
	clientB   *buckets
	targetB   *buckets
	upstreamB *buckets
	slots     chan struct{}
	draining  atomic.Bool
	tmpl      *template.Template
	base      string
	proxyWarn sync.Once
	peers     atomic.Int64
	privPeers atomic.Int64
	stop      chan struct{}
	wg        sync.WaitGroup
}

// New builds the server and starts the expiry sweeper.
func New(cfg Config) (*Server, error) {
	if cfg.Provider == nil || cfg.Registry == nil {
		return nil, errors.New("web: provider and registry are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real()
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.PollSlots <= 0 || cfg.PollSlots > cfg.MaxFlows {
		return nil, errors.New("web: poll slots must be between 1 and the pending-flow ceiling")
	}
	if len(cfg.TargetKey) < 32 {
		return nil, errors.New("web: target key must be at least 32 bytes")
	}
	if cfg.DefaultLocale == "" {
		cfg.DefaultLocale = "en"
	}
	if cfg.LongPollGap == 0 {
		cfg.LongPollGap = 250 * time.Millisecond
	}
	t, err := template.New("").Funcs(template.FuncMap{}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, flows: newFlows(cfg.MaxFlows), tmpl: t, base: cfg.Provider.BasePath(),
		ipB: newBuckets(cfg.PerIP, cfg.BucketCap, cfg.Clock), clientB: newBuckets(cfg.PerClient, cfg.BucketCap, cfg.Clock),
		targetB: newBuckets(cfg.PerTarget, cfg.BucketCap, cfg.Clock), upstreamB: newBuckets(cfg.UpstreamRate, 1, cfg.Clock),
		slots: make(chan struct{}, cfg.PollSlots), stop: make(chan struct{})}
	s.wg.Add(1)
	go s.sweeper()
	return s, nil
}

// Close stops background goroutines and cancels every pending flow.
func (s *Server) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	for _, f := range s.flows.all() {
		f.mu.Lock()
		s.finishLocked(f, StateCancelled, authn.ReasonCancelled, nil)
		f.mu.Unlock()
	}
	s.wg.Wait()
}

// Register mounts flow endpoints, static assets and health probes.
func (s *Server) Register(mux *http.ServeMux) {
	b := s.base
	// Every flow response, redirects included, carries the page security
	// headers; the callback URL holds the upstream session secret digest
	// (red-team finding F2).
	h := func(pattern string, fn http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			securityHeaders(w)
			fn(w, r)
		})
	}
	h("GET "+b+"/flow/{id}", s.page)
	h("POST "+b+"/flow/{id}/start", s.start)
	h("GET "+b+"/flow/{id}/qr.png", s.qr)
	h("GET "+b+"/flow/{id}/status", s.status)
	h("POST "+b+"/flow/{id}/cancel", s.cancelFlow)
	h("GET "+b+"/flow/{id}/continue", s.continueFlow)
	h("POST "+b+"/flow/{id}/browser", s.browserResult)
	h("GET "+b+"/flow/callback", s.callback)
	h("POST "+b+"/wallet/response/{id}", s.walletResponse)
	h("GET "+b+"/wallet/request/{id}", s.walletRequest)
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET "+b+"/static/", http.StripPrefix(b+"/static/", s.staticHandler(http.FileServer(http.FS(static)))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.readyz)
}

func (s *Server) staticHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// readyz covers configuration and key load only: saturation never makes it
// fail; only a SIGTERM drain does (ADR-009).
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "draining\n", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}

// Drain stops new authorizations, QR page loads, polling and callbacks for
// new verifications. Token and userinfo keep serving.
func (s *Server) Drain() { s.draining.Store(true) }

// Draining reports drain state.
func (s *Server) Draining() bool { return s.draining.Load() }

// FlowCount returns the number of stored flows.
func (s *Server) FlowCount() int { return s.flows.Len() }

func securityHeaders(w http.ResponseWriter) { securityHeadersFor(w, "") }

// securityHeadersFor sets the page headers. formOrigin, when not empty, is
// added to form-action: browsers check form-action on every redirect after
// a form POST, and cancel and browser-result submissions end in a 303 to
// the client's redirect_uri.
func securityHeadersFor(w http.ResponseWriter, formOrigin string) {
	h := w.Header()
	fa := "'self'"
	if formOrigin != "" {
		fa += " " + formOrigin
	}
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action "+fa+"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
}

func busy(w http.ResponseWriter, retry int) {
	securityHeaders(w)
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	http.Error(w, "The service is busy. Try again shortly.", http.StatusServiceUnavailable)
}

func (s *Server) noteProxy(r *http.Request) {
	if len(s.cfg.TrustedProxies) > 0 {
		return
	}
	n := s.peers.Add(1)
	if isPrivatePeer(r) {
		s.privPeers.Add(1)
	}
	if n == 20 && s.privPeers.Load() == n {
		s.proxyWarn.Do(func() {
			s.cfg.Log.Warn("all early requests come from private or load-balancer peers but trusted_proxies is empty; per-IP limits apply to the proxy address")
		})
	}
}

// ---- oidc.Frontend --------------------------------------------------------

// Begin admits a flow for a validated authorize request.
func (s *Server) Begin(w http.ResponseWriter, r *http.Request, req *oidc.AuthRequest) {
	s.noteProxy(r)
	if s.draining.Load() {
		busy(w, 30)
		return
	}
	// The per-client bucket is charged only after client and redirect URI
	// validated (done by the provider).
	if ok, _ := s.clientB.allow(req.ClientID); !ok {
		busy(w, 5)
		return
	}
	ip := clientIP(r, s.cfg.TrustedProxies)
	if ok, _ := s.ipB.allow(ip); !ok {
		busy(w, 5)
		return
	}
	id := randToken(16)
	binding := randToken(32)
	now := s.cfg.Clock.Mono()
	cv, fits := encodeCookie(cookieValue{B: binding, T: s.cfg.Clock.Now().Unix(), C: req.ClientID, R: req.RedirectURI, S: req.State})
	if !fits {
		http.Redirect(w, r, s.cfg.Provider.ErrorRedirect(req.RedirectURI, req.State, "invalid_request"), http.StatusSeeOther)
		return
	}
	life := s.cfg.FlowTTL + 30*time.Second
	res, err := s.cfg.Provider.Reserve(life)
	if err != nil {
		busy(w, 5)
		return
	}
	f := &flow{id: id, binding: hashOf(binding), created: now, deadline: now + life, startBy: now + 60*time.Second,
		req: req, res: res, state: StateCreated, lang: s.locale(r, req.UILocales), clientIP: ip, createdAt: s.cfg.Clock.Now()}
	if !s.flows.admit(f) {
		res.Release()
		busy(w, 5)
		return
	}
	s.reconcileCookies(w, r, f)
	setFlowCookie(w, id, cv, life)
	http.Redirect(w, r, s.base+"/flow/"+id, http.StatusSeeOther)
}

// reconcileCookies enforces at most four live flow cookies per browser: the
// new flow already holds its capacity; the oldest matching nonterminal flows
// are cancelled. Racing completion keeps issued codes (verified flows are
// terminal and never cancelled).
func (s *Server) reconcileCookies(w http.ResponseWriter, r *http.Request, nf *flow) {
	type live struct {
		f  *flow
		at time.Duration
	}
	var ls []live
	for id, cv := range flowCookies(r) {
		f := s.flows.get(id)
		if f == nil {
			clearFlowCookie(w, id)
			continue
		}
		f.mu.Lock()
		if eq(f.binding, hashOf(cv.B)) && !terminal(f.state) {
			ls = append(ls, live{f, f.created})
		}
		f.mu.Unlock()
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].at < ls[j].at })
	for i := 0; len(ls)-i >= 4; i++ {
		f := ls[i].f
		f.mu.Lock()
		if !terminal(f.state) {
			s.finishLocked(f, StateCancelled, authn.ReasonCancelled, nil)
			s.flows.remove(f)
		}
		f.mu.Unlock()
		clearFlowCookie(w, f.id)
	}
}

// ErrorPage renders an error without redirecting.
func (s *Server) ErrorPage(w http.ResponseWriter, r *http.Request, status int, reason string) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	lang := s.locale(r, nil)
	s.tmpl.ExecuteTemplate(w, "error.html", s.pageData(lang, nil, map[string]any{"Reason": reason}))
}

// ---- flow access ----------------------------------------------------------

type access int

const (
	accessNone access = iota
	accessCurrent
	accessRetired
)

// lookup finds the flow and checks the cookie binding in constant time.
func (s *Server) lookup(r *http.Request) (*flow, access, *cookieValue) {
	id := r.PathValue("id")
	c, err := r.Cookie(cookiePrefix + id)
	var cv *cookieValue
	if err == nil {
		if v, ok := decodeCookie(c.Value); ok {
			cv = &v
		}
	}
	f := s.flows.get(id)
	if f == nil || cv == nil {
		return f, accessNone, cv
	}
	h := hashOf(cv.B)
	f.mu.Lock()
	defer f.mu.Unlock()
	if eq(f.binding, h) {
		return f, accessCurrent, cv
	}
	for _, rh := range f.retired {
		if eq(rh, h) {
			return f, accessRetired, cv
		}
	}
	return f, accessNone, cv
}

// restart renders the restart page with no state change.
func (s *Server) restart(w http.ResponseWriter, r *http.Request, msg string) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	s.tmpl.ExecuteTemplate(w, "restart.html", s.pageData(s.locale(r, nil), nil, map[string]any{"Message": msg}))
}

// unknownFlow handles a lost handle after restart: a stable error page via a
// redirect with access_denied to the redirect URI recovered from the cookie
// and revalidated against the static registry (E20).
func (s *Server) unknownFlow(w http.ResponseWriter, r *http.Request, cv *cookieValue) {
	id := r.PathValue("id")
	if cv != nil {
		if c, ok := s.cfg.Provider.Client(cv.C); ok {
			for _, u := range c.RedirectURIs {
				if u == cv.R {
					clearFlowCookie(w, id)
					securityHeaders(w)
					http.Redirect(w, r, s.cfg.Provider.ErrorRedirect(cv.R, cv.S, "access_denied"), http.StatusSeeOther)
					return
				}
			}
		}
	}
	s.restart(w, r, "restart")
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	f, acc, cv := s.lookup(r)
	if f == nil {
		s.unknownFlow(w, r, cv)
		return
	}
	if acc == accessRetired {
		s.render(w, r, f, "othertab.html", nil)
		return
	}
	if acc != accessCurrent {
		s.restart(w, r, "restart")
		return
	}
	if l := r.URL.Query().Get("lang"); l != "" && catalogs[l] != nil {
		f.mu.Lock()
		f.lang = l
		f.mu.Unlock()
	}
	f.mu.Lock()
	state := f.state
	f.mu.Unlock()
	switch {
	case state == StateCreated:
		if s.draining.Load() {
			busy(w, 30)
			return
		}
		s.render(w, r, f, "choose.html", s.chooseData(f, r))
	case state == StatePending:
		s.render(w, r, f, "pending.html", nil)
	default:
		s.render(w, r, f, "outcome.html", nil)
	}
}

func (s *Server) formToken(f *flow) string {
	m := hmac.New(sha256.New, s.cfg.TargetKey)
	m.Write([]byte("form|" + f.id))
	m.Write(f.binding[:])
	return b64(m.Sum(nil))
}

// start fixes the offered flow and creates the upstream session (exactly
// once, under the flow lock).
func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	f, acc, cv := s.lookup(r)
	if f == nil {
		s.unknownFlow(w, r, cv)
		return
	}
	if acc != accessCurrent || r.ParseForm() != nil || !hmac.Equal([]byte(r.PostForm.Get("ft")), []byte(s.formToken(f))) {
		s.restart(w, r, "restart")
		return
	}
	if s.draining.Load() {
		busy(w, 30)
		return
	}
	methodName, flowName := r.PostForm.Get("method"), r.PostForm.Get("flow")
	m, ok := s.cfg.Registry.Get(methodName)
	if !ok || !contains(f.req.Methods, methodName) || !contains(s.offeredFlows(m), flowName) {
		s.restart(w, r, "restart")
		return
	}
	input := map[string]string{}
	if flowName == authn.FlowNotification {
		country := strings.ToUpper(strings.TrimSpace(r.PostForm.Get("country")))
		code := strings.TrimSpace(r.PostForm.Get("personal_code"))
		phone := strings.TrimSpace(r.PostForm.Get("phone"))
		input = map[string]string{"country": country, "personal_code": code, "phone": phone}
		// Per-target bucket keyed by an HMAC of the normalized target under a
		// separate process key, charged even when denied; unseen targets at
		// capacity get 503 and no push.
		tm := hmac.New(sha256.New, s.cfg.TargetKey)
		tm.Write([]byte("target|" + methodName + "|" + country + "|" + code + "|" + phone))
		okT, full := s.targetB.allow(b64(tm.Sum(nil)))
		if full {
			busy(w, 30)
			return
		}
		okIP, _ := s.ipB.allow("notify|" + clientIP(r, s.cfg.TrustedProxies))
		if !okT || !okIP {
			s.render(w, r, f, "choose.html", s.chooseDataErr(f, r, "rate_limited"))
			return
		}
	}
	f.mu.Lock()
	if f.state != StateCreated {
		f.mu.Unlock()
		http.Redirect(w, r, s.base+"/flow/"+f.id, http.StatusSeeOther)
		return
	}
	// One poll slot per pending flow; none free → 503, flow stays created.
	select {
	case s.slots <- struct{}{}:
	default:
		f.mu.Unlock()
		busy(w, 5)
		return
	}
	f.slot = true
	sr := authn.StartRequest{Flow: flowName, Lang: f.lang, Origin: s.cfg.PublicOrigin, Input: input, ClientID: f.req.ClientID}
	var cbValue string
	if flowName == authn.FlowSameDevice && m.Name() == "smartid" {
		cbValue = randToken(16)
		sr.CallbackURL = s.cfg.PublicOrigin + s.base + "/flow/callback?value=" + cbValue
	} else if m.Name() == "eudi" {
		// The wallet posts its response here and fetches the request object
		// from the sibling /wallet/request/{id}; it has no flow cookie.
		sr.CallbackURL = s.cfg.PublicOrigin + s.base + "/wallet/response/" + f.id
	}
	remaining := f.deadline - s.cfg.Clock.Mono()
	ctx, cancel := context.WithTimeout(context.Background(), min(remaining, 20*time.Second))
	p, err := m.Start(ctx, sr)
	cancel()
	if err != nil {
		reason := authn.ReasonOf(err)
		if reason == authn.ReasonInvalidInput {
			<-s.slots
			f.slot = false
			f.mu.Unlock()
			s.render(w, r, f, "choose.html", s.chooseDataErr(f, r, "invalid_input"))
			return
		}
		s.finishLocked(f, StateFailed, reason, nil)
		f.mu.Unlock()
		http.Redirect(w, r, s.base+"/flow/"+f.id, http.StatusSeeOther)
		return
	}
	f.method, f.offered, f.pending, f.state = methodName, flowName, p, StatePending
	s.cfg.Log.Debug("flow started", "method", methodName, "flow", flowName, "lang", f.lang)
	if cbValue != "" {
		f.callback = hashOf(cbValue)
		s.flows.indexCallback(f.callback, f.id)
	}
	pctx, pcancel := context.WithCancel(context.Background())
	f.cancel = pcancel
	f.mu.Unlock()
	if s.cfg.RememberMethod && r.PostForm.Get("remember") == "on" {
		http.SetCookie(w, &http.Cookie{Name: "__Host-eidb-method", Value: methodName, Path: "/", MaxAge: 30 * 24 * 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	s.wg.Add(1)
	go s.poll(pctx, f)
	http.Redirect(w, r, s.base+"/flow/"+f.id, http.StatusSeeOther)
}

// offeredFlows filters method flows: same-device and browser need an
// HTTPS origin.
func (s *Server) offeredFlows(m authn.Method) []string {
	var out []string
	for _, fl := range m.Flows() {
		if (fl == authn.FlowSameDevice || fl == authn.FlowBrowser) && !strings.HasPrefix(s.cfg.PublicOrigin, "https://") {
			continue
		}
		out = append(out, fl)
	}
	return out
}

// poll is the server-side poller for one pending flow. It holds the flow's
// poll slot; the browser reads only local status.
func (s *Server) poll(ctx context.Context, f *flow) {
	defer s.wg.Done()
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		default:
		}
		if s.draining.Load() {
			return // no new verification during a drain; the flow expires
		}
		f.mu.Lock()
		if terminal(f.state) {
			f.mu.Unlock()
			return
		}
		p, remaining := f.pending, f.deadline-s.cfg.Clock.Mono()
		f.mu.Unlock()
		if remaining <= 0 {
			s.expire(f)
			return
		}
		if ok, _ := s.upstreamB.allow("upstream"); !ok {
			sleepCtx(ctx, 100*time.Millisecond)
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, remaining)
		res := p.Poll(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		s.cfg.Log.Debug("upstream poll", "done", res.Done, "waiting", res.Waiting, "err", res.Err)
		if res.Done {
			s.applyResult(f, res)
			return
		}
		f.mu.Lock()
		f.waiting = res.Waiting
		f.mu.Unlock()
		if res.Err != nil {
			attempts++
			if attempts > s.cfg.RetryAttempts {
				f.mu.Lock()
				s.finishLocked(f, StateFailed, authn.ReasonRetriesExhausted, nil)
				f.mu.Unlock()
				return
			}
			var ae *authn.Error
			d := s.cfg.RetryBase << (attempts - 1)
			if errors.As(res.Err, &ae) && ae.RetryIn > d {
				d = ae.RetryIn
			}
			sleepCtx(ctx, d)
			continue
		}
		attempts = 0
		if res.Waiting == "callback" {
			sleepCtx(ctx, s.cfg.LongPollGap)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (s *Server) expire(f *flow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !terminal(f.state) {
		s.finishLocked(f, StateExpired, authn.ReasonExpired, nil)
	}
}

// applyResult moves a pending flow to its terminal state. A late result for
// a terminal flow is discarded and its secrets destroyed.
func (s *Server) applyResult(f *flow, res authn.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.applyLocked(f, res)
}

func (s *Server) applyLocked(f *flow, res authn.Result) {
	if terminal(f.state) {
		if f.pending != nil {
			f.pending.Destroy()
		}
		s.cfg.Log.Debug("late result discarded", "reason_code", "late_result")
		return
	}
	if res.Err == nil && res.Identity != nil {
		u, err := s.cfg.Provider.Complete(f.req, f.res, res.Identity, s.cfg.Clock.Now())
		if err != nil {
			s.finishLocked(f, StateFailed, authn.ReasonUpstreamError, nil)
			return
		}
		f.redirect = u
		f.codeUntil = s.cfg.Clock.Mono() + s.cfg.Provider.CodeTTL()
		f.state, f.reason = StateVerified, ""
		s.releaseLocked(f, false)
		return
	}
	switch authn.ReasonOf(res.Err) {
	case authn.ReasonRefused:
		s.finishLocked(f, StateRefused, authn.ReasonRefused, nil)
	case authn.ReasonExpired:
		s.finishLocked(f, StateExpired, authn.ReasonExpired, nil)
	case authn.ReasonCancelled:
		s.finishLocked(f, StateCancelled, authn.ReasonCancelled, nil)
	default:
		s.finishLocked(f, StateFailed, authn.ReasonOf(res.Err), nil)
	}
}

// finishLocked enters a non-verified terminal state: release the unfilled
// code reservation, destroy method secrets, stop polling.
func (s *Server) finishLocked(f *flow, state, reason string, _ error) {
	if terminal(f.state) {
		return
	}
	f.state, f.reason = state, reason
	code := "access_denied"
	if state == StateFailed {
		code = "server_error"
	}
	f.redirect = s.cfg.Provider.ErrorRedirect(f.req.RedirectURI, f.req.State, code)
	if f.res != nil {
		f.res.Release()
	}
	s.releaseLocked(f, true)
	s.cfg.Log.Info("flow finished", "flow_state", state, "reason_code", reason, "method", f.method)
}

func (s *Server) releaseLocked(f *flow, _ bool) {
	if f.pending != nil {
		f.pending.Destroy()
	}
	if f.cancel != nil {
		f.cancel()
	}
	if f.slot {
		<-s.slots
		f.slot = false
	}
	s.flows.terminated()
	if f.state == StateVerified {
		s.cfg.Log.Info("flow finished", "flow_state", StateVerified, "method", f.method)
	}
}

func (s *Server) sweeper() {
	defer s.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Sweep applies timeouts: a created flow that never started expires after
// 60 s; a pending flow at flow_ttl + 30 s; terminal entries are removed at
// the absolute deadline.
func (s *Server) Sweep() {
	now := s.cfg.Clock.Mono()
	for _, f := range s.flows.all() {
		f.mu.Lock()
		switch {
		case f.state == StateCreated && now >= f.startBy:
			s.finishLocked(f, StateExpired, authn.ReasonExpired, nil)
		case !terminal(f.state) && now >= f.deadline:
			s.finishLocked(f, StateExpired, authn.ReasonExpired, nil)
		}
		gone := terminal(f.state) && now >= f.deadline
		f.mu.Unlock()
		if gone {
			s.flows.remove(f)
		}
	}
}

func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	f, acc, _ := s.lookup(r)
	if f == nil || acc != accessCurrent {
		s.restart(w, r, "restart")
		return
	}
	f.mu.Lock()
	if f.state != StatePending || f.offered != authn.FlowQR {
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Regenerated on every request from the current elapsed time, so a QR
	// is never older than the browser's one-second refresh.
	ui, err := f.pending.UI(time.Now())
	f.mu.Unlock()
	if err != nil || ui.QRPayload == "" {
		http.NotFound(w, r)
		return
	}
	png, err := qrPNG(ui.QRPayload)
	if err != nil {
		http.Error(w, "qr", 500)
		return
	}
	securityHeaders(w)
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

type statusResp struct {
	State   string `json:"state"`
	Waiting string `json:"waiting,omitempty"`
	Next    string `json:"next,omitempty"`
	Message string `json:"message,omitempty"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	f, acc, _ := s.lookup(r)
	securityHeaders(w)
	if f == nil || acc == accessNone {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(statusResp{State: "restart"})
		return
	}
	if acc == accessRetired {
		json.NewEncoder(w).Encode(statusResp{State: "other_tab"})
		return
	}
	f.mu.Lock()
	st := statusResp{State: f.state, Waiting: f.waiting}
	if terminal(f.state) {
		st.Next = s.base + "/flow/" + f.id + "/continue"
		st.Message = t(f.lang, "outcome."+f.state)
	} else {
		st.Message = t(f.lang, "status.waiting")
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *Server) cancelFlow(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	f, acc, _ := s.lookup(r)
	if f == nil || acc != accessCurrent || r.ParseForm() != nil || !hmac.Equal([]byte(r.PostForm.Get("ft")), []byte(s.formToken(f))) {
		s.restart(w, r, "restart")
		return
	}
	f.mu.Lock()
	s.finishLocked(f, StateCancelled, authn.ReasonCancelled, nil)
	f.mu.Unlock()
	http.Redirect(w, r, s.base+"/flow/"+f.id+"/continue", http.StatusSeeOther)
}

// continueFlow delivers the terminal response: the code redirect for a
// verified flow, otherwise an error redirect with iss and state. The flow
// entry is removed and its cookie cleared.
func (s *Server) continueFlow(w http.ResponseWriter, r *http.Request) {
	f, acc, cv := s.lookup(r)
	if f == nil {
		s.unknownFlow(w, r, cv)
		return
	}
	if acc == accessRetired {
		s.render(w, r, f, "othertab.html", nil)
		return
	}
	if acc != accessCurrent {
		s.restart(w, r, "restart")
		return
	}
	f.mu.Lock()
	if !terminal(f.state) {
		f.mu.Unlock()
		http.Redirect(w, r, s.base+"/flow/"+f.id, http.StatusSeeOther)
		return
	}
	u := f.redirect
	if f.state == StateVerified && s.cfg.Clock.Mono() >= f.codeUntil {
		// The code is dead; tell the client instead of handing it over.
		u = s.cfg.Provider.ErrorRedirect(f.req.RedirectURI, f.req.State, "access_denied")
	}
	f.mu.Unlock()
	s.flows.remove(f)
	clearFlowCookie(w, f.id)
	securityHeaders(w)
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// callback handles the Smart-ID Web2App return (ADR-010).
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	value := q.Get("value")
	f := s.flows.byCallback(value)
	if f == nil || len(value) > 64 {
		s.restart(w, r, "restart")
		return
	}
	c, err := r.Cookie(cookiePrefix + f.id)
	if err != nil {
		s.restart(w, r, "callback_other_browser") // flow left unchanged; it expires
		return
	}
	cv, ok := decodeCookie(c.Value)
	f.mu.Lock()
	if !ok || !eq(f.binding, hashOf(cv.B)) || f.cbUsed || !eq(f.callback, hashOf(value)) || s.draining.Load() {
		f.mu.Unlock()
		s.restart(w, r, "restart")
		return
	}
	if f.state != StatePending {
		f.mu.Unlock()
		s.restart(w, r, "restart")
		return
	}
	f.cbUsed = true
	// Rotate to a fresh completion cookie; the old tab keeps only the
	// other-tab notice. The original absolute deadline is preserved.
	nb := randToken(32)
	f.retired = append(f.retired, f.binding)
	f.binding = hashOf(nb)
	cv.B = nb
	val, _ := encodeCookie(cv)
	setFlowCookie(w, f.id, val, f.deadline-s.cfg.Clock.Mono())
	ctx, cancel := context.WithTimeout(context.Background(), min(f.deadline-s.cfg.Clock.Mono(), 15*time.Second))
	res := f.pending.Callback(ctx, url.Values{"sessionSecretDigest": {q.Get("sessionSecretDigest")}, "userChallengeVerifier": {q.Get("userChallengeVerifier")}}, nil)
	cancel()
	if res.Done {
		s.applyLocked(f, res)
	} else {
		f.waiting = res.Waiting
	}
	done := terminal(f.state)
	f.mu.Unlock()
	if done {
		http.Redirect(w, r, s.base+"/flow/"+f.id+"/continue", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.base+"/flow/"+f.id, http.StatusSeeOther)
}

// browserResult receives a browser-produced proof (Web eID token) for the
// flow; the method verifies origin, nonce and certificate.
func (s *Server) browserResult(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	f, acc, _ := s.lookup(r)
	if f == nil || acc != accessCurrent || r.ParseForm() != nil || !hmac.Equal([]byte(r.PostForm.Get("ft")), []byte(s.formToken(f))) {
		s.restart(w, r, "restart")
		return
	}
	f.mu.Lock()
	if f.state != StatePending || f.offered != authn.FlowBrowser {
		f.mu.Unlock()
		s.restart(w, r, "restart")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	res := f.pending.Callback(ctx, nil, []byte(r.PostForm.Get("token")))
	cancel()
	if res.Done {
		s.applyLocked(f, res)
	}
	f.mu.Unlock()
	http.Redirect(w, r, s.base+"/flow/"+f.id+"/continue", http.StatusSeeOther)
}

// walletResponse receives a direct_post wallet response (OpenID4VP). The
// wallet has no flow cookie; the method binds the response to its own
// request (state, nonce, response URI).
func (s *Server) walletResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	f := s.flows.get(r.PathValue("id"))
	if f == nil || r.ParseForm() != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	if f.state != StatePending || s.draining.Load() {
		f.mu.Unlock()
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	res := f.pending.Callback(ctx, r.PostForm, nil)
	cancel()
	if res.Done {
		s.applyLocked(f, res)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if res.Err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_request"}`))
		return
	}
	w.Write([]byte(`{}`))
}

// requestObjecter is implemented by wallet methods that serve a signed
// authorization request by reference (OpenID4VP request_uri).
type requestObjecter interface{ RequestObject() (string, error) }

// walletRequest serves the request object for a pending wallet flow. The
// wallet has no flow cookie; the unguessable flow id in the request URI is
// the reference.
func (s *Server) walletRequest(w http.ResponseWriter, r *http.Request) {
	f := s.flows.get(r.PathValue("id"))
	if f == nil {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	ro, ok := f.pending.(requestObjecter)
	pending := f.state == StatePending
	f.mu.Unlock()
	if !ok || !pending {
		http.NotFound(w, r)
		return
	}
	jwt, err := ro.RequestObject()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	w.Write([]byte(jwt))
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// PendingUI returns the current UI of a pending flow (what the QR image
// encodes). Integration tests and the fixture e2e driver use it in place of
// a camera; it exposes nothing the login page does not already show.
func (s *Server) PendingUI(flowID string) (authn.UI, bool) {
	f := s.flows.get(flowID)
	if f == nil {
		return authn.UI{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != StatePending || f.pending == nil {
		return authn.UI{}, false
	}
	ui, err := f.pending.UI(time.Now())
	return ui, err == nil
}

// formActionOrigin returns the http(s) origin of a redirect URI for use as
// a CSP source, or "" when it is not an http(s) URL with a plain host.
// Custom-scheme (native app) redirect URIs get no form-action entry.
func formActionOrigin(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return ""
	}
	for _, c := range u.Host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '[' || c == ']') {
			return ""
		}
	}
	return u.Scheme + "://" + u.Host
}
