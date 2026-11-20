// Package signapi is the bridge's signing API (Story 8.1-a, FR-028): a
// client-authenticated digest relay, separate from login. Integrators send
// the signer's ETSI identifier, receive the signing certificate, compute the
// container digest themselves and receive a verified signature value. Jobs
// live in memory only, belong to one client, are single use and expire.
// The bridge makes no claim about the legal status of the signature.
package signapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Upstream is the Smart-ID client subset used here.
type Upstream interface {
	StartCertificateChoice(ctx context.Context, semanticsID string) (string, error)
	VerifyCertificateChoice(ctx context.Context, semanticsID string, st *smartid.Status) (*smartid.SigningCert, error)
	StartSignature(ctx context.Context, sc *smartid.SigningCert, r smartid.SignRequest) (*smartid.SignSession, error)
	VerifyRawDigest(ctx context.Context, ss *smartid.SignSession, st *smartid.Status) (*smartid.SignResult, error)
	Poll(ctx context.Context, sessionID string, timeout time.Duration) (*smartid.Status, error)
}

// Authenticator authenticates a client allowed to sign (HTTP Basic).
type Authenticator interface {
	AuthenticateSigningClient(r *http.Request) (clientID string, ok bool)
}

// Config configures the API.
type Config struct {
	Upstream           Upstream
	Auth               Authenticator
	Log                *slog.Logger
	JobTTL             time.Duration // default 5 minutes
	SessionTimeout     time.Duration // upstream wait per job, default 3 minutes
	PollTimeout        time.Duration // one long poll, default 30 s
	MaxJobs            int           // global ceiling, default 1000
	PerClientPerMinute int           // job starts per client per minute, default 30
	Now                func() time.Time
}

type job struct {
	client  string
	kind    string // "certificate" or "signature"
	expires time.Time
	state   string // pending, complete, failed
	errCode string
	cert    *smartid.SigningCert
	result  *smartid.SignResult
	vc      string
	used    bool
}

// Handler serves /api/v1/sign*.
type Handler struct {
	cfg    Config
	mu     sync.Mutex
	jobs   map[string]*job
	window map[string][]time.Time
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New returns a Handler; call Close on shutdown.
func New(cfg Config) *Handler {
	if cfg.JobTTL <= 0 {
		cfg.JobTTL = 5 * time.Minute
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 3 * time.Minute
	}
	if cfg.PollTimeout <= 0 {
		cfg.PollTimeout = 30 * time.Second
	}
	if cfg.MaxJobs <= 0 {
		cfg.MaxJobs = 1000
	}
	if cfg.PerClientPerMinute <= 0 {
		cfg.PerClientPerMinute = 30
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Handler{cfg: cfg, jobs: map[string]*job{}, window: map[string][]time.Time{}, ctx: ctx, cancel: cancel}
}

// Close stops upstream polling and drops every job.
func (h *Handler) Close() {
	h.cancel()
	h.wg.Wait()
	h.mu.Lock()
	h.jobs = map[string]*job{}
	h.mu.Unlock()
}

const maxBody = 16 << 10

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	client, ok := h.cfg.Auth.AuthenticateSigningClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="eidbridge-signing"`)
		writeErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sign/certificate":
		h.startCertificate(w, r, client)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sign":
		h.startSignature(w, r, client)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/sign/"):
		h.get(w, client, strings.TrimPrefix(r.URL.Path, "/api/v1/sign/"))
	default:
		writeErr(w, http.StatusNotFound, "not_found")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (h *Handler) startCertificate(w http.ResponseWriter, r *http.Request, client string) {
	var in struct {
		Signer string `json:"signer"`
	}
	if !decode(w, r, &in) {
		return
	}
	if smartid.ValidateSemanticsID(in.Signer) != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, j, code := h.admit(client, "certificate")
	if code != 0 {
		writeErr(w, code, http.StatusText(code))
		return
	}
	sessionID, err := h.cfg.Upstream.StartCertificateChoice(r.Context(), in.Signer)
	if err != nil {
		h.drop(id)
		writeErr(w, http.StatusBadGateway, reason(err))
		return
	}
	h.run(j, func(ctx context.Context, st *smartid.Status) error {
		sc, err := h.cfg.Upstream.VerifyCertificateChoice(ctx, in.Signer, st)
		if err == nil {
			h.mu.Lock()
			j.cert = sc
			h.mu.Unlock()
		}
		return err
	}, sessionID)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": "pending"})
}

func (h *Handler) startSignature(w http.ResponseWriter, r *http.Request, client string) {
	var in struct {
		Certificate        string `json:"certificate"`
		Digest             string `json:"digest"`
		HashAlgorithm      string `json:"hash_algorithm"`
		SignatureAlgorithm string `json:"signature_algorithm"`
		DisplayText        string `json:"display_text"`
	}
	if !decode(w, r, &in) {
		return
	}
	d, err := base64.StdEncoding.DecodeString(in.Digest)
	req := smartid.SignRequest{Digest: d, HashAlgorithm: in.HashAlgorithm, SignatureAlgorithm: in.SignatureAlgorithm, DisplayText200: in.DisplayText}
	if err != nil || !validSignRequest(req) {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// Consume the certificate job atomically: a replay finds nothing.
	h.mu.Lock()
	h.sweep()
	cj := h.jobs[in.Certificate]
	switch {
	case cj == nil || cj.client != client || cj.kind != "certificate" || cj.used:
		h.mu.Unlock()
		writeErr(w, http.StatusNotFound, "not_found")
		return
	case cj.state != "complete":
		h.mu.Unlock()
		writeErr(w, http.StatusConflict, "certificate_not_ready")
		return
	}
	cj.used = true
	sc := cj.cert
	delete(h.jobs, in.Certificate)
	h.mu.Unlock()

	id, j, code := h.admit(client, "signature")
	if code != 0 {
		writeErr(w, code, http.StatusText(code))
		return
	}
	ss, err := h.cfg.Upstream.StartSignature(r.Context(), sc, req)
	if err != nil {
		h.drop(id)
		writeErr(w, http.StatusBadGateway, reason(err))
		return
	}
	h.mu.Lock()
	j.vc = ss.VC
	h.mu.Unlock()
	h.run(j, func(ctx context.Context, st *smartid.Status) error {
		res, err := h.cfg.Upstream.VerifyRawDigest(ctx, ss, st)
		if err == nil {
			h.mu.Lock()
			j.result = res
			h.mu.Unlock()
		}
		return err
	}, ss.ID)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": "pending", "verification_code": ss.VC})
}

var hashSize = map[string]int{"SHA-256": 32, "SHA-384": 48, "SHA-512": 64}

func validSignRequest(r smartid.SignRequest) bool {
	n, ok := hashSize[r.HashAlgorithm]
	if !ok || len(r.Digest) != n || r.DisplayText200 == "" || len([]rune(r.DisplayText200)) > 200 {
		return false
	}
	switch r.SignatureAlgorithm {
	case "rsassa-pss":
		return true
	case "sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption":
		return strings.TrimPrefix(r.HashAlgorithm, "SHA-") == r.SignatureAlgorithm[3:6]
	}
	return false
}

func (h *Handler) get(w http.ResponseWriter, client, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep()
	j := h.jobs[id]
	if j == nil || j.client != client || j.used {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	out := map[string]any{"status": j.state}
	switch {
	case j.state == "failed":
		out["error"] = j.errCode
		delete(h.jobs, id)
	case j.state == "complete" && j.kind == "certificate":
		out["certificate"] = base64.StdEncoding.EncodeToString(j.cert.Certificate.Raw)
		out["certificate_level"] = j.cert.Level
	case j.state == "complete":
		out["signature"] = base64.StdEncoding.EncodeToString(j.result.Value)
		out["signature_algorithm"] = j.result.SignatureAlgorithm
		out["hash_algorithm"] = j.result.HashAlgorithm
		out["certificate"] = base64.StdEncoding.EncodeToString(j.result.Certificate.Raw)
		out["certificate_level"] = j.result.Level
		delete(h.jobs, id) // delivered once
	default:
		if j.vc != "" {
			out["verification_code"] = j.vc
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// admit applies the rate limit and the capacity ceiling, then registers a job.
func (h *Handler) admit(client, kind string) (string, *job, int) {
	now := h.cfg.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweep()
	recent := h.window[client][:0]
	for _, t := range h.window[client] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	h.window[client] = recent
	if len(recent) >= h.cfg.PerClientPerMinute {
		return "", nil, http.StatusTooManyRequests
	}
	if len(h.jobs) >= h.cfg.MaxJobs {
		return "", nil, http.StatusServiceUnavailable
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, http.StatusInternalServerError
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	j := &job{client: client, kind: kind, state: "pending", expires: now.Add(h.cfg.JobTTL)}
	h.jobs[id] = j
	h.window[client] = append(recent, now)
	return id, j, 0
}

func (h *Handler) drop(id string) {
	h.mu.Lock()
	delete(h.jobs, id)
	h.mu.Unlock()
}

// sweep removes expired jobs; h.mu must be held.
func (h *Handler) sweep() {
	now := h.cfg.Now()
	for id, j := range h.jobs {
		if !now.Before(j.expires) {
			delete(h.jobs, id)
		}
	}
}

// run polls the upstream session in the background and records the outcome.
func (h *Handler) run(j *job, verify func(context.Context, *smartid.Status) error, sessionID string) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ctx, cancel := context.WithTimeout(h.ctx, h.cfg.SessionTimeout)
		defer cancel()
		err := func() error {
			backoff := 250 * time.Millisecond
			for {
				st, err := h.cfg.Upstream.Poll(ctx, sessionID, h.cfg.PollTimeout)
				if err != nil {
					var he *smartid.HTTPError
					if errors.As(err, &he) && he.Retryable && ctx.Err() == nil {
						// Back off so a failing upstream is not hammered.
						select {
						case <-time.After(backoff):
						case <-ctx.Done():
							return ctx.Err()
						}
						backoff = min(2*backoff, 5*time.Second)
						continue
					}
					return err
				}
				if st.State == "COMPLETE" {
					return verify(ctx, st)
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
		}()
		h.mu.Lock()
		defer h.mu.Unlock()
		if err != nil {
			j.state, j.errCode = "failed", reason(err)
			h.cfg.Log.Info("signing job failed", "kind", j.kind, "reason", j.errCode)
			return
		}
		j.state = "complete"
		h.cfg.Log.Info("signing job complete", "kind", j.kind)
	}()
}

func reason(err error) string {
	var e *smartid.Error
	if errors.As(err, &e) {
		return e.Reason
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return smartid.ReasonExpired
	}
	return smartid.ReasonUpstreamError
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, e string) {
	writeJSON(w, code, map[string]string{"error": e})
}
