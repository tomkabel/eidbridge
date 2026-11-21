// Package smartid is a clean-room Smart-ID RP API v3 client written from the
// pinned SK documentation (docs/spec-pins). It creates device-link and
// notification authentication sessions, long-polls their status and verifies
// the result. An Identity is produced only by Verify, after every check in
// research/smart-id-v3-facts-2026-11-18.md §4 passes.
package smartid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config configures a Client. Trust holds only explicitly configured
// authentication CAs; the system store is never used.
type Config struct {
	BaseURL      string // e.g. https://sid.demo.sk.ee/smart-id-rp (no /v3)
	RPUUID       string
	RPName       string
	SchemeName   string // smart-id or smart-id-demo
	HTTP         *http.Client
	Trust        *TrustStore
	MinCertLevel string
	// PolicyOIDs lists certificate policy OIDs the end-entity certificate
	// must carry (Smart-ID scheme check). Empty disables the check; config
	// invariants forbid that in production.
	PolicyOIDs []asn1.ObjectIdentifier
	Status     StatusChecker
	Recorder   *Recorder
	MaxBody    int64 // response size cap, default 64 KiB
	Now        func() time.Time
	// HashAlgorithm requested for ACSP_V2; default SHA-512.
	HashAlgorithm string
}

// Client is safe for concurrent use.
type Client struct{ cfg Config }

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// NewClient validates cfg.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, errors.New("smartid: BaseURL must be https (http only on loopback for fixtures)")
	}
	if !uuidRe.MatchString(cfg.RPUUID) || cfg.RPName == "" {
		return nil, errors.New("smartid: RP UUID and name are required")
	}
	if cfg.SchemeName != SchemeLive && cfg.SchemeName != SchemeDemo && cfg.SchemeName != "smart-id-mock" {
		return nil, errors.New("smartid: unknown scheme name")
	}
	if cfg.Trust == nil || cfg.Trust.Empty() {
		return nil, errors.New("smartid: authentication trust anchors are required")
	}
	if levelRank(cfg.MinCertLevel) == 0 {
		return nil, errors.New("smartid: MinCertLevel must be ADVANCED or QUALIFIED")
	}
	if cfg.Status == nil {
		return nil, errors.New("smartid: a certificate status checker is required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = DefaultHTTPClient()
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 64 << 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HashAlgorithm == "" {
		cfg.HashAlgorithm = "SHA-512"
	}
	if _, ok := hashByName[cfg.HashAlgorithm]; !ok {
		return nil, errors.New("smartid: unsupported hash algorithm")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg}, nil
}

// DefaultHTTPClient refuses redirects and bounds connection setup. Production
// callers pass a pinned client from internal/tlspin instead.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       130 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// DeviceLinkRequest starts an anonymous device-link authentication.
type DeviceLinkRequest struct {
	Flow               string // FlowQR or FlowWeb2App
	InitialCallbackURL string // required for Web2App, must be empty for QR
	DisplayText60      string
	Lang               string // ISO 639-2, default "eng"
}

// NotificationRequest starts a notification authentication for a known
// person (ETSI semantics identifier such as PNOEE-…) or document number.
type NotificationRequest struct {
	SemanticsID    string
	DocumentNumber string
	DisplayText60  string
	Lang           string
}

type sigParams struct {
	RPChallenge        string            `json:"rpChallenge"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
	AlgParams          map[string]string `json:"signatureAlgorithmParameters"`
}

type authRequest struct {
	RPUUID             string          `json:"relyingPartyUUID"`
	RPName             string          `json:"relyingPartyName"`
	InitialCallbackURL *string         `json:"initialCallbackUrl,omitempty"`
	CertificateLevel   string          `json:"certificateLevel"`
	SignatureProtocol  string          `json:"signatureProtocol"`
	Params             sigParams       `json:"signatureProtocolParameters"`
	Interactions       string          `json:"interactions"`
	RequestProperties  map[string]bool `json:"requestProperties"`
	VCType             string          `json:"vcType,omitempty"`
}

type deviceLinkResponse struct {
	SessionID      string `json:"sessionID"`
	SessionToken   string `json:"sessionToken"`
	SessionSecret  string `json:"sessionSecret"`
	DeviceLinkBase string `json:"deviceLinkBase"`
}

// Interactions returns the Base64 interactions string for a displayTextAndPIN
// interaction. The bridge stores and reuses this exact string.
func Interactions(text60 string) (string, error) {
	if text60 == "" || len([]rune(text60)) > 60 {
		return "", errors.New("smartid: displayText60 must be 1 to 60 characters")
	}
	b, err := json.Marshal([]map[string]string{{"type": "displayTextAndPIN", "displayText60": text60}})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

var tokenRe = regexp.MustCompile(`^[a-zA-Z0-9]{24,}$`)
var b64Re = regexp.MustCompile(`^[a-zA-Z0-9+/]+={0,2}$`)

func (c *Client) newSession(flow, callback, text, lang string) (*Session, authRequest, error) {
	inter, err := Interactions(text)
	if err != nil {
		return nil, authRequest{}, err
	}
	if lang == "" {
		lang = "eng"
	}
	if !regexp.MustCompile(`^[a-z]{3}$`).MatchString(lang) {
		return nil, authRequest{}, errors.New("smartid: lang must be ISO 639-2")
	}
	ch := make([]byte, 32)
	if _, err := rand.Read(ch); err != nil {
		return nil, authRequest{}, err
	}
	s := &Session{Flow: flow, InitialCallbackURL: callback, Interactions: inter, Lang: lang,
		rpChallenge: ch, scheme: c.cfg.SchemeName, rpName: c.cfg.RPName}
	req := authRequest{
		RPUUID: c.cfg.RPUUID, RPName: c.cfg.RPName, CertificateLevel: c.cfg.MinCertLevel,
		SignatureProtocol: "ACSP_V2",
		Params: sigParams{RPChallenge: s.RPChallengeB64(), SignatureAlgorithm: "rsassa-pss",
			AlgParams: map[string]string{"hashAlgorithm": c.cfg.HashAlgorithm}},
		Interactions:      inter,
		RequestProperties: map[string]bool{"shareMdClientIpAddress": false},
	}
	return s, req, nil
}

// StartDeviceLink creates an anonymous device-link authentication session.
func (c *Client) StartDeviceLink(ctx context.Context, r DeviceLinkRequest) (*Session, error) {
	switch r.Flow {
	case FlowQR:
		if r.InitialCallbackURL != "" {
			return nil, errors.New("smartid: initialCallbackUrl must be empty for QR")
		}
	case FlowWeb2App:
		if err := ValidateCallbackURL(r.InitialCallbackURL); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("smartid: device-link flow must be QR or Web2App")
	}
	s, req, err := c.newSession(r.Flow, r.InitialCallbackURL, r.DisplayText60, r.Lang)
	if err != nil {
		return nil, err
	}
	// Live demo (2026-11-20) rejects a blank initialCallbackUrl for QR with
	// HTTP 400 although the docs say "empty": omit the field for QR.
	if r.Flow == FlowWeb2App {
		cb := r.InitialCallbackURL
		req.InitialCallbackURL = &cb
	}
	var resp deviceLinkResponse
	if err := c.post(ctx, "/v3/authentication/device-link/anonymous", "create-device-link", req, &resp); err != nil {
		s.Destroy()
		return nil, err
	}
	if err := c.acceptDeviceLink(s, resp); err != nil {
		s.Destroy()
		return nil, err
	}
	return s, nil
}

func (c *Client) acceptDeviceLink(s *Session, r deviceLinkResponse) error {
	if !uuidRe.MatchString(r.SessionID) || !tokenRe.MatchString(r.SessionToken) ||
		len(r.SessionSecret) < 24 || !b64Re.MatchString(r.SessionSecret) {
		return fail(ReasonUpstreamError, "malformed device-link response")
	}
	secret, err := base64.StdEncoding.DecodeString(r.SessionSecret)
	if err != nil {
		return fail(ReasonUpstreamError, "malformed sessionSecret")
	}
	u, err := url.Parse(r.DeviceLinkBase)
	if err != nil || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return fail(ReasonUpstreamError, "malformed deviceLinkBase")
	}
	s.ID, s.token, s.secret, s.linkBase = r.SessionID, r.SessionToken, secret, r.DeviceLinkBase
	s.created = c.cfg.Now()
	return nil
}

// ValidateCallbackURL enforces the pinned initialCallbackUrl rules: HTTPS,
// no fragment or "|", at most 1800 characters.
func ValidateCallbackURL(raw string) error {
	if len(raw) > 1800 || !strings.HasPrefix(raw, "https://") || strings.ContainsAny(raw, "#|") {
		return errors.New("smartid: initialCallbackUrl must be https, without # or |, at most 1800 chars")
	}
	if _, err := url.Parse(raw); err != nil {
		return errors.New("smartid: invalid initialCallbackUrl")
	}
	return nil
}

// StartNotification creates a notification authentication session for a
// person already validated locally (ValidateSemanticsID). Callers must apply
// rate limits before calling.
func (c *Client) StartNotification(ctx context.Context, r NotificationRequest) (*Session, error) {
	var path, expected string
	switch {
	case r.SemanticsID != "" && r.DocumentNumber == "":
		if err := ValidateSemanticsID(r.SemanticsID); err != nil {
			return nil, err
		}
		path, expected = "/v3/authentication/notification/etsi/"+url.PathEscape(r.SemanticsID), r.SemanticsID
	case r.DocumentNumber != "" && r.SemanticsID == "":
		if !docNumberRe.MatchString(r.DocumentNumber) {
			return nil, errors.New("smartid: invalid document number")
		}
		path, expected = "/v3/authentication/notification/document/"+url.PathEscape(r.DocumentNumber), r.DocumentNumber
	default:
		return nil, errors.New("smartid: exactly one of SemanticsID or DocumentNumber is required")
	}
	s, req, err := c.newSession(FlowNotification, "", r.DisplayText60, r.Lang)
	if err != nil {
		return nil, err
	}
	req.VCType = "numeric4"
	s.ExpectedIdentity = expected
	var resp struct {
		SessionID string `json:"sessionID"`
	}
	if err := c.post(ctx, path, "create-notification", req, &resp); err != nil {
		s.Destroy()
		return nil, err
	}
	if !uuidRe.MatchString(resp.SessionID) {
		s.Destroy()
		return nil, fail(ReasonUpstreamError, "malformed notification response")
	}
	s.ID = resp.SessionID
	s.created = c.cfg.Now()
	s.secret = []byte{} // notification sessions have no session secret
	s.VC = NotificationVC(s.rpChallenge)
	return s, nil
}

var docNumberRe = regexp.MustCompile(`^(PNO|PAS|IDC)[A-Z]{2}-[0-9A-Za-z-]{4,40}$`)

// Poll long-polls the session status endpoint once.
func (c *Client) Poll(ctx context.Context, sessionID string, timeout time.Duration) (*Status, error) {
	if !uuidRe.MatchString(sessionID) {
		return nil, errors.New("smartid: invalid session id")
	}
	ms := timeout.Milliseconds()
	if ms < 1000 {
		ms = 1000
	}
	if ms > 120000 {
		ms = 120000
	}
	path := "/v3/session/" + sessionID + "?timeoutMs=" + strconv.FormatInt(ms, 10)
	body, err := c.do(ctx, http.MethodGet, path, "session-status", nil)
	if err != nil {
		return nil, err
	}
	return ParseStatus(body)
}

func (c *Client) post(ctx context.Context, path, name string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	body, err := c.do(ctx, http.MethodPost, path, name, b)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fail(ReasonUpstreamError, "malformed JSON response")
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path, name string, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, &HTTPError{Retryable: ctx.Err() == nil, Cause: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxBody+1))
	if err != nil {
		return nil, &HTTPError{Retryable: true, Cause: err}
	}
	if int64(len(data)) > c.cfg.MaxBody {
		return nil, fail(ReasonUpstreamError, "response exceeds size cap")
	}
	c.cfg.Recorder.record(name, method, path, resp.StatusCode, body, data)
	if resp.StatusCode == http.StatusOK {
		if len(data) == 0 {
			return nil, fail(ReasonUnknownEndResult, "empty 200 body")
		}
		return data, nil
	}
	he := &HTTPError{Status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		he.Retryable = true
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 && s <= 600 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
	case resp.StatusCode >= 500:
		he.Retryable = true
	}
	return nil, he
}

// ErrNoSuchKey is a sentinel used by fixture helpers.
