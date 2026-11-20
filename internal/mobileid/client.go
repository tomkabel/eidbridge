// Package mobileid authenticates people with Mobile-ID through SK's MID REST
// API (https://github.com/SK-EID/MID, README commit pinned in
// docs/adr/0004-mobile-id.md). It is a second authn.Method behind the same
// OIDC issuer; it has no OIDC code of its own.
//
// The relying party sends a random hash, shows the verification code
// derived from it, long-polls the session and then verifies the returned
// signature, certificate chain, policy, purpose, identity and status before
// it reports an identity.
package mobileid

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Config configures a Client. Trust and status checking reuse the Smart-ID
// certificate types: both schemes are SK PKI with the same roots.
type Config struct {
	BaseURL string // e.g. https://tsp.demo.sk.ee/mid-api
	RPUUID  string
	RPName  string
	HTTP    *http.Client
	Trust   *smartid.TrustStore
	// PolicyOIDs the end-entity certificate must carry (demo and live
	// Mobile-ID authentication certificates: 1.3.6.1.4.1.10015.18.1).
	PolicyOIDs []asn1.ObjectIdentifier
	Status     smartid.StatusChecker
	MaxBody    int64 // response size cap, default 64 KiB
	Now        func() time.Time
}

// Client is safe for concurrent use.
type Client struct{ cfg Config }

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	phoneRe = regexp.MustCompile(`^\+(372|370)[0-9]{7,8}$`)
)

// NewClient validates cfg.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, errors.New("mobileid: BaseURL must be https (http only on loopback for fixtures)")
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if !uuidRe.MatchString(cfg.RPUUID) {
		return nil, errors.New("mobileid: relyingPartyUUID must be a lower-case UUID (MID REST API §2.2)")
	}
	if cfg.RPName == "" || cfg.HTTP == nil || cfg.Trust == nil || cfg.Trust.Empty() || cfg.Status == nil {
		return nil, errors.New("mobileid: RPName, HTTP client, trust anchors and status checker are required")
	}
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 64 << 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg}, nil
}

func loopback(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

// Countries maps the phone prefix to the country whose personal codes the
// service issues (EE, LT; the API has no Latvian Mobile-ID).
var Countries = map[string]string{"+372": "EE", "+370": "LT"}

// Session is one started authentication. Hash is the random value the phone
// signs; it is erased by Destroy.
type Session struct {
	ID       string
	Hash     []byte
	VC       string
	Country  string // from the phone prefix
	Code     string // requested national identity number (personal data)
	Phone    string // requested phone number (personal data)
	hashType string
}

// Destroy erases the hash and the requested identifiers.
func (s *Session) Destroy() {
	for i := range s.Hash {
		s.Hash[i] = 0
	}
	s.Hash, s.Code, s.Phone = nil, "", ""
}

// StartRequest is validated input for an authentication.
type StartRequest struct {
	Phone, Code string
	Lang3       string // EST, ENG, RUS or LIT
	DisplayText string // ≤ 40 GSM-7 characters, optional
}

// ValidateInput checks the phone number (E.164, EE or LT) and that the
// personal code is valid for the phone's country before any request leaves.
func ValidateInput(phone, code string) (country string, err error) {
	if !phoneRe.MatchString(phone) {
		return "", &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "phone number is not +372/+370 E.164"}
	}
	country = Countries[phone[:4]]
	if !smartid.ValidPersonalCode(country, code) {
		return "", &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "personal code failed local validation"}
	}
	return country, nil
}

var gsm7Re = regexp.MustCompile(`^[A-Za-z0-9 .,:;!?()'"/+&%-]{0,40}$`)

// ValidDisplayText reports whether t fits the conservative GSM-7 subset
// and length the bridge sends as displayText.
func ValidDisplayText(t string) bool { return gsm7Re.MatchString(t) }

// Start initiates an authentication with a fresh random SHA-256 hash.
func (c *Client) Start(ctx context.Context, r StartRequest) (*Session, error) {
	country, err := ValidateInput(r.Phone, r.Code)
	if err != nil {
		return nil, err
	}
	switch r.Lang3 {
	case "EST", "ENG", "RUS", "LIT":
	default:
		r.Lang3 = "ENG"
	}
	if !gsm7Re.MatchString(r.DisplayText) {
		return nil, errors.New("mobileid: display text must be ≤ 40 plain GSM-7 characters")
	}
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(seed)
	hash := sum[:]
	req := map[string]string{
		"relyingPartyUUID": c.cfg.RPUUID, "relyingPartyName": c.cfg.RPName,
		"phoneNumber": r.Phone, "nationalIdentityNumber": r.Code,
		"hash": base64.StdEncoding.EncodeToString(hash), "hashType": "SHA256", "language": r.Lang3,
	}
	if r.DisplayText != "" {
		req["displayText"], req["displayTextFormat"] = r.DisplayText, "GSM-7"
	}
	b, _ := json.Marshal(req)
	body, err := c.do(ctx, http.MethodPost, "/authentication", b)
	if err != nil {
		return nil, err
	}
	var out struct {
		SessionID string `json:"sessionID"`
	}
	if json.Unmarshal(body, &out) != nil || !sidRe.MatchString(out.SessionID) {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "malformed start response"}
	}
	return &Session{ID: out.SessionID, Hash: hash, VC: VerificationCode(hash), Country: country, Code: r.Code, Phone: r.Phone, hashType: "SHA256"}, nil
}

// Status is a parsed session status (MID REST API §3.3.5).
type Status struct {
	State     string `json:"state"`
	Result    string `json:"result"`
	Signature *struct {
		Value     string `json:"value"`
		Algorithm string `json:"algorithm"`
	} `json:"signature"`
	Cert string `json:"cert"`
}

// Poll long-polls the authentication session once.
func (c *Client) Poll(ctx context.Context, sessionID string, timeout time.Duration) (*Status, error) {
	if !sidRe.MatchString(sessionID) {
		return nil, errors.New("mobileid: invalid session id")
	}
	ms := min(max(timeout.Milliseconds(), 1000), 60000)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond+1500*time.Millisecond) // §3.3.4
	defer cancel()
	body, err := c.do(ctx, http.MethodGet, "/authentication/session/"+sessionID+"?timeoutMs="+strconv.FormatInt(ms, 10), nil)
	if err != nil {
		return nil, err
	}
	return ParseStatus(body)
}

// ParseStatus parses and shape-checks a status body. Unknown fields are
// allowed (§2.7); unknown states and results are errors.
func ParseStatus(body []byte) (*Status, error) {
	var st Status
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "malformed status JSON"}
	}
	switch st.State {
	case "RUNNING":
		return &st, nil
	case "COMPLETE":
		if _, ok := results[st.Result]; !ok {
			return nil, &authn.Error{Reason: authn.ReasonUnknownEndResult, Detail: "unknown result"}
		}
		return &st, nil
	}
	return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "unknown state"}
}

// results maps every §3.3.8 result to a reason (empty: success).
var results = map[string]string{
	"OK":                      "",
	"TIMEOUT":                 authn.ReasonExpired,
	"NOT_MID_CLIENT":          authn.ReasonAccountUnusable,
	"USER_CANCELLED":          authn.ReasonRefused,
	"SIGNATURE_HASH_MISMATCH": authn.ReasonAccountUnusable,
	"PHONE_ABSENT":            authn.ReasonAccountUnusable,
	"DELIVERY_ERROR":          authn.ReasonUpstreamError,
	"SIM_ERROR":               authn.ReasonAccountUnusable,
}

// Outcome maps a COMPLETE non-OK result to a typed error.
func Outcome(st *Status) error {
	if st == nil || st.State != "COMPLETE" {
		return &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "session not complete"}
	}
	r, ok := results[st.Result]
	if !ok {
		return &authn.Error{Reason: authn.ReasonUnknownEndResult, Detail: "unknown result"}
	}
	if r != "" {
		return &authn.Error{Reason: r, Detail: "result " + st.Result}
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
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
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "request failed", Retryable: ctx.Err() == nil, Cause: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxBody+1))
	if err != nil {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "read failed", Retryable: true, Cause: err}
	}
	if int64(len(data)) > c.cfg.MaxBody {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "response exceeds size cap"}
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return data, nil
	case resp.StatusCode == http.StatusNotFound && method == http.MethodGet:
		return nil, &authn.Error{Reason: authn.ReasonExpired, Detail: "session not found (expired)"} // §3.3.9
	case resp.StatusCode >= 500:
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "HTTP " + strconv.Itoa(resp.StatusCode), Retryable: method == http.MethodGet}
	case resp.StatusCode == http.StatusBadRequest && method == http.MethodPost:
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "request refused (HTTP 400)"}
	}
	return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "HTTP " + strconv.Itoa(resp.StatusCode)}
}
