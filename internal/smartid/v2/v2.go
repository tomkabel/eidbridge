// Package v2 is the legacy Smart-ID RP API v2 authentication (Story 7.5,
// FR-029), implemented from SK-EID/smart-id-documentation branch v2
// (README sha256 pinned in docs/adr/0007-smart-id-v2.md). It shares the
// Smart-ID certificate checks with the v3 package. v3 is recommended; v2
// exists only for deployments that cannot move yet.
//
// v2 has no device link: the user types their identity and the request is
// pushed to their app (notification flow).
package v2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Config configures a v2 client.
type Config struct {
	BaseURL      string // e.g. https://sid.demo.sk.ee/smart-id-rp/v2
	RPUUID       string
	RPName       string
	HTTP         *http.Client
	Trust        *smartid.TrustStore
	MinCertLevel string
	PolicyOIDs   []asn1.ObjectIdentifier
	Status       smartid.StatusChecker
	MaxBody      int64
	Now          func() time.Time
}

// Client is safe for concurrent use.
type Client struct{ cfg Config }

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	oidSN  = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGN  = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSur = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// NewClient validates cfg.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, errors.New("smartid v2: BaseURL must be https (http only on loopback for fixtures)")
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if !uuidRe.MatchString(cfg.RPUUID) || cfg.RPName == "" || len(cfg.RPName) > 32 || cfg.HTTP == nil || cfg.Trust == nil || cfg.Trust.Empty() || cfg.Status == nil {
		return nil, errors.New("smartid v2: RP UUID, RP name (≤ 32 bytes), HTTP client, trust and status checker are required")
	}
	if smartid.LevelRank(cfg.MinCertLevel) == 0 {
		return nil, errors.New("smartid v2: MinCertLevel must be ADVANCED or QUALIFIED")
	}
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 64 << 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg}, nil
}

func isLoopback(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || ip != nil && ip.IsLoopback()
}

// Session is a started authentication.
type Session struct {
	ID       string
	Hash     []byte // SHA-512 of 64 random bytes; erased by Destroy
	VC       string
	Expected string // PNO<country>-<code> the user typed
}

// Destroy erases the hash and the requested identity.
func (s *Session) Destroy() {
	for i := range s.Hash {
		s.Hash[i] = 0
	}
	s.Hash, s.Expected = nil, ""
}

// VerificationCode is integer(SHA256(hash)[-2:]) mod 10000 (§2.3.12.2).
func VerificationCode(hash []byte) string {
	s := sha256.Sum256(hash)
	return fmt.Sprintf("%04d", (int(s[30])<<8|int(s[31]))%10000)
}

// Start sends an authentication request to the person's ETSI semantics
// identifier (PNOEE-…), validated locally first.
func (c *Client) Start(ctx context.Context, semanticsID, displayText60 string) (*Session, error) {
	if smartid.ValidateSemanticsID(semanticsID) != nil {
		return nil, &authn.Error{Reason: authn.ReasonInvalidInput, Detail: "identifier failed local validation"}
	}
	if displayText60 == "" || utf8.RuneCountInString(displayText60) > 60 {
		return nil, errors.New("smartid v2: display text must be 1–60 characters")
	}
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	sum := sha512.Sum512(seed)
	hash := sum[:]
	body, _ := json.Marshal(map[string]any{"relyingPartyUUID": c.cfg.RPUUID, "relyingPartyName": c.cfg.RPName,
		"certificateLevel": c.cfg.MinCertLevel, "hash": base64.StdEncoding.EncodeToString(hash), "hashType": "SHA512",
		"allowedInteractionsOrder": []map[string]string{{"type": "displayTextAndPIN", "displayText60": displayText60}}})
	resp, err := c.do(ctx, http.MethodPost, "/authentication/etsi/"+url.PathEscape(semanticsID), body)
	if err != nil {
		return nil, err
	}
	var out struct {
		SessionID string `json:"sessionID"`
	}
	if json.Unmarshal(resp, &out) != nil || !uuidRe.MatchString(out.SessionID) {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "malformed session response"}
	}
	return &Session{ID: out.SessionID, Hash: hash, VC: VerificationCode(hash), Expected: semanticsID}, nil
}

// Status is a v2 session status (§2.3.11.4).
type Status struct {
	State  string `json:"state"`
	Result struct {
		EndResult      string `json:"endResult"`
		DocumentNumber string `json:"documentNumber"`
	} `json:"result"`
	Signature *struct {
		Value     string `json:"value"`
		Algorithm string `json:"algorithm"`
	} `json:"signature"`
	Cert *struct {
		Value            string `json:"value"`
		CertificateLevel string `json:"certificateLevel"`
	} `json:"cert"`
}

// Poll long-polls the session status once.
func (c *Client) Poll(ctx context.Context, id string, timeout time.Duration) (*Status, error) {
	if !uuidRe.MatchString(id) {
		return nil, errors.New("smartid v2: invalid session id")
	}
	ms := min(max(timeout.Milliseconds(), 1000), 120000)
	b, err := c.do(ctx, http.MethodGet, "/session/"+id+"?timeoutMs="+strconv.FormatInt(ms, 10), nil)
	if err != nil {
		return nil, err
	}
	var st Status
	if json.Unmarshal(b, &st) != nil || (st.State != "RUNNING" && st.State != "COMPLETE") {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "malformed status"}
	}
	return &st, nil
}

// endResults maps §2.3.11.5 codes to reasons (empty: OK).
var endResults = map[string]string{"OK": "", "USER_REFUSED": authn.ReasonRefused, "TIMEOUT": authn.ReasonExpired,
	"DOCUMENT_UNUSABLE": authn.ReasonAccountUnusable, "WRONG_VC": authn.ReasonWrongCode,
	"REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP": authn.ReasonAccountUnusable, "USER_REFUSED_CERT_CHOICE": authn.ReasonRefused,
	"USER_REFUSED_DISPLAYTEXTANDPIN": authn.ReasonRefused, "USER_REFUSED_VC_CHOICE": authn.ReasonRefused,
	"USER_REFUSED_CONFIRMATIONMESSAGE": authn.ReasonRefused, "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE": authn.ReasonRefused}

func vfail(d string) error { return &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: d} }

var sigHash = map[string]crypto.Hash{"sha256WithRSAEncryption": crypto.SHA256, "sha384WithRSAEncryption": crypto.SHA384, "sha512WithRSAEncryption": crypto.SHA512}

// Identity is a verified v2 result.
type Identity struct{ IDType, Country, Code, GivenName, Surname, CertLevel string }

// Verify follows §2.3.12.3, failing closed: end result OK; certificate
// present, chains to configured CAs, not a CA, Smart-ID authentication
// purpose, required policies, level at least the minimum; identity equals
// the requested identifier and owns the document number; signature
// (RSA ≥ 2048, PKCS #1 v1.5 with SHA-512 as requested) over the submitted
// hash; certificate status good.
func (c *Client) Verify(ctx context.Context, s *Session, st *Status) (*Identity, error) {
	if s == nil || s.Hash == nil {
		return nil, vfail("session destroyed or missing")
	}
	if st == nil || st.State != "COMPLETE" {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "session not complete"}
	}
	reason, known := endResults[st.Result.EndResult]
	if !known {
		return nil, &authn.Error{Reason: authn.ReasonUnknownEndResult, Detail: "unknown endResult"}
	}
	if reason != "" {
		return nil, &authn.Error{Reason: reason, Detail: "endResult " + st.Result.EndResult}
	}
	if st.Cert == nil || st.Signature == nil || st.Cert.Value == "" || st.Signature.Value == "" || st.Result.DocumentNumber == "" {
		return nil, vfail("missing certificate, signature or document number")
	}
	der, err := base64.StdEncoding.DecodeString(st.Cert.Value)
	if err != nil {
		return nil, vfail("cert is not Base64")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, vfail("cert does not parse")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: c.cfg.Trust.Roots, Intermediates: c.cfg.Trust.Intermediates,
		CurrentTime: c.cfg.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 || leaf.IsCA {
		return nil, vfail("certificate chain does not verify to a configured CA")
	}
	for _, p := range c.cfg.PolicyOIDs {
		if !smartid.HasPolicy(leaf, p) {
			return nil, vfail("required certificate policy missing")
		}
	}
	if !smartid.AuthPurpose(leaf) {
		return nil, vfail("certificate is not an authentication certificate")
	}
	level, ok := smartid.AuthenticationLevel(leaf)
	if !ok || level != st.Cert.CertificateLevel || smartid.LevelRank(level) < smartid.LevelRank(c.cfg.MinCertLevel) {
		return nil, vfail("certificate level invalid, mismatched, or below the required minimum")
	}
	idType, country, code, ok := smartid.ParseSerialNumber(smartid.SubjectAttr(leaf.Subject, oidSN))
	if !ok {
		return nil, vfail("subject serialNumber is not PNO/PAS/IDC")
	}
	got := idType + country + "-" + code
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.Expected)) != 1 {
		return nil, &authn.Error{Reason: authn.ReasonIdentityMismatch, Detail: "certificate identity differs from requested identity"}
	}
	if !strings.HasPrefix(st.Result.DocumentNumber, got+"-") {
		return nil, &authn.Error{Reason: authn.ReasonIdentityMismatch, Detail: "documentNumber does not belong to the certificate subject"}
	}
	h, ok := sigHash[st.Signature.Algorithm]
	if !ok || h != crypto.SHA512 {
		return nil, vfail("signature algorithm does not match the requested SHA-512")
	}
	sig, err := base64.StdEncoding.DecodeString(st.Signature.Value)
	if err != nil {
		return nil, vfail("signature is not Base64")
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, vfail("certificate key is not RSA-2048 or stronger")
	}
	if rsa.VerifyPKCS1v15(pub, crypto.SHA512, s.Hash, sig) != nil {
		return nil, vfail("signature does not verify over the submitted hash")
	}
	if err := c.cfg.Status.Check(ctx, leaf, chains[0][1]); err != nil {
		if err == smartid.ErrRevoked {
			return nil, vfail("certificate revoked")
		}
		return nil, &authn.Error{Reason: authn.ReasonStatusUnavailable, Detail: "certificate status unavailable", Cause: err}
	}
	return &Identity{IDType: idType, Country: country, Code: code, GivenName: smartid.SubjectAttr(leaf.Subject, oidGN),
		Surname: smartid.SubjectAttr(leaf.Subject, oidSur), CertLevel: level}, nil
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
	if err != nil || int64(len(data)) > c.cfg.MaxBody {
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "response unreadable or too large"}
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return data, nil
	case resp.StatusCode == http.StatusNotFound && method == http.MethodPost:
		return nil, &authn.Error{Reason: authn.ReasonAccountUnusable, Detail: "no Smart-ID account (404)"}
	case resp.StatusCode == http.StatusNotFound:
		return nil, &authn.Error{Reason: authn.ReasonExpired, Detail: "session not found (404)"}
	case resp.StatusCode == 471 || resp.StatusCode == 472:
		return nil, &authn.Error{Reason: authn.ReasonAccountUnusable, Detail: "account not usable (" + strconv.Itoa(resp.StatusCode) + ")"}
	case resp.StatusCode >= 500:
		return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "HTTP " + strconv.Itoa(resp.StatusCode), Retryable: method == http.MethodGet}
	}
	return nil, &authn.Error{Reason: authn.ReasonUpstreamError, Detail: "HTTP " + strconv.Itoa(resp.StatusCode)}
}
