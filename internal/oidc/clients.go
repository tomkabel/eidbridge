package oidc

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/jose"
)

// Client authentication methods.
const (
	AuthBasic   = "client_secret_basic"
	AuthPost    = "client_secret_post"
	AuthPrivKey = "private_key_jwt"
)

// Client is a statically configured OIDC client.
type Client struct {
	ID           string     `json:"client_id"`
	Secret       string     `json:"client_secret,omitempty"`
	AuthMethod   string     `json:"token_endpoint_auth_method"`
	RedirectURIs []string   `json:"redirect_uris"`
	JWKS         []jose.JWK `json:"jwks,omitempty"`
	JWKSURI      string     `json:"jwks_uri,omitempty"` // always rejected (A06)
	SubMode      string     `json:"sub_mode"`           // public or pairwise
	SectorID     string     `json:"sector_id,omitempty"`
	IDTokenAlg   string     `json:"id_token_signed_response_alg,omitempty"`
	PersonalCode bool       `json:"personal_code_allowed,omitempty"`
	// AllowedMethods restricts methods (empty: all enabled).
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	// DisplayText overrides the on-device interaction text per language.
	DisplayText map[string]string `json:"display_text,omitempty"`
	// DemoLoopback allows the exact static http://localhost:<port>/<path>
	// redirect URIs registered here (demo mode only).
	keys []crypto.PublicKey
}

func (c *Client) sector() string {
	if c.SubMode == "public" {
		return "g:public"
	}
	id := c.SectorID
	if id == "" {
		id = c.ID
	}
	return "c:" + id
}

// validateClients checks static registrations (startup invariants).
func validateClients(cs []Client, demo bool) error {
	seen := map[string]bool{}
	sectors := map[string]string{}
	for i := range cs {
		c := &cs[i]
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("oidc: empty or duplicate client_id %q", c.ID)
		}
		seen[c.ID] = true
		switch c.AuthMethod {
		case AuthBasic, AuthPost:
			if len(c.Secret) < 32 {
				return fmt.Errorf("oidc: client %s: client_secret must be at least 32 characters", c.ID)
			}
			if len(c.JWKS) > 0 || c.JWKSURI != "" {
				return fmt.Errorf("oidc: client %s: secret clients take no keys", c.ID)
			}
		case AuthPrivKey:
			if c.JWKSURI != "" {
				return fmt.Errorf("oidc: client %s: jwks_uri is not supported; register an inline jwks", c.ID)
			}
			if len(c.JWKS) == 0 || c.Secret != "" {
				return fmt.Errorf("oidc: client %s: private_key_jwt needs an inline jwks and no secret", c.ID)
			}
			c.keys = nil
			for _, j := range c.JWKS {
				k, err := j.Key()
				if err != nil {
					return fmt.Errorf("oidc: client %s: %w", c.ID, err)
				}
				c.keys = append(c.keys, k)
			}
		default:
			return fmt.Errorf("oidc: client %s: unsupported token_endpoint_auth_method %q", c.ID, c.AuthMethod)
		}
		if c.IDTokenAlg == "" {
			c.IDTokenAlg = jose.RS256
		}
		if c.IDTokenAlg != jose.RS256 && c.IDTokenAlg != jose.ES256 {
			return fmt.Errorf("oidc: client %s: unsupported id_token_signed_response_alg %q", c.ID, c.IDTokenAlg)
		}
		if c.SubMode != "public" && c.SubMode != "pairwise" {
			return fmt.Errorf("oidc: client %s: sub_mode must be public or pairwise", c.ID)
		}
		if c.SubMode == "pairwise" {
			s := c.sector()
			if other, ok := sectors[s]; ok && (c.SectorID != "" || other != "") {
				return fmt.Errorf("oidc: client %s: sector_id collides with another client", c.ID)
			}
			sectors[s] = c.SectorID
		}
		if len(c.RedirectURIs) == 0 {
			return fmt.Errorf("oidc: client %s: at least one redirect_uri", c.ID)
		}
		for _, r := range c.RedirectURIs {
			if err := validateRedirect(r, demo); err != nil {
				return fmt.Errorf("oidc: client %s: %w", c.ID, err)
			}
		}
	}
	return nil
}

// validateRedirect: HTTPS only; demo mode alone allows exact static
// http://localhost:<port>/<path>; never fragments, userinfo or wildcards.
func validateRedirect(raw string, demo bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || strings.Contains(raw, "*") {
		return fmt.Errorf("invalid redirect_uri %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if demo && u.Hostname() == "localhost" && u.Port() != "" {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri %q must be https (demo: exact http://localhost:<port>/<path>)", raw)
}

// jtiStore records client-assertion jti values until exp plus skew. Insert
// and capacity check are one atomic step; unexpired entries are never
// evicted (A06).
type jtiStore struct {
	mu  sync.Mutex
	cap int
	m   map[string]time.Duration // key → monotonic expiry
	clk clock.Clock
}

var errJTIFull = errors.New("oidc: client assertion replay store full")

func (s *jtiStore) insert(clientID, jti string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Mono()
	key := clientID + "\x00" + jti
	if exp, ok := s.m[key]; ok && now < exp {
		return errors.New("oidc: client assertion jti replayed")
	}
	if len(s.m) >= s.cap {
		for k, exp := range s.m {
			if now >= exp {
				delete(s.m, k)
			}
		}
		if len(s.m) >= s.cap {
			return errJTIFull
		}
	}
	s.m[key] = now + ttl
	return nil
}

// authenticateClient implements the token endpoint client authentication.
// Exactly the registered method is accepted; credentials of two methods in
// one request are invalid_client.
func (p *Provider) authenticateClient(r *http.Request) (*Client, error) {
	user, pass, hasBasic := r.BasicAuth()
	postID, postSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	assertion := r.PostForm.Get("client_assertion")
	n := 0
	if hasBasic {
		n++
	}
	if postSecret != "" {
		n++
	}
	if assertion != "" {
		n++
	}
	if n != 1 {
		return nil, oauthErr(401, "invalid_client", "exactly one client authentication method is required")
	}
	switch {
	case hasBasic:
		id, err1 := url.QueryUnescape(user)
		sec, err2 := url.QueryUnescape(pass)
		if err1 != nil || err2 != nil {
			return nil, oauthErr(401, "invalid_client", "malformed basic credentials")
		}
		if postID != "" && postID != id {
			return nil, oauthErr(401, "invalid_client", "client_id mismatch")
		}
		return p.secretClient(id, sec, AuthBasic)
	case postSecret != "":
		return p.secretClient(postID, postSecret, AuthPost)
	}
	if r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return nil, oauthErr(401, "invalid_client", "unsupported client_assertion_type")
	}
	return p.assertionClient(assertion, postID)
}

func (p *Provider) secretClient(id, secret, method string) (*Client, error) {
	c := p.clients[id]
	// Compare hashes so timing does not depend on secret length.
	var want [32]byte
	if c != nil {
		want = sha256.Sum256([]byte(c.Secret))
	}
	got := sha256.Sum256([]byte(secret))
	if c == nil || c.AuthMethod != method || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return nil, oauthErr(401, "invalid_client", "client authentication failed")
	}
	return c, nil
}

func (p *Provider) assertionClient(assertion, postID string) (*Client, error) {
	fail := oauthErr(401, "invalid_client", "client assertion rejected")
	var peek struct {
		Iss string `json:"iss"`
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, fail
	}
	if b, err := b64url.DecodeString(parts[1]); err != nil || json.Unmarshal(b, &peek) != nil {
		return nil, fail
	}
	c := p.clients[peek.Iss]
	if c == nil || c.AuthMethod != AuthPrivKey || (postID != "" && postID != c.ID) {
		return nil, fail
	}
	_, payload, err := jose.Verify(assertion, []string{jose.RS256, jose.ES256}, func(alg, kid string) []crypto.PublicKey { return c.keys })
	if err != nil {
		return nil, fail
	}
	var cl struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp int64           `json:"exp"`
		JTI string          `json:"jti"`
	}
	if json.Unmarshal(payload, &cl) != nil || cl.Iss != c.ID || cl.Sub != c.ID || cl.JTI == "" || len(cl.JTI) > 256 {
		return nil, fail
	}
	if !audIs(cl.Aud, p.cfg.Issuer) {
		return nil, fail
	}
	now := p.cfg.Clock.Now()
	until := time.Unix(cl.Exp, 0).Sub(now)
	if until <= 0 || until > 60*time.Second+p.cfg.ClockSkew {
		return nil, fail
	}
	if err := p.jti.insert(c.ID, cl.JTI, until+p.cfg.ClockSkew); err != nil {
		if errors.Is(err, errJTIFull) {
			return nil, &oauthError{Status: 503, Code: "temporarily_unavailable", Desc: "try again", RetryAfter: 5}
		}
		return nil, fail
	}
	return c, nil
}

func audIs(raw json.RawMessage, want string) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == want
	}
	var a []string
	if json.Unmarshal(raw, &a) == nil && len(a) == 1 {
		return a[0] == want
	}
	return false
}
