// Package webeid validates Web eID authentication tokens (ID-card and other
// smart-card eIDs through the Web eID browser extension) and adapts the
// validator to authn.Method. Implemented from the Web eID system
// architecture document (https://github.com/web-eid/web-eid-system-architecture-doc,
// README sha256 pinned in docs/adr/0005-web-eid.md), sections "Web eID
// authentication token specification" and "Authentication".
package webeid

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// Token is a Web eID authentication token, format web-eid:1.0 or 1.1.
// Every unverified field comes from the user's untrusted environment.
type Token struct {
	UnverifiedCertificate              string          `json:"unverifiedCertificate"`
	UnverifiedIntermediateCertificates []string        `json:"unverifiedIntermediateCertificates,omitempty"`
	UnverifiedSigningCertificates      json.RawMessage `json:"unverifiedSigningCertificates,omitempty"`
	Algorithm                          string          `json:"algorithm"`
	Signature                          string          `json:"signature"`
	Format                             string          `json:"format"`
	AppVersion                         string          `json:"appVersion"`

	cert          *x509.Certificate
	intermediates []*x509.Certificate
	sig           []byte
}

// Limits on untrusted input.
const (
	MaxTokenBytes    = 32 << 10
	maxIntermediates = 4
)

// Algorithms allowed by the specification (JWA §3.3–3.5).
var algorithms = map[string]bool{"ES256": true, "ES384": true, "ES512": true, "PS256": true, "PS384": true, "PS512": true,
	"RS256": true, "RS384": true, "RS512": true}

func bad(detail string) error {
	return &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: detail}
}

// ParseToken parses and shape-checks a token: size cap, known format major
// version, allowed algorithm, decodable signature and certificates. It does
// not establish any trust.
func ParseToken(b []byte) (*Token, error) {
	if len(b) == 0 || len(b) > MaxTokenBytes {
		return nil, bad("token empty or too large")
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, bad("token is not JSON")
	}
	// Minor versions are backwards-compatible within major version 1.
	ver, ok := strings.CutPrefix(t.Format, "web-eid:1")
	if !ok || len(ver) < 2 || len(ver) > 4 || ver[0] != '.' || strings.Trim(ver[1:], "0123456789") != "" {
		return nil, bad("unsupported token format")
	}
	if !algorithms[t.Algorithm] {
		return nil, bad("algorithm not allowed")
	}
	var err error
	if t.sig, err = base64.StdEncoding.DecodeString(t.Signature); err != nil || len(t.sig) == 0 || len(t.sig) > 1024 {
		return nil, bad("signature is not Base64")
	}
	der, err := base64.StdEncoding.DecodeString(t.UnverifiedCertificate)
	if err != nil || len(der) == 0 {
		return nil, bad("certificate is not Base64")
	}
	if t.cert, err = x509.ParseCertificate(der); err != nil {
		return nil, bad("certificate does not parse")
	}
	if t.UnverifiedIntermediateCertificates != nil && len(t.UnverifiedIntermediateCertificates) == 0 {
		return nil, bad("intermediate certificate list present but empty")
	}
	if len(t.UnverifiedIntermediateCertificates) > maxIntermediates {
		return nil, bad("too many intermediate certificates")
	}
	for _, s := range t.UnverifiedIntermediateCertificates {
		d, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, bad("intermediate certificate is not Base64")
		}
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, bad("intermediate certificate does not parse")
		}
		t.intermediates = append(t.intermediates, c)
	}
	return &t, nil
}
