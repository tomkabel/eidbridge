// Package eudi is the OpenID4VP verifier for EUDI Wallet PID presentations
// in SD-JWT VC format. Specifications are pinned in docs/adr/0006-eudi-openid4vp.md:
// OpenID for Verifiable Presentations 1.0, SD-JWT (RFC 9901), SD-JWT VC
// (IETF draft, version pinned in the ADR) and Token Status List.
package eudi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// header is the protected header fields this package uses.
type header struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ,omitempty"`
	KID  string          `json:"kid,omitempty"`
	X5C  []string        `json:"x5c,omitempty"`
	JWK  json.RawMessage `json:"jwk,omitempty"`
	Crit []string        `json:"crit,omitempty"`
}

// esAlgs maps the allowed algorithms (ECDSA only; no none, HMAC or RSA).
var esAlgs = map[string]struct {
	h     crypto.Hash
	curve elliptic.Curve
}{"ES256": {crypto.SHA256, elliptic.P256()}, "ES384": {crypto.SHA384, elliptic.P384()}, "ES512": {crypto.SHA512, elliptic.P521()}}

const maxJWS = 64 << 10

// parseJWS splits and decodes a compact JWS without verifying it.
func parseJWS(s string) (h header, payload []byte, signingInput string, sig []byte, err error) {
	if len(s) > maxJWS {
		return h, nil, "", nil, errors.New("JWS too large")
	}
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return h, nil, "", nil, errors.New("malformed compact JWS")
	}
	hb, err := b64.DecodeString(p[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return h, nil, "", nil, errors.New("bad JWS header")
	}
	if len(h.Crit) > 0 {
		return h, nil, "", nil, errors.New("crit header not supported")
	}
	if _, ok := esAlgs[h.Alg]; !ok {
		return h, nil, "", nil, fmt.Errorf("JWS algorithm %q not allowed", h.Alg)
	}
	if payload, err = b64.DecodeString(p[1]); err != nil {
		return h, nil, "", nil, errors.New("bad JWS payload")
	}
	if sig, err = b64.DecodeString(p[2]); err != nil {
		return h, nil, "", nil, errors.New("bad JWS signature encoding")
	}
	return h, payload, p[0] + "." + p[1], sig, nil
}

// verifyES checks an ECDSA JWS signature; the key curve must match alg.
func verifyES(alg string, pub crypto.PublicKey, signingInput string, sig []byte) error {
	a := esAlgs[alg]
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || a.curve == nil || k.Curve != a.curve {
		return errors.New("key does not match the JWS algorithm")
	}
	n := (k.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return errors.New("ECDSA signature has the wrong length")
	}
	d := a.h.New()
	d.Write([]byte(signingInput))
	if !ecdsa.Verify(k, d.Sum(nil), new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
		return errors.New("JWS signature does not verify")
	}
	return nil
}

// signES produces a compact JWS with the given header (alg must fit key).
func signES(k *ecdsa.PrivateKey, h header, claims any) (string, error) {
	a, ok := esAlgs[h.Alg]
	if !ok || k.Curve != a.curve {
		return "", errors.New("signing key does not match the algorithm")
	}
	hb, _ := json.Marshal(h)
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	d := a.h.New()
	d.Write([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, d.Sum(nil))
	if err != nil {
		return "", err
	}
	n := (k.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return in + "." + b64.EncodeToString(sig), nil
}

// x5cChain decodes an x5c header (standard Base64 DER, leaf first).
func x5cChain(x5c []string) ([]*x509.Certificate, error) {
	if len(x5c) == 0 || len(x5c) > 5 {
		return nil, errors.New("x5c missing or too long")
	}
	var out []*x509.Certificate
	for _, s := range x5c {
		d, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("x5c entry is not Base64")
		}
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, errors.New("x5c entry does not parse")
		}
		out = append(out, c)
	}
	return out, nil
}

// ecJWK decodes a public EC JWK (P-256, P-384, P-521).
func ecJWK(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var j struct {
		Kty, Crv, X, Y, D string
	}
	if json.Unmarshal(raw, &j) != nil || j.Kty != "EC" || j.D != "" {
		return nil, errors.New("holder key is not a public EC JWK")
	}
	c := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[j.Crv]
	if c == nil {
		return nil, errors.New("holder key curve not allowed")
	}
	xb, err1 := b64.DecodeString(j.X)
	yb, err2 := b64.DecodeString(j.Y)
	n := (c.Params().BitSize + 7) / 8
	if err1 != nil || err2 != nil || len(xb) != n || len(yb) != n {
		return nil, errors.New("holder key coordinates malformed")
	}
	k := &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !c.IsOnCurve(k.X, k.Y) {
		return nil, errors.New("holder key is not on its curve")
	}
	return k, nil
}

// publicJWK encodes an EC public key as a JWK object.
func publicJWK(k *ecdsa.PublicKey) map[string]string {
	n := (k.Curve.Params().BitSize + 7) / 8
	x, y := make([]byte, n), make([]byte, n)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]string{"kty": "EC", "crv": k.Curve.Params().Name, "x": b64.EncodeToString(x), "y": b64.EncodeToString(y)}
}
