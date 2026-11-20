// Package jose is a narrow, allow-list-only JWS/JWK implementation for the
// two algorithms eidbridge supports: RS256 and ES256 (RFC 7515, 7517, 7518,
// 7638, and the RFC 8725 best practices). "none" and HMAC are never accepted.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Algorithms.
const (
	RS256 = "RS256"
	ES256 = "ES256"
)

var b64 = base64.RawURLEncoding

// Key is a signing key with its key ID.
type Key struct {
	KID     string
	Alg     string
	Private crypto.Signer
}

// Public returns the public key.
func (k *Key) Public() crypto.PublicKey { return k.Private.Public() }

// Header is a JWS protected header.
type Header struct {
	Alg string `json:"alg"`
	KID string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Sign produces a compact JWS over the JSON encoding of claims.
func Sign(k *Key, typ string, claims any) (string, error) {
	if err := CheckKey(k.Alg, k.Public()); err != nil {
		return "", err
	}
	h, _ := json.Marshal(Header{Alg: k.Alg, KID: k.KID, Typ: typ})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(input))
	var sig []byte
	switch k.Alg {
	case RS256:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.Private.(*rsa.PrivateKey), crypto.SHA256, d[:])
	case ES256:
		r, s, e := ecdsa.Sign(rand.Reader, k.Private.(*ecdsa.PrivateKey), d[:])
		err = e
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	}
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// CheckKey enforces algorithm/key pairing and minimum sizes: RSA ≥ 2048 bits
// for RS256, P-256 only for ES256.
func CheckKey(alg string, pub crypto.PublicKey) error {
	switch alg {
	case RS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return errors.New("jose: RS256 needs an RSA key of at least 2048 bits")
		}
	case ES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return errors.New("jose: ES256 needs a P-256 key")
		}
	default:
		return fmt.Errorf("jose: algorithm %q not allowed", alg)
	}
	return nil
}

// MaxJWS bounds input size.
const MaxJWS = 16 << 10

// Verify checks a compact JWS with keys selected by the allow-listed alg.
// keyFor returns candidate keys for (alg, kid). It returns the header and
// raw payload.
func Verify(jws string, allowed []string, keyFor func(alg, kid string) []crypto.PublicKey) (Header, []byte, error) {
	var h Header
	if len(jws) > MaxJWS {
		return h, nil, errors.New("jose: token too large")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return h, nil, errors.New("jose: malformed compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, nil, errors.New("jose: bad header encoding")
	}
	dec := json.NewDecoder(strings.NewReader(string(hb)))
	if err := dec.Decode(&h); err != nil {
		return h, nil, errors.New("jose: bad header")
	}
	var crit map[string]any
	json.Unmarshal(hb, &crit)
	if _, ok := crit["crit"]; ok {
		return h, nil, errors.New("jose: crit header not supported")
	}
	ok := false
	for _, a := range allowed {
		ok = ok || a == h.Alg
	}
	if !ok {
		return h, nil, fmt.Errorf("jose: algorithm %q not allowed", h.Alg)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, nil, errors.New("jose: bad payload encoding")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return h, nil, errors.New("jose: bad signature encoding")
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	for _, pub := range keyFor(h.Alg, h.KID) {
		if CheckKey(h.Alg, pub) != nil {
			continue
		}
		switch h.Alg {
		case RS256:
			if rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig) == nil {
				return h, payload, nil
			}
		case ES256:
			if len(sig) == 64 && ecdsa.Verify(pub.(*ecdsa.PublicKey), d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				return h, payload, nil
			}
		}
	}
	return h, nil, errors.New("jose: signature does not verify")
}

// JWK is a public JSON Web Key (RSA or EC P-256 only).
type JWK struct {
	Kty string `json:"kty"`
	KID string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// PublicJWK encodes a public key.
func PublicJWK(pub crypto.PublicKey, kid, alg string) (JWK, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", KID: kid, Use: "sig", Alg: alg, N: b64.EncodeToString(k.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return JWK{}, errors.New("jose: only P-256")
		}
		x, y := make([]byte, 32), make([]byte, 32)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		return JWK{Kty: "EC", KID: kid, Use: "sig", Alg: alg, Crv: "P-256", X: b64.EncodeToString(x), Y: b64.EncodeToString(y)}, nil
	}
	return JWK{}, errors.New("jose: unsupported key type")
}

// Key decodes a JWK into a public key.
func (j JWK) Key() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(j.N)
		e, err2 := b64.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("jose: bad RSA JWK")
		}
		k := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if k.N.BitLen() < 2048 || k.E < 3 {
			return nil, errors.New("jose: weak RSA JWK")
		}
		return k, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("jose: only P-256 EC JWK")
		}
		x, err1 := b64.DecodeString(j.X)
		y, err2 := b64.DecodeString(j.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("jose: bad EC JWK")
		}
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !k.Curve.IsOnCurve(k.X, k.Y) {
			return nil, errors.New("jose: EC point not on curve")
		}
		return k, nil
	}
	return nil, errors.New("jose: unsupported kty")
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint, base64url.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	j, err := PublicJWK(pub, "", "")
	if err != nil {
		return "", err
	}
	var m string
	if j.Kty == "RSA" {
		m = `{"e":"` + j.E + `","kty":"RSA","n":"` + j.N + `"}`
	} else {
		m = `{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	}
	s := sha256.Sum256([]byte(m))
	return b64.EncodeToString(s[:]), nil
}
