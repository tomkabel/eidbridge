package webeid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Validator checks tokens against configured trust. It holds no per-flow
// state: the caller supplies the flow's nonce and enforces single use.
type Validator struct {
	Trust *smartid.TrustStore
	// DisallowedPolicies rejects certificates carrying any of these
	// policies (for example Mobile-ID or e-Seal policies on a card CA).
	DisallowedPolicies []asn1.ObjectIdentifier
	Status             smartid.StatusChecker
	Now                func() time.Time
}

// Identity is a verified card holder.
type Identity struct {
	IDType, Country, Code, GivenName, Surname string
}

var (
	oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGivenName    = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname      = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// ASCIIOrigin returns the ASCII serialization of an https origin
// (scheme "://" host [":" port], no trailing slash, default port omitted).
// The caller must pass the bridge's configured public origin, never a value
// from the request.
func ASCIIOrigin(public string) (string, error) {
	u, err := url.Parse(public)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("webeid: origin must be an https origin")
	}
	host := strings.ToLower(u.Hostname())
	for _, c := range host {
		if c > 127 {
			return "", errors.New("webeid: origin host must be ASCII (Punycode)")
		}
	}
	if p := u.Port(); p != "" && p != "443" {
		host += ":" + p
	}
	return "https://" + host, nil
}

// Validate checks a parsed token for one flow. Steps, failing closed:
//
//  1. certificate validity period covers now
//  2. purpose: client authentication (EKU) and digitalSignature
//  3. no disallowed certificate policy
//  4. chain to configured CAs; token intermediates are untrusted candidates
//  5. signature over hash(origin)+hash(nonce) with the token's algorithm,
//     whose family and curve must match the certificate key
//  6. subject identity is present and well-formed
//  7. certificate status (OCSP/CRL); unknown fails closed
//
// The nonce and origin are checked only implicitly through the signature,
// as the specification intends; the caller binds the nonce to the flow.
func (v *Validator) Validate(ctx context.Context, t *Token, origin, nonce string) (*Identity, error) {
	if t == nil || t.cert == nil {
		return nil, bad("token not parsed")
	}
	if len(nonce) < 44 || len(nonce) > 128 {
		return nil, bad("nonce length outside 44–128")
	}
	now := v.Now()
	leaf := t.cert
	// 1
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, bad("certificate not valid at this time")
	}
	// 2
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuth(leaf) {
		return nil, bad("certificate is not a client-authentication certificate")
	}
	// 3
	for _, p := range leaf.PolicyIdentifiers {
		for _, d := range v.DisallowedPolicies {
			if p.Equal(d) {
				return nil, bad("certificate carries a disallowed policy")
			}
		}
	}
	// 4
	inter := v.Trust.Intermediates.Clone()
	for _, c := range t.intermediates {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.Trust.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return nil, bad("certificate chain does not verify to a configured CA")
	}
	// 5
	if err := verifySignature(leaf.PublicKey, t.Algorithm, t.sig, origin, nonce); err != nil {
		return nil, err
	}
	// 6
	idType, country, code, ok := smartid.ParseSerialNumber(attr(leaf.Subject, oidSerialNumber))
	if !ok {
		return nil, bad("subject serialNumber is not PNO/PAS/IDC")
	}
	// 7
	if err := v.Status.Check(ctx, leaf, chains[0][1]); err != nil {
		if err == smartid.ErrRevoked {
			return nil, bad("certificate revoked")
		}
		return nil, &authn.Error{Reason: authn.ReasonStatusUnavailable, Detail: "certificate status unavailable", Cause: err}
	}
	return &Identity{IDType: idType, Country: country, Code: code, GivenName: attr(leaf.Subject, oidGivenName), Surname: attr(leaf.Subject, oidSurname)}, nil
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, e := range c.ExtKeyUsage {
		if e == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

var hashFor = map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}

// SignedData returns hash(origin)+hash(nonce) for the algorithm's hash.
func SignedData(alg, origin, nonce string) ([]byte, crypto.Hash, error) {
	if len(alg) != 5 || !algorithms[alg] {
		return nil, 0, bad("algorithm not allowed")
	}
	h := hashFor[alg[2:]]
	ho, hn := h.New(), h.New()
	ho.Write([]byte(origin))
	hn.Write([]byte(nonce))
	return append(ho.Sum(nil), hn.Sum(nil)...), h, nil
}

func verifySignature(pub crypto.PublicKey, alg string, sig []byte, origin, nonce string) error {
	data, h, err := SignedData(alg, origin, nonce)
	if err != nil {
		return err
	}
	d := h.New()
	d.Write(data)
	digest := d.Sum(nil)
	switch alg[:2] {
	case "ES":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return bad("ES algorithm with a non-EC key")
		}
		want := map[string]elliptic.Curve{"256": elliptic.P256(), "384": elliptic.P384(), "512": elliptic.P521()}[alg[2:]]
		if k.Curve != want {
			return bad("ES algorithm does not match the key curve")
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n { // JWS ECDSA signatures are raw r||s
			return bad("ECDSA signature has the wrong length")
		}
		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, digest, r, s) {
			return bad("signature does not verify over origin and nonce")
		}
	case "RS", "PS":
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return bad("RSA algorithm with a non-RSA or short key")
		}
		var err error
		if alg[0] == 'R' {
			err = rsa.VerifyPKCS1v15(k, h, digest, sig)
		} else {
			err = rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		}
		if err != nil {
			return bad("signature does not verify over origin and nonce")
		}
	default:
		return bad("algorithm not allowed")
	}
	return nil
}

func attr(n pkix.Name, oid asn1.ObjectIdentifier) string {
	for _, a := range n.Names {
		if a.Type.Equal(oid) {
			if s, ok := a.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}
