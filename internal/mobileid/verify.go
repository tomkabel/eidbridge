package mobileid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

// Identity is a verified Mobile-ID person.
type Identity struct {
	Country, Code, GivenName, Surname string
}

var (
	oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGivenName    = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname      = asn1.ObjectIdentifier{2, 5, 4, 4}
	// MIDPolicyOID is carried by demo and live Mobile-ID authentication
	// certificates (observed on the demo certificate, 2026-11-20).
	MIDPolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 18, 1}
)

func vfail(detail string) error {
	return &authn.Error{Reason: authn.ReasonVerificationFailed, Detail: detail}
}

// Verify checks a COMPLETE status against the session that created it
// (MID REST API §3.3.6 plus the bridge's own checks), failing closed:
//
//  1. result is OK
//  2. signature and certificate are present and well-formed
//  3. signature algorithm matches the requested hash type and the key type
//  4. certificate chains to a configured CA at the current time, not a CA
//  5. required certificate policies are present
//  6. purpose: digitalSignature, not a signing (nonRepudiation) certificate
//  7. identity: subject serialNumber PNO<country>-<code> equals the request
//  8. signature verifies over the submitted hash with the certificate key
//  9. certificate status (OCSP/CRL) is good; unknown fails closed
func (c *Client) Verify(ctx context.Context, s *Session, st *Status) (*Identity, error) {
	if s == nil || s.Hash == nil {
		return nil, vfail("session destroyed or missing")
	}
	// 1
	if err := Outcome(st); err != nil {
		return nil, err
	}
	// 2
	if st.Signature == nil || st.Signature.Value == "" || st.Cert == "" {
		return nil, vfail("missing signature or certificate")
	}
	sig, err := base64.StdEncoding.DecodeString(st.Signature.Value)
	if err != nil {
		return nil, vfail("signature is not Base64")
	}
	der, err := base64.StdEncoding.DecodeString(st.Cert)
	if err != nil {
		return nil, vfail("cert is not Base64")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, vfail("cert does not parse")
	}
	// 3
	alg := st.Signature.Algorithm
	if !strings.HasPrefix(alg, s.hashType+"With") {
		return nil, vfail("signature algorithm does not match the requested hash type")
	}
	switch strings.TrimPrefix(alg, s.hashType+"With") {
	case "ECEncryption":
		if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, vfail("EC signature with a non-EC certificate key")
		}
	case "RSAEncryption":
		if k, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() < 2048 {
			return nil, vfail("RSA signature with a non-RSA or short certificate key")
		}
	default:
		return nil, vfail("unsupported signature algorithm")
	}
	// 4
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: c.cfg.Trust.Roots, Intermediates: c.cfg.Trust.Intermediates,
		CurrentTime: c.cfg.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return nil, vfail("certificate chain does not verify to a configured CA")
	}
	if leaf.IsCA {
		return nil, vfail("end-entity certificate is a CA")
	}
	// 5
	for _, want := range c.cfg.PolicyOIDs {
		found := false
		for _, p := range leaf.PolicyIdentifiers {
			if p.Equal(want) {
				found = true
			}
		}
		if !found {
			return nil, vfail("required certificate policy missing")
		}
	}
	// 6
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		return nil, vfail("certificate is not an authentication certificate")
	}
	// 7
	idType, country, code, ok := smartid.ParseSerialNumber(attr(leaf.Subject, oidSerialNumber))
	if !ok || idType != "PNO" {
		return nil, vfail("subject serialNumber is not PNO")
	}
	if subtle.ConstantTimeCompare([]byte(country+"-"+code), []byte(s.Country+"-"+s.Code)) != 1 {
		return nil, &authn.Error{Reason: authn.ReasonIdentityMismatch, Detail: "certificate identity differs from requested identity"}
	}
	// 8
	if !verifySig(leaf.PublicKey, s.Hash, sig) {
		return nil, vfail("signature does not verify over the submitted hash")
	}
	// 9
	if err := c.cfg.Status.Check(ctx, leaf, chains[0][1]); err != nil {
		if err == smartid.ErrRevoked {
			return nil, vfail("certificate revoked")
		}
		return nil, &authn.Error{Reason: authn.ReasonStatusUnavailable, Detail: "certificate status unavailable", Cause: err}
	}
	return &Identity{Country: country, Code: code, GivenName: attr(leaf.Subject, oidGivenName), Surname: attr(leaf.Subject, oidSurname)}, nil
}

// verifySig checks a signature over a SHA-256 hash. EC signatures are the
// raw r||s concatenation the service returns (observed: 64 bytes for
// P-256); ASN.1 DER is accepted too. RSA is PKCS #1 v1.5.
func verifySig(pub crypto.PublicKey, hash, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) == 2*n {
			r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
			return ecdsa.Verify(k, hash, r, s)
		}
		return ecdsa.VerifyASN1(k, hash, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, hash, sig) == nil
	}
	return false
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
