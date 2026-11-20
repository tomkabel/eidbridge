// Package smartidtest provides a synthetic Smart-ID RP API v3 upstream for
// offline tests: a generated test PKI, response signing and an HTTP server
// that behaves like the RP API plus the demo automated testing interface.
// Certificates are generated at run time; identities are SK's published demo
// test codes. Nothing here is trusted outside tests and demo/mock mode.
package smartidtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

// OIDs observed on the demo authentication certificate (ADR 0001).
var (
	OIDAuthEKU    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62306, 5, 7, 0}
	OIDDemoPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 17, 2}
	oidSerial     = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGN         = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSN         = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// PKI is a root, an intermediate and a leaf factory.
type PKI struct {
	Root, Inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

// LeafOptions varies a generated end-entity certificate for negative tests.
type LeafOptions struct {
	SerialNumber string // default PNOEE-40404040009
	GivenName    string // default OK
	Surname      string // default TEST
	NotBefore    time.Time
	NotAfter     time.Time
	NoAuthEKU    bool
	OldProfile   bool // digitalSignature+keyEncipherment+dataEncipherment+clientAuth
	NoPolicy     bool
	IsCA         bool
	KeyUsage     x509.KeyUsage // overrides when non-zero
	ECKey        bool
	RSABits      int  // default 2048
	SelfIssuedBy *PKI // issue from another PKI (untrusted chain)
}

// Leaf is a generated end-entity certificate and its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func sharedRSA() *rsa.PrivateKey {
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

// NewPKI generates a two-level ECDSA P-256 CA hierarchy.
func NewPKI(name string) *PKI {
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " TEST ROOT", Organization: []string{"eidbridge synthetic"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rd, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rd)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " TEST ISSUING CA", Organization: []string{"eidbridge synthetic"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, OCSPServer: []string{"http://127.0.0.1/ocsp"}}
	id, _ := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	inter, _ := x509.ParseCertificate(id)
	return &PKI{Root: root, Inter: inter, rootKey: rk, interKey: ik}
}

var serialCounter = big.NewInt(1000)
var serialMu sync.Mutex

// NewLeaf issues an authentication certificate.
func (p *PKI) NewLeaf(o LeafOptions) *Leaf {
	if o.SerialNumber == "" {
		o.SerialNumber = "PNOEE-40404040009"
	}
	if o.GivenName == "" {
		o.GivenName = "OK"
	}
	if o.Surname == "" {
		o.Surname = "TEST"
	}
	now := time.Now()
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = now.Add(365 * 24 * time.Hour)
	}
	var key crypto.Signer = sharedRSA()
	if o.RSABits != 0 && o.RSABits != 2048 {
		k, _ := rsa.GenerateKey(rand.Reader, o.RSABits)
		key = k
	}
	if o.ECKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key = k
	}
	serialMu.Lock()
	serialCounter.Add(serialCounter, big.NewInt(1))
	sn := new(big.Int).Set(serialCounter)
	serialMu.Unlock()
	t := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{Country: []string{o.SerialNumber[3:5]}, CommonName: o.Surname + "," + o.GivenName,
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidSN, Value: o.Surname}, {Type: oidGN, Value: o.GivenName}, {Type: oidSerial, Value: o.SerialNumber}}},
		NotBefore: o.NotBefore, NotAfter: o.NotAfter, BasicConstraintsValid: true, IsCA: o.IsCA,
		KeyUsage: x509.KeyUsageDigitalSignature, OCSPServer: []string{"http://127.0.0.1/ocsp"},
	}
	if !o.NoAuthEKU && !o.OldProfile {
		t.UnknownExtKeyUsage = []asn1.ObjectIdentifier{OIDAuthEKU}
	}
	if o.OldProfile {
		t.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.KeyUsage != 0 {
		t.KeyUsage = o.KeyUsage
	}
	if !o.NoPolicy {
		pol, _ := x509.OIDFromInts([]uint64{1, 3, 6, 1, 4, 1, 10015, 17, 2})
		t.Policies = []x509.OID{pol}
	}
	issuer, ikey := p.Inter, p.interKey
	if o.SelfIssuedBy != nil {
		issuer, ikey = o.SelfIssuedBy.Inter, o.SelfIssuedBy.interKey
	}
	der, err := x509.CreateCertificate(rand.Reader, t, issuer, key.Public(), ikey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &Leaf{Cert: c, Key: key}
}

// IssuerKey exposes the issuing CA key for OCSP responder tests.
func (p *PKI) IssuerKey() crypto.Signer { return p.interKey }

// PEM returns root and intermediate as PEM.
func (p *PKI) PEM() []byte {
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Root.Raw})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Inter.Raw})...)
}
