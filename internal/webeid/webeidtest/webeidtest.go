// Package webeidtest builds synthetic ID-card certificates, Web eID tokens
// and an OCSP responder for offline tests and the bridge's mock mode. The
// identity is SK's published test person; nothing here is trusted outside
// tests and demo/mock mode.
package webeidtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	oidSerial = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGN     = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSN     = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// PKI is a root and an issuing CA (EC P-384, like ESTEID2018).
type PKI struct {
	Root, Inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	// OCSPURL is placed in issued certificates (set before issuing).
	OCSPURL string

	mu      sync.Mutex
	revoked map[string]bool
}

// NewPKI generates the hierarchy.
func NewPKI(name string) *PKI {
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now()
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " TEST CARD ROOT"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rd, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rd)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " TEST ESTEID"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	id, _ := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	inter, _ := x509.ParseCertificate(id)
	return &PKI{Root: root, Inter: inter, rootKey: rk, interKey: ik, revoked: map[string]bool{}}
}

// LeafOptions varies a generated card certificate.
type LeafOptions struct {
	SerialNumber string // default PNOEE-38001085718
	Key          string // "p384" (default), "p256", "rsa2048", "rsa1024"
	NoClientAuth bool
	Signing      bool // nonRepudiation instead of digitalSignature
	Policies     []string
	Expired      bool
	NotYetValid  bool
	IssuedBy     *PKI
	ByRoot       bool // issued directly by the root (two-certificate chain)
}

// Leaf is a certificate and its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var serial struct {
	sync.Mutex
	n int64
}

// NewLeaf issues an ID-card-like authentication certificate.
func (p *PKI) NewLeaf(o LeafOptions) *Leaf {
	if o.SerialNumber == "" {
		o.SerialNumber = "PNOEE-38001085718"
	}
	var key crypto.Signer
	switch o.Key {
	case "p256":
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa2048":
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa1024":
		key, _ = rsa.GenerateKey(rand.Reader, 1024)
	default:
		key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(5*365*24*time.Hour)
	if o.Expired {
		nb, na = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	if o.NotYetValid {
		nb, na = now.Add(24*time.Hour), now.Add(48*time.Hour)
	}
	serial.Lock()
	serial.n++
	sn := big.NewInt(5000 + serial.n)
	serial.Unlock()
	t := &x509.Certificate{SerialNumber: sn,
		Subject: pkix.Name{Country: []string{o.SerialNumber[3:5]}, CommonName: "JÕEORG,JAAK-KRISTJAN,38001085718",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidSN, Value: "JÕEORG"}, {Type: oidGN, Value: "JAAK-KRISTJAN"}, {Type: oidSerial, Value: o.SerialNumber}}},
		NotBefore: nb, NotAfter: na, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if !o.NoClientAuth {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.Signing {
		t.KeyUsage = x509.KeyUsageContentCommitment
	}
	for _, s := range o.Policies {
		oid, _ := x509.ParseOID(s)
		t.Policies = append(t.Policies, oid)
	}
	issuer, ikey := p.Inter, p.interKey
	if o.IssuedBy != nil {
		issuer, ikey = o.IssuedBy.Inter, o.IssuedBy.interKey
	}
	if o.ByRoot {
		issuer, ikey = p.Root, p.rootKey
	}
	if p.OCSPURL != "" {
		t.OCSPServer = []string{p.OCSPURL}
	}
	d, err := x509.CreateCertificate(rand.Reader, t, issuer, key.Public(), ikey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(d)
	return &Leaf{Cert: c, Key: key}
}

// Token returns a web-eid:1.0 token signing hash(origin)+hash(nonce) with
// alg (ES256/384/512, RS256/384/512, PS256/384/512).
func (l *Leaf) Token(alg, origin, nonce string) []byte {
	return l.TokenWith(alg, origin, nonce, nil)
}

// TokenWith lets a test change the token map before encoding.
func (l *Leaf) TokenWith(alg, origin, nonce string, mut func(map[string]any)) []byte {
	h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
	ho, hn := h.New(), h.New()
	ho.Write([]byte(origin))
	hn.Write([]byte(nonce))
	d := h.New()
	d.Write(append(ho.Sum(nil), hn.Sum(nil)...))
	digest := d.Sum(nil)
	var sig []byte
	switch k := l.Key.(type) {
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, k, digest)
		n := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*n)
		r.FillBytes(sig[:n])
		s.FillBytes(sig[n:])
	case *rsa.PrivateKey:
		if alg[0] == 'P' {
			sig, _ = rsa.SignPSS(rand.Reader, k, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, _ = rsa.SignPKCS1v15(rand.Reader, k, h, digest)
		}
	}
	m := map[string]any{"unverifiedCertificate": base64.StdEncoding.EncodeToString(l.Cert.Raw), "algorithm": alg,
		"signature": base64.StdEncoding.EncodeToString(sig), "format": "web-eid:1.0", "appVersion": "https://web-eid.eu/web-eid-app/releases/v2.5.0"}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

// Revoke marks a certificate revoked at the OCSP responder.
func (p *PKI) Revoke(c *x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked[c.SerialNumber.String()] = true
}

// OCSPHandler answers OCSP requests for certificates of this PKI, signed by
// the issuing CA.
func (p *PKI) OCSPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
		req, err := ocsp.ParseRequest(b)
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		p.mu.Lock()
		rev := p.revoked[req.SerialNumber.String()]
		p.mu.Unlock()
		tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute),
			NextUpdate: time.Now().Add(time.Hour)}
		if rev {
			tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, time.Now().Add(-time.Hour), ocsp.KeyCompromise
		}
		resp, err := ocsp.CreateResponse(p.Inter, p.Inter, tmpl, p.interKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp)
	})
}

// Nonce returns a fresh Base64 nonce of 32 random bytes (44 characters).
func Nonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
