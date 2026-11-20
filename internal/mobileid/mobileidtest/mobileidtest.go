// Package mobileidtest is a synthetic MID REST API for offline tests and the
// bridge's mock mode: a generated SK-like PKI and an HTTP server that signs
// the relying party's hash like a Mobile-ID SIM. Identities are SK's
// published demo test numbers; nothing here is trusted outside tests and
// demo/mock mode.
package mobileidtest

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
	"strings"
	"sync"
	"time"
)

// PolicyOID is the Mobile-ID authentication certificate policy.
var PolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 18, 1}

var (
	oidSerial = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGN     = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSN     = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// PKI is a root and an issuing CA.
type PKI struct {
	Root, Inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

// NewPKI generates a two-level ECDSA P-256 hierarchy.
func NewPKI(name string) *PKI {
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " TEST MID ROOT"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rd, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rd)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name + " TEST MID ISSUING CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	id, _ := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	inter, _ := x509.ParseCertificate(id)
	return &PKI{Root: root, Inter: inter, rootKey: rk, interKey: ik}
}

// LeafOptions varies a generated certificate for negative tests.
type LeafOptions struct {
	SerialNumber   string // default PNOEE-51307149560
	RSA            bool   // RSA-2048 instead of EC P-256
	RSABits        int
	NoPolicy       bool
	Signing        bool // nonRepudiation key usage (a signing certificate)
	NoDigitalSig   bool
	IsCA           bool
	Expired        bool
	IssuedBy       *PKI // another (untrusted) PKI
	ByRoot         bool // issued directly by the root (two-certificate chain)
	NoIntermediate bool
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

// NewLeaf issues a Mobile-ID-like authentication certificate.
func (p *PKI) NewLeaf(o LeafOptions) *Leaf {
	if o.SerialNumber == "" {
		o.SerialNumber = "PNOEE-51307149560"
	}
	var key crypto.Signer
	if o.RSA {
		bits := o.RSABits
		if bits == 0 {
			bits = 2048
		}
		key, _ = rsa.GenerateKey(rand.Reader, bits)
	} else {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(365*24*time.Hour)
	if o.Expired {
		nb, na = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	serial.Lock()
	serial.n++
	sn := big.NewInt(1000 + serial.n)
	serial.Unlock()
	ku := x509.KeyUsageDigitalSignature
	if o.Signing {
		ku = x509.KeyUsageContentCommitment
	}
	if o.NoDigitalSig {
		ku = x509.KeyUsageKeyAgreement
	}
	t := &x509.Certificate{SerialNumber: sn,
		Subject: pkix.Name{Country: []string{o.SerialNumber[3:5]}, CommonName: "MARY ÄNN,O'CONNEŽ-ŠUSLIK TESTNUMBER",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidSN, Value: "O'CONNEŽ-ŠUSLIK TESTNUMBER"}, {Type: oidGN, Value: "MARY ÄNN"}, {Type: oidSerial, Value: o.SerialNumber}}},
		NotBefore: nb, NotAfter: na, BasicConstraintsValid: true, IsCA: o.IsCA, KeyUsage: ku}
	if !o.NoPolicy {
		t.Policies = []x509.OID{mustOID("1.3.6.1.4.1.10015.18.1")}
	}
	issuer, ikey := p.Inter, p.interKey
	if o.IssuedBy != nil {
		issuer, ikey = o.IssuedBy.Inter, o.IssuedBy.interKey
	}
	if o.ByRoot {
		issuer, ikey = p.Root, p.rootKey
	}
	d, err := x509.CreateCertificate(rand.Reader, t, issuer, key.Public(), ikey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(d)
	return &Leaf{Cert: c, Key: key}
}

func mustOID(s string) x509.OID {
	o, err := x509.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// Sign signs a SHA-256 hash the way the service reports it: EC as raw r||s,
// RSA as PKCS #1 v1.5.
func (l *Leaf) Sign(hash []byte) (value, algorithm string) {
	switch k := l.Key.(type) {
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, k, hash)
		b := make([]byte, 64)
		r.FillBytes(b[:32])
		s.FillBytes(b[32:])
		return base64.StdEncoding.EncodeToString(b), "SHA256WithECEncryption"
	case *rsa.PrivateKey:
		b, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hash)
		return base64.StdEncoding.EncodeToString(b), "SHA256WithRSAEncryption"
	}
	panic("key type")
}

// Scenario is what the fake service does for a phone number.
type Scenario struct {
	Result string // OK or a §3.3.8 result
	Leaf   *Leaf  // certificate that signs; nil for non-OK
	Polls  int    // RUNNING answers before COMPLETE
	// Mutate may change the status JSON before it is sent (negative tests).
	Mutate func(m map[string]any)
}

// Server is a fake MID REST API.
type Server struct {
	PKI *PKI
	mu  sync.Mutex
	sc  map[string]*Scenario // by phone
	ses map[string]*session
	// Starts counts authentication requests; LastStart is the last body.
	Starts    int
	LastStart map[string]string
}

type session struct {
	hash  []byte
	phone string
	polls int
}

// DefaultPhone and DefaultCode are SK's published demo number with an
// "OK" result on the EID-Q 2021E chain.
const (
	DefaultPhone = "+37269930366"
	DefaultCode  = "51307149560"
)

// NewServer returns a server with SK's demo test numbers mapped to results.
func NewServer(p *PKI) *Server {
	s := &Server{PKI: p, sc: map[string]*Scenario{}, ses: map[string]*session{}}
	s.Set(DefaultPhone, &Scenario{Result: "OK", Leaf: p.NewLeaf(LeafOptions{SerialNumber: "PNOEE-" + DefaultCode})})
	s.Set("+37060000666", &Scenario{Result: "OK", Leaf: p.NewLeaf(LeafOptions{SerialNumber: "PNOLT-50001018865"})})
	s.Set("+37201100266", &Scenario{Result: "USER_CANCELLED"})
	s.Set("+37200000266", &Scenario{Result: "NOT_MID_CLIENT"})
	s.Set("+37266000266", &Scenario{Result: "TIMEOUT"})
	s.Set("+37207110066", &Scenario{Result: "DELIVERY_ERROR"})
	return s
}

// Set installs a scenario for a phone number.
func (s *Server) Set(phone string, sc *Scenario) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sc[phone] = sc
}

// ServeHTTP implements POST /authentication and GET /authentication/session/{id}.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/authentication"):
		var req map[string]string
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
		if json.Unmarshal(b, &req) != nil || req["hashType"] != "SHA256" || req["relyingPartyUUID"] == "" {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad request"}`))
			return
		}
		h, err := base64.StdEncoding.DecodeString(req["hash"])
		if err != nil || len(h) != 32 {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"The length of the hash must match the type of hash"}`))
			return
		}
		id := newUUID()
		s.mu.Lock()
		s.Starts++
		s.LastStart = req
		s.ses[id] = &session{hash: h, phone: req["phoneNumber"]}
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"sessionID": id})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/authentication/session/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		s.mu.Lock()
		se := s.ses[id]
		var sc *Scenario
		if se != nil {
			sc = s.sc[se.phone]
			se.polls++
		}
		s.mu.Unlock()
		if se == nil {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"SessionID not found"}`))
			return
		}
		if sc == nil {
			sc = &Scenario{Result: "NOT_MID_CLIENT"}
		}
		if se.polls <= sc.Polls {
			json.NewEncoder(w).Encode(map[string]string{"state": "RUNNING"})
			return
		}
		m := map[string]any{"state": "COMPLETE", "result": sc.Result, "traceId": "0"}
		if sc.Result == "OK" && sc.Leaf != nil {
			v, alg := sc.Leaf.Sign(se.hash)
			m["signature"] = map[string]string{"value": v, "algorithm": alg}
			m["cert"] = base64.StdEncoding.EncodeToString(sc.Leaf.Cert.Raw)
		}
		if sc.Mutate != nil {
			sc.Mutate(m)
		}
		json.NewEncoder(w).Encode(m)
	default:
		w.WriteHeader(405)
	}
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexd[x>>4], hexd[x&15])
	}
	return string(out)
}
