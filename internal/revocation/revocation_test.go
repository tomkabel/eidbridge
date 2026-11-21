package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"golang.org/x/crypto/ocsp"
)

type responder struct {
	pki      *smartidtest.PKI
	status   int
	this     time.Time
	next     time.Time
	signer   *smartidtest.PKI // sign with another CA
	hits     atomic.Int64
	crl      []byte
	response []byte
	code     int
}

func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.hits.Add(1)
	if r.code != 0 && req.Method != http.MethodGet {
		w.WriteHeader(r.code)
		return
	}
	if req.Method == http.MethodGet {
		w.Write(r.crl)
		return
	}
	if r.response != nil {
		w.Write(r.response)
		return
	}
	signer := r.pki
	if r.signer != nil {
		signer = r.signer
	}
	tmpl := ocsp.Response{Status: r.status, SerialNumber: big.NewInt(0), ThisUpdate: r.this, NextUpdate: r.next, RevokedAt: r.this}
	var raw [512]byte
	n, _ := req.Body.Read(raw[:])
	parsed, err := ocsp.ParseRequest(raw[:n])
	if err == nil {
		tmpl.SerialNumber = parsed.SerialNumber
	}
	out, err := ocsp.CreateResponse(signer.Inter, signer.Inter, tmpl, signer.IssuerKey())
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Write(out)
}

func setup(t *testing.T, r *responder, ocspPath bool) (*Checker, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	hs := httptest.NewServer(r)
	t.Cleanup(hs.Close)
	u, _ := url.Parse(hs.URL)
	leaf := r.pki.NewLeaf(smartidtest.LeafOptions{}).Cert
	// Rewrite responder URLs to the test server.
	leaf.OCSPServer = []string{hs.URL + "/ocsp"}
	leaf.CRLDistributionPoints = []string{hs.URL + "/crl"}
	if !ocspPath {
		leaf.OCSPServer = nil
	}
	return &Checker{AllowedHosts: map[string]bool{u.Host: true}, CRLFallback: true}, leaf, r.pki.Inter
}

func TestOCSPGoodRevokedUnknown(t *testing.T) {
	p := smartidtest.NewPKI("ocsp")
	now := time.Now()
	for status, want := range map[int]error{ocsp.Good: nil, ocsp.Revoked: ErrRevoked} {
		r := &responder{pki: p, status: status, this: now.Add(-time.Minute), next: now.Add(time.Hour)}
		c, leaf, iss := setup(t, r, true)
		if err := c.Check(context.Background(), leaf, iss); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("status %d: %v", status, err)
		}
	}
	r := &responder{pki: p, status: ocsp.Unknown, this: now.Add(-time.Minute), next: now.Add(time.Hour)}
	c, leaf, iss := setup(t, r, true)
	c.CRLFallback = false
	if err := c.Check(context.Background(), leaf, iss); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestStaleWrongSignerAndHTTPFailuresFail(t *testing.T) {
	p, other := smartidtest.NewPKI("ocsp"), smartidtest.NewPKI("evil")
	now := time.Now()
	cases := map[string]*responder{
		"next update passed": {pki: p, status: ocsp.Good, this: now.Add(-2 * time.Hour), next: now.Add(-time.Hour)},
		"too old":            {pki: p, status: ocsp.Good, this: now.Add(-72 * time.Hour)},
		"future":             {pki: p, status: ocsp.Good, this: now.Add(time.Hour), next: now.Add(2 * time.Hour)},
		"wrong signer":       {pki: p, status: ocsp.Good, this: now, next: now.Add(time.Hour), signer: other},
		"http 500":           {pki: p, code: 500},
		"http 302":           {pki: p, code: 302},
	}
	for name, r := range cases {
		c, leaf, iss := setup(t, r, true)
		c.CRLFallback = false
		if err := c.Check(context.Background(), leaf, iss); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOnlyAllowListedHostsContacted(t *testing.T) {
	p := smartidtest.NewPKI("ocsp")
	r := &responder{pki: p, status: ocsp.Good, this: time.Now(), next: time.Now().Add(time.Hour)}
	c, leaf, iss := setup(t, r, true)
	c.AllowedHosts = map[string]bool{"aia.demo.sk.ee": true}
	if err := c.Check(context.Background(), leaf, iss); err == nil {
		t.Fatal("non-allow-listed responder accepted")
	}
	if r.hits.Load() != 0 {
		t.Fatalf("contacted non-allow-listed host %d times", r.hits.Load())
	}
}

func TestSizeCapAndTimeout(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, 1<<20)) }))
	defer big.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	p := smartidtest.NewPKI("ocsp")
	for _, hs := range []*httptest.Server{big, slow} {
		u, _ := url.Parse(hs.URL)
		leaf := p.NewLeaf(smartidtest.LeafOptions{}).Cert
		leaf.OCSPServer = []string{hs.URL}
		c := &Checker{AllowedHosts: map[string]bool{u.Host: true}, Timeout: 100 * time.Millisecond, MaxBytes: 64 << 10}
		if err := c.Check(context.Background(), leaf, p.Inter); err == nil {
			t.Errorf("%s accepted", hs.URL)
		}
	}
}

func crlFor(t *testing.T, p *smartidtest.PKI, revoked *big.Int, this, next time.Time) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next}
	if revoked != nil {
		tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: revoked, RevocationTime: this}}
	}
	inter := *p.Inter
	inter.KeyUsage |= x509.KeyUsageCRLSign
	b, err := x509.CreateRevocationList(rand.Reader, tmpl, &inter, p.IssuerKey())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCRLFallback(t *testing.T) {
	p := smartidtest.NewPKI("crl")
	now := time.Now()
	r := &responder{pki: p}
	c, leaf, iss := setup(t, r, false) // no OCSP URL → CRL
	r.crl = crlFor(t, p, nil, now.Add(-time.Minute), now.Add(time.Hour))
	if err := c.Check(context.Background(), leaf, iss); err != nil {
		t.Fatalf("crl good: %v", err)
	}
	c2, leaf2, _ := setup(t, r, false)
	r.crl = crlFor(t, p, leaf2.SerialNumber, now.Add(-time.Minute), now.Add(time.Hour))
	if err := c2.Check(context.Background(), leaf2, iss); !errors.Is(err, ErrRevoked) {
		t.Fatalf("crl revoked: %v", err)
	}
	c3, leaf3, _ := setup(t, r, false)
	r.crl = crlFor(t, p, nil, now.Add(-3*time.Hour), now.Add(-time.Hour))
	if err := c3.Check(context.Background(), leaf3, iss); err == nil {
		t.Fatal("stale crl accepted")
	}
	c4, leaf4, _ := setup(t, r, false)
	r.crl = crlFor(t, smartidtest.NewPKI("evil"), nil, now, now.Add(time.Hour))
	if err := c4.Check(context.Background(), leaf4, iss); err == nil {
		t.Fatal("crl from another CA accepted")
	}
	c5, leaf5, _ := setup(t, r, false)
	r.crl = []byte("garbage")
	if err := c5.Check(context.Background(), leaf5, iss); err == nil || !strings.Contains(err.Error(), "crl") {
		t.Fatalf("garbage crl: %v", err)
	}
}

func TestPR31FallbackOnlyWhenOCSPCannotProvideAResponse(t *testing.T) {
	p := smartidtest.NewPKI("pr31-fallback")
	now := time.Now()
	cases := []struct {
		name     string
		ocspPath bool
		setup    func(*responder)
	}{
		{name: "missing endpoint", ocspPath: false},
		{name: "transport response failure", ocspPath: true, setup: func(r *responder) { r.code = http.StatusServiceUnavailable }},
		{name: "malformed response", ocspPath: true, setup: func(r *responder) { r.response = []byte("malformed OCSP") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &responder{pki: p}
			if tc.setup != nil {
				tc.setup(r)
			}
			c, leaf, issuer := setup(t, r, tc.ocspPath)
			r.crl = crlFor(t, p, nil, now.Add(-time.Minute), now.Add(time.Hour))
			if err := c.Check(context.Background(), leaf, issuer); err != nil {
				t.Fatalf("valid CRL fallback: %v", err)
			}
			wantHits := int64(2)
			if !tc.ocspPath {
				wantHits = 1
			}
			if hits := r.hits.Load(); hits != wantHits {
				t.Fatalf("requests %d, want %d", hits, wantHits)
			}
		})
	}
}

func TestPR31DefinitiveAndValidationFailuresDoNotFallback(t *testing.T) {
	p := smartidtest.NewPKI("pr31-terminal")
	other := smartidtest.NewPKI("pr31-other")
	now := time.Now()
	cases := []struct {
		name   string
		status int
		signer *smartidtest.PKI
		this   time.Time
		next   time.Time
	}{
		{name: "unknown", status: ocsp.Unknown, this: now.Add(-time.Minute), next: now.Add(time.Hour)},
		{name: "revoked", status: ocsp.Revoked, this: now.Add(-time.Minute), next: now.Add(time.Hour)},
		{name: "wrong signer", status: ocsp.Good, signer: other, this: now.Add(-time.Minute), next: now.Add(time.Hour)},
		{name: "stale", status: ocsp.Good, this: now.Add(-72 * time.Hour), next: now.Add(time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &responder{pki: p, status: tc.status, signer: tc.signer, this: tc.this, next: tc.next}
			c, leaf, issuer := setup(t, r, true)
			r.crl = crlFor(t, p, nil, now.Add(-time.Minute), now.Add(time.Hour))
			if err := c.Check(context.Background(), leaf, issuer); err == nil {
				t.Fatal("accepted OCSP failure with a good CRL available")
			}
			if hits := r.hits.Load(); hits != 1 {
				t.Fatalf("terminal OCSP result made %d requests, want one", hits)
			}
		})
	}
}

func TestOCSPParseErrorFallbackClassification(t *testing.T) {
	for _, message := range []string{
		"trailing data in OCSP response",
		"bad OCSP response type",
		"OCSP response contains bad number of responses",
	} {
		if isOCSPValidationError(ocsp.ParseError(message)) {
			t.Errorf("structural parse error classified as validation failure: %s", message)
		}
	}
	for _, message := range []string{
		"no response matching the supplied certificate",
		"invalid responder name",
		"invalid responder key hash",
		"invalid responder id tag",
		"bad signature on embedded certificate: x509: ECDSA verification failure",
		"bad OCSP signature: x509: ECDSA verification failure",
		"unsupported critical extension",
		"unsupported issuer hash algorithm",
		"unexpected future OCSP parse failure",
	} {
		if !isOCSPValidationError(ocsp.ParseError(message)) {
			t.Errorf("validation parse error allowed to fall back: %s", message)
		}
	}
}

func TestCacheAvoidsRefetchAndCustomSentinel(t *testing.T) {
	p := smartidtest.NewPKI("ocsp")
	r := &responder{pki: p, status: ocsp.Revoked, this: time.Now().Add(-time.Minute), next: time.Now().Add(time.Hour)}
	c, leaf, iss := setup(t, r, true)
	mine := errors.New("mine")
	c.Revoked = mine
	for i := 0; i < 3; i++ {
		if err := c.Check(context.Background(), leaf, iss); err != mine {
			t.Fatalf("got %v", err)
		}
	}
	if r.hits.Load() != 1 {
		t.Fatalf("hits %d, want 1", r.hits.Load())
	}
	if err := c.Check(context.Background(), nil, iss); err == nil {
		t.Fatal("nil leaf accepted")
	}
}
