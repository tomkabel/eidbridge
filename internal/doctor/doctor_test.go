package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/tlspin"
)

// tlsServer serves HTTPS with a certificate valid for validFor; it records
// every request it receives.
func tlsServer(t *testing.T, validFor time.Duration) (*httptest.Server, *x509.Certificate, *[]string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(validFor), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	d, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(d)
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{d}, PrivateKey: k}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, c, &seen
}

func pool(c *x509.Certificate) *x509.CertPool { p := x509.NewCertPool(); p.AddCert(c); return p }

func TestUpstreamOKAndOnlyConfiguredEndpoint(t *testing.T) {
	srv, c, seen := tlsServer(t, 400*24*time.Hour)
	rs := Run(context.Background(), []Target{{Component: "smartid", Env: "demo", BaseURL: srv.URL + "/smart-id-rp", Pins: []tlspin.Pin{tlspin.PinOf(c)}, Roots: pool(c)}}, nil, time.Now())
	r := rs[0]
	if r.Status != "OK" || r.Pin != "ok" || r.TLSVersion == "" || r.Cipher == "" || r.ExpiresIn < 390 {
		t.Fatalf("%+v", r)
	}
	if len(*seen) != 1 || (*seen)[0] != "HEAD /smart-id-rp" {
		t.Fatalf("doctor made other requests: %v", *seen)
	}
}

func TestPinMismatchFails(t *testing.T) {
	srv, c, _ := tlsServer(t, 400*24*time.Hour)
	var other tlspin.Pin
	other[0] = 1
	r := Run(context.Background(), []Target{{Component: "smartid", BaseURL: srv.URL, Pins: []tlspin.Pin{other}, Roots: pool(c)}}, nil, time.Now())[0]
	if r.Status != "FAIL" || r.Pin != "mismatch" || Failed([]Result{r}) != true {
		t.Fatalf("%+v", r)
	}
}

func TestExpiringCertWarns(t *testing.T) {
	srv, c, _ := tlsServer(t, 10*24*time.Hour)
	r := Run(context.Background(), []Target{{Component: "mobileid", BaseURL: srv.URL, Pins: []tlspin.Pin{tlspin.PinOf(c)}, Roots: pool(c)}}, nil, time.Now())[0]
	if r.Status != "WARN" || !strings.Contains(r.Detail, "expires in") || Failed([]Result{r}) {
		t.Fatalf("%+v", r)
	}
}

func TestUnreachableAndUntrustedFail(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	r := Run(context.Background(), []Target{{Component: "smartid", BaseURL: "https://" + addr, PinsDisabled: true}}, nil, time.Now())[0]
	if r.Status != "FAIL" || !strings.Contains(r.Detail, "connection failed") {
		t.Fatalf("unreachable: %+v", r)
	}
	srv, _, _ := tlsServer(t, 400*24*time.Hour)
	r = Run(context.Background(), []Target{{Component: "smartid", BaseURL: srv.URL, PinsDisabled: true}}, nil, time.Now())[0]
	if r.Status != "FAIL" {
		t.Fatalf("untrusted server certificate: %+v", r)
	}
}

func TestPinsDisabledWarns(t *testing.T) {
	srv, c, _ := tlsServer(t, 400*24*time.Hour)
	r := Run(context.Background(), []Target{{Component: "smartid", BaseURL: srv.URL, PinsDisabled: true, Roots: pool(c)}}, nil, time.Now())[0]
	if r.Status != "WARN" || r.Pin != "disabled" {
		t.Fatalf("%+v", r)
	}
}

func TestTrustBundles(t *testing.T) {
	now := time.Now()
	mk := func(na time.Time) *x509.Certificate { return &x509.Certificate{NotAfter: na} }
	for want, b := range map[string]Bundle{
		"OK":   {Component: "smartid", Certs: []*x509.Certificate{mk(now.Add(400 * 24 * time.Hour)), mk(now.Add(900 * 24 * time.Hour))}},
		"WARN": {Component: "smartid", Certs: []*x509.Certificate{mk(now.Add(900 * 24 * time.Hour)), mk(now.Add(20 * 24 * time.Hour))}},
		"FAIL": {Component: "smartid", Certs: []*x509.Certificate{mk(now.Add(-time.Hour))}},
	} {
		if r := Run(context.Background(), nil, []Bundle{b}, now)[0]; r.Status != want {
			t.Errorf("%s: %+v", want, r)
		}
	}
	if r := Run(context.Background(), nil, []Bundle{{Component: "x"}}, now)[0]; r.Status != "FAIL" {
		t.Error("empty bundle")
	}
}

// The --json field names are part of the documented schema (docs/doctor.md).
func TestJSONFieldNames(t *testing.T) {
	b, _ := json.Marshal(Result{Component: "smartid", Kind: "upstream", Status: "OK"})
	for _, f := range []string{`"component"`, `"kind"`, `"status"`, `"cert_expires_in_days"`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("missing %s in %s", f, b)
		}
	}
}
