package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pinOf(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(s[:])
}

func server(t *testing.T) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()
	hs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(hs.Close)
	pool := x509.NewCertPool()
	pool.AddCert(hs.Certificate())
	return hs, pool, pinOf(hs.Certificate())
}

const bogus = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func get(t *testing.T, c *http.Client, url string) error {
	t.Helper()
	resp, err := c.Get(url)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestMatchingPinSucceedsMismatchFails(t *testing.T) {
	hs, pool, pin := server(t)
	ps, _ := ParsePins(pin)
	if err := get(t, NewClient(Options{Pins: ps, Roots: pool}), hs.URL); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	ps, _ = ParsePins(bogus)
	err := get(t, NewClient(Options{Pins: ps, Roots: pool}), hs.URL)
	if err == nil {
		t.Fatal("mismatching pin accepted")
	}
	if !strings.Contains(err.Error(), "observed") || !strings.Contains(err.Error(), pin) {
		t.Fatalf("error must name observed pin: %v", err)
	}
}

func TestPinRotationEitherAccepted(t *testing.T) {
	hs, pool, pin := server(t)
	for _, v := range []string{pin + "," + bogus, bogus + "," + pin} {
		ps, err := ParsePins(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := get(t, NewClient(Options{Pins: ps, Roots: pool}), hs.URL); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
}

func TestDisabledPinsKeepCAAndHostnameValidation(t *testing.T) {
	hs, pool, _ := server(t)
	if err := get(t, NewClient(Options{Disabled: true, Roots: pool}), hs.URL); err != nil {
		t.Fatalf("disabled with trusted CA: %v", err)
	}
	if err := get(t, NewClient(Options{Disabled: true, Roots: x509.NewCertPool()}), hs.URL); err == nil {
		t.Fatal("disabled pins skipped CA validation")
	}
	// Hostname: the httptest cert is for 127.0.0.1/example.com, not "localhost.invalid".
	c := NewClient(Options{Disabled: true, Roots: pool})
	c.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong.invalid"
	if err := get(t, c, hs.URL); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
}

func TestLegacyTLSRefused(t *testing.T) {
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	hs.TLS = &tls.Config{MaxVersion: tls.VersionTLS11, MinVersion: tls.VersionTLS10}
	hs.StartTLS()
	defer hs.Close()
	pool := x509.NewCertPool()
	pool.AddCert(hs.Certificate())
	if err := get(t, NewClient(Options{Disabled: true, Roots: pool}), hs.URL); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	hs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		t.Error("redirect followed")
	}))
	defer hs.Close()
	pool := x509.NewCertPool()
	pool.AddCert(hs.Certificate())
	resp, err := NewClient(Options{Disabled: true, Roots: pool}).Get(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestTLSPinsInvalidValuesFail(t *testing.T) {
	for _, v := range []string{"", " ", "sha256/", "md5/AAAA", "sha256/notbase64!", "sha256/AAAA", "disabled,sha256/" + strings.Repeat("A", 43) + "="} {
		if _, err := Policy("demo", v, false); err == nil {
			t.Errorf("demo accepted %q", v)
		}
		if _, err := Policy("production", v, true); err == nil {
			t.Errorf("production accepted %q", v)
		}
	}
	p, err := Policy("demo", "disabled", false)
	if err != nil || !p.Disabled || p.Warning == "" {
		t.Fatalf("demo disabled: %+v %v", p, err)
	}
}

func TestPinDisableRequiresAcknowledgement(t *testing.T) {
	if _, err := Policy("production", "disabled", false); err == nil {
		t.Fatal("production pin disable without acknowledgement started")
	}
	p, err := Policy("production", "disabled", true)
	if err != nil || !p.Disabled || p.Warning == "" || p.Deviation == "" {
		t.Fatalf("acknowledged disable: %+v %v", p, err)
	}
	p, err = Policy("production", bogus, false)
	if err != nil || p.Disabled || len(p.Pins) != 1 || p.Deviation != "" {
		t.Fatalf("pinned: %+v %v", p, err)
	}
	if _, err := Policy("staging", bogus, false); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
