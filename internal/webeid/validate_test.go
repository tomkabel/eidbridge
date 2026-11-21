package webeid

import (
	"context"
	"encoding/asn1"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
)

const origin = "https://login.example.com"

type venv struct {
	pki *webeidtest.PKI
	v   *Validator
}

// newVEnv wires a validator to a synthetic PKI whose certificates point at a
// real OCSP responder served from this test (status: mock OCSP).
func newVEnv(t *testing.T) *venv {
	t.Helper()
	p := webeidtest.NewPKI("unit")
	ocspSrv := httptest.NewServer(p.OCSPHandler())
	t.Cleanup(ocspSrv.Close)
	p.OCSPURL = ocspSrv.URL
	host := strings.TrimPrefix(ocspSrv.URL, "http://")
	st := &revocation.Checker{AllowedHosts: map[string]bool{host: true}, Revoked: smartid.ErrRevoked}
	return &venv{pki: p, v: &Validator{Trust: smartid.NewTrustStore(p.Root, p.Inter), Status: st, Now: time.Now,
		DisallowedPolicies: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 10015, 18, 1}}}}
}

func (e *venv) check(t *testing.T, tok []byte, org, nonce string) (*Identity, error) {
	t.Helper()
	pt, err := ParseToken(tok)
	if err != nil {
		return nil, err
	}
	return e.v.Validate(context.Background(), pt, org, nonce)
}

// Story 5.1 test vector: valid token, every algorithm family.
func TestValidTokens(t *testing.T) {
	e := newVEnv(t)
	for alg, key := range map[string]string{"ES384": "p384", "ES256": "p256", "RS256": "rsa2048", "PS256": "rsa2048", "RS512": "rsa2048", "PS384": "rsa2048"} {
		n := webeidtest.Nonce()
		id, err := e.check(t, e.pki.NewLeaf(webeidtest.LeafOptions{Key: key}).Token(alg, origin, n), origin, n)
		if err != nil || id.Code != "38001085718" || id.Country != "EE" || id.GivenName != "JAAK-KRISTJAN" || id.Surname != "JÕEORG" {
			t.Errorf("%s: %+v %v", alg, id, err)
		}
	}
}

// Story 5.1 test vectors (wrong origin, expired, revoked via mock OCSP,
// untrusted CA) and one negative per validation step.
func TestValidationNegatives(t *testing.T) {
	type tc struct {
		name   string
		tok    func(e *venv, n string) []byte
		org    string
		reason string
		detail string
	}
	other := webeidtest.NewPKI("other")
	ok := func(e *venv) *webeidtest.Leaf { return e.pki.NewLeaf(webeidtest.LeafOptions{}) }
	cases := []tc{
		{"wrong origin", func(e *venv, n string) []byte { return ok(e).Token("ES384", "https://evil.example.com", n) }, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"origin with port", func(e *venv, n string) []byte { return ok(e).Token("ES384", origin+":8443", n) }, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"other nonce", func(e *venv, n string) []byte { return ok(e).Token("ES384", origin, webeidtest.Nonce()) }, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"expired certificate", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{Expired: true}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "not valid at this time"},
		{"not yet valid", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{NotYetValid: true}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "not valid at this time"},
		{"revoked (mock OCSP)", func(e *venv, n string) []byte {
			l := ok(e)
			e.pki.Revoke(l.Cert)
			return l.Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "revoked"},
		{"untrusted CA", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{IssuedBy: other}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "chain"},
		{"untrusted CA with its intermediate in the token", func(e *venv, n string) []byte {
			l := e.pki.NewLeaf(webeidtest.LeafOptions{IssuedBy: other})
			return l.TokenWith("ES384", origin, n, func(m map[string]any) {
				m["format"] = "web-eid:1.1"
				m["unverifiedIntermediateCertificates"] = []string{base64.StdEncoding.EncodeToString(other.Inter.Raw), base64.StdEncoding.EncodeToString(other.Root.Raw)}
			})
		}, "", authn.ReasonVerificationFailed, "chain"},
		{"no client-auth EKU", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{NoClientAuth: true}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "client-authentication"},
		{"signing certificate", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{Signing: true}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "client-authentication"},
		{"disallowed policy", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{Policies: []string{"1.3.6.1.4.1.10015.18.1"}}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "disallowed policy"},
		{"ES on RSA key", func(e *venv, n string) []byte {
			l := e.pki.NewLeaf(webeidtest.LeafOptions{Key: "rsa2048"})
			return l.TokenWith("RS256", origin, n, func(m map[string]any) { m["algorithm"] = "ES256" })
		}, "", authn.ReasonVerificationFailed, "non-EC"},
		{"RS on EC key", func(e *venv, n string) []byte {
			return ok(e).TokenWith("ES384", origin, n, func(m map[string]any) { m["algorithm"] = "RS384" })
		}, "", authn.ReasonVerificationFailed, "non-RSA"},
		{"curve mismatch", func(e *venv, n string) []byte {
			return ok(e).TokenWith("ES384", origin, n, func(m map[string]any) { m["algorithm"] = "ES256" })
		}, "", authn.ReasonVerificationFailed, "curve"},
		{"PS signature labelled RS", func(e *venv, n string) []byte {
			l := e.pki.NewLeaf(webeidtest.LeafOptions{Key: "rsa2048"})
			return l.TokenWith("PS256", origin, n, func(m map[string]any) { m["algorithm"] = "RS256" })
		}, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"short RSA key", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{Key: "rsa1024"}).Token("RS256", origin, n)
		}, "", authn.ReasonVerificationFailed, "short"},
		{"tampered signature", func(e *venv, n string) []byte {
			return ok(e).TokenWith("ES384", origin, n, func(m map[string]any) {
				b, _ := base64.StdEncoding.DecodeString(m["signature"].(string))
				b[3] ^= 1
				m["signature"] = base64.StdEncoding.EncodeToString(b)
			})
		}, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"truncated ECDSA signature", func(e *venv, n string) []byte {
			return ok(e).TokenWith("ES384", origin, n, func(m map[string]any) {
				b, _ := base64.StdEncoding.DecodeString(m["signature"].(string))
				m["signature"] = base64.StdEncoding.EncodeToString(b[1:])
			})
		}, "", authn.ReasonVerificationFailed, "wrong length"},
		{"certificate swapped", func(e *venv, n string) []byte {
			other := ok(e)
			return ok(e).TokenWith("ES384", origin, n, func(m map[string]any) { m["unverifiedCertificate"] = base64.StdEncoding.EncodeToString(other.Cert.Raw) })
		}, "", authn.ReasonVerificationFailed, "origin and nonce"},
		{"subject not PNO/PAS/IDC", func(e *venv, n string) []byte {
			return e.pki.NewLeaf(webeidtest.LeafOptions{SerialNumber: "XYZEE-38001085718"}).Token("ES384", origin, n)
		}, "", authn.ReasonVerificationFailed, "serialNumber"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newVEnv(t)
			n := webeidtest.Nonce()
			id, err := e.check(t, c.tok(e, n), origin, n)
			if err == nil || id != nil {
				t.Fatalf("accepted: %+v", id)
			}
			if authn.ReasonOf(err) != c.reason || !strings.Contains(err.Error(), c.detail) {
				t.Fatalf("got %v, want %s / %q", err, c.reason, c.detail)
			}
		})
	}
}

func TestStatusUnknownFailsClosed(t *testing.T) {
	e := newVEnv(t)
	e.pki.OCSPURL = "http://127.0.0.1:1/ocsp" // not allow-listed, unreachable
	n := webeidtest.Nonce()
	if _, err := e.check(t, e.pki.NewLeaf(webeidtest.LeafOptions{}).Token("ES384", origin, n), origin, n); authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
		t.Fatalf("%v", err)
	}
}

func TestNonceLengthBounds(t *testing.T) {
	e := newVEnv(t)
	for _, n := range []string{strings.Repeat("a", 43), strings.Repeat("a", 129)} {
		if _, err := e.check(t, e.pki.NewLeaf(webeidtest.LeafOptions{}).Token("ES384", origin, n), origin, n); err == nil {
			t.Errorf("nonce length %d accepted", len(n))
		}
	}
	for _, n := range []string{strings.Repeat("a", 44), strings.Repeat("a", 128)} {
		if _, err := e.check(t, e.pki.NewLeaf(webeidtest.LeafOptions{}).Token("ES384", origin, n), origin, n); err != nil {
			t.Errorf("nonce length %d refused: %v", len(n), err)
		}
	}
}

func TestParseTokenRejects(t *testing.T) {
	l := webeidtest.NewPKI("p").NewLeaf(webeidtest.LeafOptions{})
	n := webeidtest.Nonce()
	for name, mut := range map[string]func(map[string]any){
		"format v2":            func(m map[string]any) { m["format"] = "web-eid:2.0" },
		"format other":         func(m map[string]any) { m["format"] = "jwt" },
		"format 1.x":           func(m map[string]any) { m["format"] = "web-eid:1.x" },
		"format 1.":            func(m map[string]any) { m["format"] = "web-eid:1." },
		"format suffix":        func(m map[string]any) { m["format"] = "web-eid:10" },
		"format no minor":      func(m map[string]any) { m["format"] = "web-eid:1" },
		"alg none":             func(m map[string]any) { m["algorithm"] = "none" },
		"alg HS256":            func(m map[string]any) { m["algorithm"] = "HS256" },
		"signature not b64":    func(m map[string]any) { m["signature"] = "%%%" },
		"empty signature":      func(m map[string]any) { m["signature"] = "" },
		"cert not b64":         func(m map[string]any) { m["unverifiedCertificate"] = "%%%" },
		"cert garbage":         func(m map[string]any) { m["unverifiedCertificate"] = base64.StdEncoding.EncodeToString([]byte("x")) },
		"empty intermediates":  func(m map[string]any) { m["unverifiedIntermediateCertificates"] = []string{} },
		"bad intermediate":     func(m map[string]any) { m["unverifiedIntermediateCertificates"] = []string{"%%"} },
		"garbage intermediate": func(m map[string]any) { m["unverifiedIntermediateCertificates"] = []string{"AAAA"} },
		"too many intermediates": func(m map[string]any) {
			m["unverifiedIntermediateCertificates"] = []string{"AAAA", "AAAA", "AAAA", "AAAA", "AAAA"}
		},
	} {
		if _, err := ParseToken(l.TokenWith("ES384", origin, n, mut)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, f := range []string{"web-eid:1.0", "web-eid:1.1", "web-eid:1.12"} {
		if _, err := ParseToken(l.TokenWith("ES384", origin, n, func(m map[string]any) { m["format"] = f })); err != nil {
			t.Errorf("format %s refused: %v", f, err)
		}
	}
	if _, err := ParseToken([]byte(strings.Repeat(" ", MaxTokenBytes+1))); err == nil {
		t.Error("oversized token accepted")
	}
	if _, err := ParseToken(nil); err == nil {
		t.Error("empty token accepted")
	}
}

func TestASCIIOrigin(t *testing.T) {
	for in, want := range map[string]string{"https://Login.Example.com": "https://login.example.com", "https://a.example:443/": "https://a.example",
		"https://a.example:8443": "https://a.example:8443", "https://xn--pike-loa.ee": "https://xn--pike-loa.ee"} {
		if got, err := ASCIIOrigin(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"http://a.example", "https://päike.ee", "https://a.example/path", "https://u@a.example", "https://a.example?x", "a.example"} {
		if _, err := ASCIIOrigin(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

func FuzzParseToken(f *testing.F) {
	l := webeidtest.NewPKI("f").NewLeaf(webeidtest.LeafOptions{})
	f.Add(l.Token("ES384", origin, webeidtest.Nonce()))
	f.Add([]byte(`{"format":"web-eid:1.1","algorithm":"RS256","signature":"AA==","unverifiedCertificate":"AA==","unverifiedIntermediateCertificates":["AA=="]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tok, err := ParseToken(b)
		if err != nil {
			return
		}
		if tok.cert == nil || !algorithms[tok.Algorithm] || len(tok.sig) == 0 {
			t.Fatal("accepted token without certificate, algorithm or signature")
		}
	})
}
