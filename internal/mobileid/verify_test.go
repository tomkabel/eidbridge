package mobileid

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/mobileid/mobileidtest"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

type env struct {
	pki *mobileidtest.PKI
	srv *mobileidtest.Server
	c   *Client
	st  *statusRec
}

type statusRec struct {
	err   error
	calls int
}

func (s *statusRec) Check(context.Context, *x509.Certificate, *x509.Certificate) error {
	s.calls++
	return s.err
}

func newEnv(t *testing.T) *env {
	t.Helper()
	p := mobileidtest.NewPKI("unit")
	s := mobileidtest.NewServer(p)
	hs := httptest.NewServer(s)
	t.Cleanup(hs.Close)
	rec := &statusRec{}
	c, err := NewClient(Config{BaseURL: hs.URL, RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO", HTTP: hs.Client(),
		Trust: smartid.NewTrustStore(p.Root, p.Inter), PolicyOIDs: []asn1.ObjectIdentifier{MIDPolicyOID}, Status: rec})
	if err != nil {
		t.Fatal(err)
	}
	return &env{pki: p, srv: s, c: c, st: rec}
}

// login starts a session for phone/code and returns the verified result.
func (e *env) login(t *testing.T, phone, code string) (*Identity, error) {
	t.Helper()
	s, err := e.c.Start(context.Background(), StartRequest{Phone: phone, Code: code, Lang3: "ENG"})
	if err != nil {
		return nil, err
	}
	st, err := e.c.Poll(context.Background(), s.ID, time.Second)
	if err != nil {
		return nil, err
	}
	return e.c.Verify(context.Background(), s, st)
}

func reason(err error) string { return authn.ReasonOf(err) }

func TestVerifyHappyPathEC(t *testing.T) {
	e := newEnv(t)
	id, err := e.login(t, mobileidtest.DefaultPhone, mobileidtest.DefaultCode)
	if err != nil {
		t.Fatal(err)
	}
	if id.Country != "EE" || id.Code != mobileidtest.DefaultCode || id.GivenName != "MARY ÄNN" || id.Surname != "O'CONNEŽ-ŠUSLIK TESTNUMBER" {
		t.Fatalf("%+v", id)
	}
	if e.st.calls != 1 {
		t.Fatal("status not checked")
	}
}

func TestVerifyHappyPathRSAAndLT(t *testing.T) {
	e := newEnv(t)
	e.srv.Set("+37060000666", &mobileidtest.Scenario{Result: "OK", Leaf: e.pki.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOLT-50001018865", RSA: true})})
	id, err := e.login(t, "+37060000666", "50001018865")
	if err != nil || id.Country != "LT" {
		t.Fatalf("%+v %v", id, err)
	}
}

// One negative test per verification step (§3.3.6 and the bridge's own).
func TestVerifyNegatives(t *testing.T) {
	other := mobileidtest.NewPKI("other")
	cases := []struct {
		name   string
		sc     func(e *env) *mobileidtest.Scenario
		reason string
		detail string
	}{
		{"1 result not OK", func(e *env) *mobileidtest.Scenario { return &mobileidtest.Scenario{Result: "USER_CANCELLED"} }, authn.ReasonRefused, ""},
		{"2 signature missing", mut(func(m map[string]any) { delete(m, "signature") }), authn.ReasonVerificationFailed, "missing signature"},
		{"2 cert missing", mut(func(m map[string]any) { delete(m, "cert") }), authn.ReasonVerificationFailed, "missing signature"},
		{"2 signature not base64", mut(func(m map[string]any) { m["signature"].(map[string]string)["value"] = "!!" }), authn.ReasonVerificationFailed, "not Base64"},
		{"2 cert not base64", mut(func(m map[string]any) { m["cert"] = "!!" }), authn.ReasonVerificationFailed, "not Base64"},
		{"2 cert garbage", mut(func(m map[string]any) { m["cert"] = base64.StdEncoding.EncodeToString([]byte("x")) }), authn.ReasonVerificationFailed, "does not parse"},
		{"3 hash type mismatch", mut(func(m map[string]any) { m["signature"].(map[string]string)["algorithm"] = "SHA512WithECEncryption" }), authn.ReasonVerificationFailed, "hash type"},
		{"3 key type mismatch", mut(func(m map[string]any) { m["signature"].(map[string]string)["algorithm"] = "SHA256WithRSAEncryption" }), authn.ReasonVerificationFailed, "non-RSA"},
		{"3 unknown algorithm", mut(func(m map[string]any) { m["signature"].(map[string]string)["algorithm"] = "SHA256WithDSAEncryption" }), authn.ReasonVerificationFailed, "unsupported"},
		{"3 short RSA key", leaf(mobileidtest.LeafOptions{RSA: true, RSABits: 1024}), authn.ReasonVerificationFailed, "short"},
		{"3 EC algorithm on RSA key", func(e *env) *mobileidtest.Scenario {
			sc := leaf(mobileidtest.LeafOptions{RSA: true})(e)
			sc.Mutate = func(m map[string]any) { m["signature"].(map[string]string)["algorithm"] = "SHA256WithECEncryption" }
			return sc
		}, authn.ReasonVerificationFailed, "non-EC"},
		{"4 untrusted chain", leaf(mobileidtest.LeafOptions{IssuedBy: other}), authn.ReasonVerificationFailed, "chain"},
		{"4 expired", leaf(mobileidtest.LeafOptions{Expired: true}), authn.ReasonVerificationFailed, "chain"},
		{"4 leaf is CA", leaf(mobileidtest.LeafOptions{IsCA: true}), authn.ReasonVerificationFailed, "is a CA"},
		{"5 policy missing", leaf(mobileidtest.LeafOptions{NoPolicy: true}), authn.ReasonVerificationFailed, "policy"},
		{"6 signing certificate", leaf(mobileidtest.LeafOptions{Signing: true}), authn.ReasonVerificationFailed, "not an authentication"},
		{"6 no digitalSignature", leaf(mobileidtest.LeafOptions{NoDigitalSig: true}), authn.ReasonVerificationFailed, "not an authentication"},
		{"7 not PNO", leaf(mobileidtest.LeafOptions{SerialNumber: "PASEE-51307149560"}), authn.ReasonVerificationFailed, "not PNO"},
		{"7 other person", leaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-60001017869"}), authn.ReasonIdentityMismatch, ""},
		{"7 same code, other country", leaf(mobileidtest.LeafOptions{SerialNumber: "PNOLT-51307149560"}), authn.ReasonIdentityMismatch, ""},
		{"8 tampered signature", mut(func(m map[string]any) {
			sig := m["signature"].(map[string]string)
			b, _ := base64.StdEncoding.DecodeString(sig["value"])
			b[10] ^= 1
			sig["value"] = base64.StdEncoding.EncodeToString(b)
		}), authn.ReasonVerificationFailed, "signature does not verify"},
		{"8 signature over another hash", func(e *env) *mobileidtest.Scenario {
			l := e.pki.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-51307149560"})
			other := sha256.Sum256([]byte("another hash"))
			v, alg := l.Sign(other[:])
			return &mobileidtest.Scenario{Result: "OK", Leaf: l, Mutate: func(m map[string]any) {
				m["signature"] = map[string]string{"value": v, "algorithm": alg}
			}}
		}, authn.ReasonVerificationFailed, "signature does not verify"},
		{"8 signature by another key", func(e *env) *mobileidtest.Scenario {
			l := e.pki.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-51307149560"})
			impostor := e.pki.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-51307149560"})
			return &mobileidtest.Scenario{Result: "OK", Leaf: impostor, Mutate: func(m map[string]any) {
				m["cert"] = base64.StdEncoding.EncodeToString(l.Cert.Raw)
			}}
		}, authn.ReasonVerificationFailed, "signature does not verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.Set(mobileidtest.DefaultPhone, tc.sc(e))
			id, err := e.login(t, mobileidtest.DefaultPhone, mobileidtest.DefaultCode)
			if err == nil || id != nil {
				t.Fatalf("accepted: %+v", id)
			}
			if reason(err) != tc.reason || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("got %v (reason %s), want %s / %q", err, reason(err), tc.reason, tc.detail)
			}
			if e.st.calls != 0 {
				t.Fatal("status checked before the other checks passed")
			}
		})
	}
}

// 9: status – revoked fails verification; unknown fails closed.
func TestVerifyStatus(t *testing.T) {
	e := newEnv(t)
	e.st.err = smartid.ErrRevoked
	if _, err := e.login(t, mobileidtest.DefaultPhone, mobileidtest.DefaultCode); reason(err) != authn.ReasonVerificationFailed || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %v", err)
	}
	e.st.err = errors.New("responder down")
	if _, err := e.login(t, mobileidtest.DefaultPhone, mobileidtest.DefaultCode); reason(err) != authn.ReasonStatusUnavailable {
		t.Fatalf("unknown: %v", err)
	}
}

func TestVerifyDestroyedSession(t *testing.T) {
	e := newEnv(t)
	s, _ := e.c.Start(context.Background(), StartRequest{Phone: mobileidtest.DefaultPhone, Code: mobileidtest.DefaultCode})
	st, _ := e.c.Poll(context.Background(), s.ID, time.Second)
	s.Destroy()
	if _, err := e.c.Verify(context.Background(), s, st); err == nil {
		t.Fatal("destroyed session verified")
	}
	if s.Code != "" || s.Phone != "" || s.Hash != nil {
		t.Fatal("Destroy left data")
	}
}

func mut(f func(map[string]any)) func(*env) *mobileidtest.Scenario {
	return func(e *env) *mobileidtest.Scenario {
		return &mobileidtest.Scenario{Result: "OK", Leaf: e.pki.NewLeaf(mobileidtest.LeafOptions{SerialNumber: "PNOEE-51307149560"}), Mutate: f}
	}
}

func leaf(o mobileidtest.LeafOptions) func(*env) *mobileidtest.Scenario {
	return func(e *env) *mobileidtest.Scenario {
		if o.SerialNumber == "" {
			o.SerialNumber = "PNOEE-51307149560"
		}
		return &mobileidtest.Scenario{Result: "OK", Leaf: e.pki.NewLeaf(o)}
	}
}
