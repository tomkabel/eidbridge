package smartid

// Tests added for mutation survivors (gremlins, 2026-11-20).

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func pssSig(t *testing.T, leaf *smartidtest.Leaf, d []byte, trailer string) *Signature {
	t.Helper()
	v, err := rsa.SignPSS(rand.Reader, leaf.Key.(*rsa.PrivateKey), crypto.SHA256, d, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	s := &Signature{Value: base64.StdEncoding.EncodeToString(v), FlowType: FlowNotification, SignatureAlgorithm: "rsassa-pss"}
	salt := 32
	s.Params = &struct {
		HashAlgorithm    string `json:"hashAlgorithm"`
		MaskGenAlgorithm *struct {
			Algorithm  string `json:"algorithm"`
			Parameters *struct {
				HashAlgorithm string `json:"hashAlgorithm"`
			} `json:"parameters"`
		} `json:"maskGenAlgorithm"`
		SaltLength   *int   `json:"saltLength"`
		TrailerField string `json:"trailerField"`
	}{HashAlgorithm: "SHA-256", SaltLength: &salt, TrailerField: trailer}
	s.Params.MaskGenAlgorithm = &struct {
		Algorithm  string `json:"algorithm"`
		Parameters *struct {
			HashAlgorithm string `json:"hashAlgorithm"`
		} `json:"parameters"`
	}{Algorithm: "id-mgf1", Parameters: &struct {
		HashAlgorithm string `json:"hashAlgorithm"`
	}{HashAlgorithm: "SHA-256"}}
	return s
}

func TestRawSignatureKeySizeAndTrailer(t *testing.T) {
	pki := smartidtest.NewPKI("mut")
	d := digestOf("doc")
	req := SignRequest{Digest: d, HashAlgorithm: "SHA-256", SignatureAlgorithm: "rsassa-pss"}
	l2048 := pki.NewLeaf(smartidtest.LeafOptions{NoAuthEKU: true, KeyUsage: x509.KeyUsageContentCommitment, RSABits: 2048})
	for _, tr := range []string{"", "0xbc"} {
		if err := verifyRawSignature(req, pssSig(t, l2048, d, tr), l2048.Cert); err != nil {
			t.Fatalf("RSA-2048 with trailer %q rejected: %v", tr, err)
		}
	}
	if verifyRawSignature(req, pssSig(t, l2048, d, "0x01"), l2048.Cert) == nil {
		t.Fatal("unknown trailer accepted")
	}
	l1024 := pki.NewLeaf(smartidtest.LeafOptions{NoAuthEKU: true, KeyUsage: x509.KeyUsageContentCommitment, RSABits: 1024})
	if verifyRawSignature(req, pssSig(t, l1024, d, "0xbc"), l1024.Cert) == nil {
		t.Fatal("RSA-1024 accepted")
	}
}

func TestDisplayText200Boundary(t *testing.T) {
	_, c := fakeUpstream(t)
	sc := chooseCert(t, c)
	r := signReq("rsassa-pss")
	r.DisplayText200 = strings.Repeat("ä", 200)
	if _, err := c.StartSignature(context.Background(), sc, r); err != nil {
		t.Fatalf("200 characters rejected: %v", err)
	}
}

func TestTwoCertificateChainAccepted(t *testing.T) {
	srv, c := fakeUpstream(t)
	byRoot := srv.PKI.NewLeaf(smartidtest.LeafOptions{SerialNumber: signer, NoAuthEKU: true, KeyUsage: x509.KeyUsageContentCommitment, ByRoot: true})
	srv.SetMutate(func(st map[string]any) { setCert(st, byRoot.Cert.Raw) })
	id, _ := c.StartCertificateChoice(context.Background(), signer)
	if _, err := c.VerifyCertificateChoice(context.Background(), signer, complete(t, c, id)); err != nil {
		t.Fatalf("leaf issued by the root rejected: %v", err)
	}
	// The same holds for authentication (verify.go chain check).
	sy := newSynth(t, FlowQR, smartidtest.LeafOptions{})
	sy.leaf = testPKI.NewLeaf(smartidtest.LeafOptions{ByRoot: true})
	sy.sign()
	if _, err := sy.verify(); err != nil {
		t.Fatalf("authentication leaf issued by the root rejected: %v", err)
	}
	// A self-signed leaf alone (chain of one) is refused.
	self := smartidtest.NewPKI("self").Root
	srv.SetMutate(func(st map[string]any) { setCert(st, self.Raw) })
	c.cfg.Trust = NewTrustStore(srv.PKI.Root, srv.PKI.Inter, self)
	id, _ = c.StartCertificateChoice(context.Background(), signer)
	if _, err := c.VerifyCertificateChoice(context.Background(), signer, complete(t, c, id)); err == nil {
		t.Fatal("trust anchor accepted as end-entity certificate")
	}
}

func TestStatusBodyAtCap(t *testing.T) {
	b := []byte(`{"state":"RUNNING"}`)
	b = append(b, []byte(strings.Repeat(" ", MaxStatusBody-len(b)))...)
	if _, err := ParseStatus(b); err != nil {
		t.Fatalf("body of exactly MaxStatusBody rejected: %v", err)
	}
	if _, err := ParseStatus(append(b, ' ')); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestPersonalCodeFirstDigitBounds(t *testing.T) {
	for _, code := range []string{"60001019906", "10001010007"} {
		if !ValidPersonalCode("EE", fixChecksum(code)) {
			t.Errorf("%s rejected", code)
		}
	}
	for _, code := range []string{"00001010008", "70001010000"} {
		if ValidPersonalCode("EE", fixChecksum(code)) {
			t.Errorf("%s accepted", code)
		}
	}
}

func fixChecksum(code string) string { return code[:10] + string(rune('0'+eeChecksum(code))) }

func TestRetryAfterBounds(t *testing.T) {
	for _, v := range []string{"0", "600"} {
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", v)
			w.WriteHeader(429)
		}))
		c, _ := NewClient(Config{BaseURL: hs.URL, RPUUID: DemoRPUUID, RPName: DemoRPName, SchemeName: SchemeDemo,
			Trust: NewTrustStore(testPKI.Root), MinCertLevel: LevelQualified, Status: NoStatusCheck{}, HTTP: hs.Client()})
		_, err := c.Poll(context.Background(), "00000000-0000-4000-8000-000000000000", 0)
		he, ok := err.(*HTTPError)
		if !ok || !he.Retryable || (v == "600") != (he.RetryAfter.Seconds() == 600) || (v == "0" && he.RetryAfter != 0) {
			t.Errorf("Retry-After %s: %#v", v, err)
		}
		hs.Close()
	}
}

func TestLoadCADirIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README"), []byte("not a certificate"), 0o644)
	os.WriteFile(filepath.Join(dir, "root.pem"), testPKI.PEM(), 0o644)
	ts, err := LoadCADir(dir)
	if err != nil || ts.Empty() || len(ts.Certificates()) != 2 {
		t.Fatalf("LoadCADir: %v", err)
	}
	if NewTrustStore(testPKI.Inter).Empty() == false {
		t.Fatal("an intermediate alone counted as a root")
	}
}

func TestMethodRefusesFlowNotConfigured(t *testing.T) {
	_, c := fakeUpstream(t)
	m, err := NewMethod(MethodConfig{Client: c, Flows: []string{authn.FlowQR}, DisplayText: map[string]string{"en": "Log in"}, IsDemo: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{authn.FlowNotification, authn.FlowSameDevice} {
		if _, err := m.Start(context.Background(), authn.StartRequest{Flow: f, Lang: "en", CallbackURL: "https://bridge.example/cb?value=v",
			Input: map[string]string{"country": "EE", "personal_code": "40404040009"}}); err == nil {
			t.Errorf("flow %s started although not configured", f)
		}
	}
}

func TestFinishZeroesSessionSecrets(t *testing.T) {
	h := newHarness(t)
	p, _ := h.m.Start(context.Background(), authn.StartRequest{Flow: authn.FlowQR})
	pp := p.(*pending)
	secret, ch := pp.s.secret, pp.s.rpChallenge
	pp.finish(authn.Result{Err: &authn.Error{Reason: authn.ReasonVerificationFailed}})
	for _, b := range append(append([]byte{}, secret...), ch...) {
		if b != 0 {
			t.Fatal("finish left session secrets in memory")
		}
	}
}
