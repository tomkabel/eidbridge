package smartid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

const signer = "PNOEE-40404040009"

func chooseCert(t *testing.T, c *Client) *SigningCert {
	t.Helper()
	id, err := c.StartCertificateChoice(context.Background(), signer)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := c.VerifyCertificateChoice(context.Background(), signer, complete(t, c, id))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func digestOf(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

func signReq(alg string) SignRequest {
	return SignRequest{Digest: digestOf("contract"), HashAlgorithm: "SHA-256", SignatureAlgorithm: alg, DisplayText200: "Sign the synthetic contract"}
}

func runSign(t *testing.T, srv *smartidtest.Server, c *Client, req SignRequest, mutate func(map[string]any)) (*SignResult, error) {
	t.Helper()
	sc := chooseCert(t, c)
	srv.SetMutate(mutate)
	defer srv.SetMutate(nil)
	ss, err := c.StartSignature(context.Background(), sc, req)
	if err != nil {
		t.Fatal(err)
	}
	if !vcRe.MatchString(ss.VC) {
		t.Fatalf("verification code %q", ss.VC)
	}
	return c.VerifyRawDigest(context.Background(), ss, complete(t, c, ss.ID))
}

func TestSignPositive(t *testing.T) {
	for _, alg := range []string{"rsassa-pss", "sha256WithRSAEncryption"} {
		srv, c := fakeUpstream(t)
		res, err := runSign(t, srv, c, signReq(alg), nil)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if res.DocumentNumber != signer+"-MOCK-Q" || res.SignatureAlgorithm != alg || len(res.Value) != 384 || res.Certificate == nil {
			t.Fatalf("%s: unexpected result %+v", alg, res)
		}
	}
}

func TestCertificateChoiceNegative(t *testing.T) {
	cases := map[string]func(srv *smartidtest.Server) func(map[string]any){
		"authentication certificate": func(srv *smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { setCert(st, srv.Leaf(signer).Cert.Raw) }
		},
		"untrusted chain": func(*smartidtest.Server) func(map[string]any) {
			other := smartidtest.NewPKI("other").NewLeaf(smartidtest.LeafOptions{SerialNumber: signer, NoAuthEKU: true, KeyUsage: 1 << 1})
			return func(st map[string]any) { setCert(st, other.Cert.Raw) }
		},
		"other person": func(srv *smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { setCert(st, srv.SignLeaf("PNOEE-40504040001").Cert.Raw) }
		},
		"document of other person": func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["result"].(map[string]any)["documentNumber"] = "PNOEE-40504040001-MOCK-Q" }
		},
		"advanced level": func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["cert"].(map[string]any)["certificateLevel"] = "ADVANCED" }
		},
		"flow type": func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["signature"] = map[string]any{"flowType": "QR"} }
		},
		"refused": func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				st["result"] = map[string]any{"endResult": "USER_REFUSED"}
				delete(st, "cert")
			}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			srv, c := fakeUpstream(t)
			srv.SetMutate(mk(srv))
			id, err := c.StartCertificateChoice(context.Background(), signer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.VerifyCertificateChoice(context.Background(), signer, complete(t, c, id))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

func TestCertificateChoiceRevoked(t *testing.T) {
	srv, c := fakeUpstream(t)
	_ = srv
	c.cfg.Status = statusFn(func(context.Context, *x509.Certificate, *x509.Certificate) error { return ErrRevoked })
	id, _ := c.StartCertificateChoice(context.Background(), signer)
	if _, err := c.VerifyCertificateChoice(context.Background(), signer, complete(t, c, id)); err == nil {
		t.Fatal("revoked signing certificate accepted")
	}
}

func setCert(st map[string]any, der []byte) {
	st["cert"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString(der)
}

func sigMap(st map[string]any) map[string]any { return st["signature"].(map[string]any) }

func TestSignNegativePerStep(t *testing.T) {
	cases := map[string]struct {
		alg    string
		mutate func(srv *smartidtest.Server) func(map[string]any)
	}{
		"tampered signature": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				v, _ := base64.StdEncoding.DecodeString(sigMap(st)["value"].(string))
				v[10] ^= 1
				sigMap(st)["value"] = base64.StdEncoding.EncodeToString(v)
			}
		}},
		"wrong digest": {"rsassa-pss", func(srv *smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				k := srv.SignLeaf(signer).Key.(*rsa.PrivateKey)
				v, _ := rsa.SignPSS(rand.Reader, k, crypto.SHA256, digestOf("other"), &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
				sigMap(st)["value"] = base64.StdEncoding.EncodeToString(v)
			}
		}},
		"authentication certificate": {"rsassa-pss", func(srv *smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { setCert(st, srv.Leaf(signer).Cert.Raw) }
		}},
		"certificate differs from chosen": {"rsassa-pss", func(srv *smartidtest.Server) func(map[string]any) {
			other := srv.PKI.NewLeaf(smartidtest.LeafOptions{SerialNumber: signer, NoAuthEKU: true, KeyUsage: 1 << 1})
			return func(st map[string]any) { setCert(st, other.Cert.Raw) }
		}},
		"protocol": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["signatureProtocol"] = "ACSP_V2" }
		}},
		"document number": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["result"].(map[string]any)["documentNumber"] = "PNOEE-40504040001-MOCK-Q" }
		}},
		"flow type": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { sigMap(st)["flowType"] = "QR" }
		}},
		"algorithm downgrade": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { sigMap(st)["signatureAlgorithm"] = "sha256WithRSAEncryption" }
		}},
		"pkcs1 hash": {"sha256WithRSAEncryption", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { sigMap(st)["signatureAlgorithm"] = "sha512WithRSAEncryption" }
		}},
		"hash parameter": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				sigMap(st)["signatureAlgorithmParameters"].(map[string]any)["hashAlgorithm"] = "SHA-512"
			}
		}},
		"mgf1 hash": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				p := sigMap(st)["signatureAlgorithmParameters"].(map[string]any)
				p["maskGenAlgorithm"] = map[string]any{"algorithm": "id-mgf1", "parameters": map[string]any{"hashAlgorithm": "SHA-512"}}
			}
		}},
		"salt length": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) {
				sigMap(st)["signatureAlgorithmParameters"].(map[string]any)["saltLength"] = 20
			}
		}},
		"missing parameters": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { delete(sigMap(st), "signatureAlgorithmParameters") }
		}},
		"interaction not offered": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["interactionTypeUsed"] = "displayTextAndPIN" }
		}},
		"advanced level": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["cert"].(map[string]any)["certificateLevel"] = "ADVANCED" }
		}},
		"refused": {"rsassa-pss", func(*smartidtest.Server) func(map[string]any) {
			return func(st map[string]any) { st["result"] = map[string]any{"endResult": "USER_REFUSED"} }
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, c := fakeUpstream(t)
			_, err := runSign(t, srv, c, signReq(tc.alg), tc.mutate(srv))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

func TestSignRevokedAtSigning(t *testing.T) {
	srv, c := fakeUpstream(t)
	sc := chooseCert(t, c)
	c.cfg.Status = statusFn(func(context.Context, *x509.Certificate, *x509.Certificate) error { return errors.New("ocsp down") })
	ss, err := c.StartSignature(context.Background(), sc, signReq("rsassa-pss"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.VerifyRawDigest(context.Background(), ss, complete(t, c, ss.ID))
	var e *Error
	if !errors.As(err, &e) || e.Reason != ReasonStatusUnavailable {
		t.Fatalf("want status unavailable, got %v", err)
	}
	_ = srv
}

func TestStartSignatureRejectsBadInput(t *testing.T) {
	_, c := fakeUpstream(t)
	sc := chooseCert(t, c)
	bad := map[string]SignRequest{
		"short digest":  {Digest: digestOf("x")[:20], HashAlgorithm: "SHA-256", SignatureAlgorithm: "rsassa-pss", DisplayText200: "x"},
		"hash mismatch": {Digest: digestOf("x"), HashAlgorithm: "SHA-512", SignatureAlgorithm: "rsassa-pss", DisplayText200: "x"},
		"pkcs1 hash":    {Digest: digestOf("x"), HashAlgorithm: "SHA-256", SignatureAlgorithm: "sha512WithRSAEncryption", DisplayText200: "x"},
		"algorithm":     {Digest: digestOf("x"), HashAlgorithm: "SHA-256", SignatureAlgorithm: "ecdsa", DisplayText200: "x"},
		"no text":       {Digest: digestOf("x"), HashAlgorithm: "SHA-256", SignatureAlgorithm: "rsassa-pss"},
		"long text":     {Digest: digestOf("x"), HashAlgorithm: "SHA-256", SignatureAlgorithm: "rsassa-pss", DisplayText200: strings.Repeat("a", 201)},
	}
	for name, r := range bad {
		if _, err := c.StartSignature(context.Background(), sc, r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := c.StartSignature(context.Background(), &SigningCert{}, signReq("rsassa-pss")); err == nil {
		t.Error("unverified certificate accepted")
	}
}
