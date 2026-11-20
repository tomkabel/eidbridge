package v2

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/authn/authntest"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"github.com/tomkabel/eidbridge/internal/smartid/v2/v2test"
)

type env struct {
	srv *v2test.Server
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
	s := v2test.NewServer()
	hs := httptest.NewServer(s)
	t.Cleanup(hs.Close)
	rec := &statusRec{}
	c, err := NewClient(Config{BaseURL: hs.URL + "/smart-id-rp/v2", RPUUID: "00000000-0000-0000-0000-000000000000", RPName: "DEMO",
		HTTP: hs.Client(), Trust: smartid.NewTrustStore(s.PKI.Root, s.PKI.Inter), MinCertLevel: "QUALIFIED",
		PolicyOIDs: smartid.DemoPolicyOIDs, Status: rec})
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv: s, c: c, st: rec}
}

func (e *env) login(t *testing.T, id string) (*Identity, error) {
	t.Helper()
	s, err := e.c.Start(context.Background(), id, "Log in")
	if err != nil {
		return nil, err
	}
	st, err := e.c.Poll(context.Background(), s.ID, time.Second)
	if err != nil {
		return nil, err
	}
	return e.c.Verify(context.Background(), s, st)
}

// §2.3.12.2: SHA256(hash), two rightmost bytes big-endian, mod 10000.
func TestVerificationCode(t *testing.T) {
	h := []byte("any hash value")
	s := sha256.Sum256(h)
	want := (int(s[30])*256 + int(s[31])) % 10000
	if got := VerificationCode(h); len(got) != 4 || got != fmtInt(want) {
		t.Fatalf("got %s want %04d", got, want)
	}
}

func fmtInt(n int) string {
	return string([]byte{byte('0' + n/1000), byte('0' + n/100%10), byte('0' + n/10%10), byte('0' + n%10)})
}

func TestVerifyOK(t *testing.T) {
	e := newEnv(t)
	id, err := e.login(t, "PNOEE-40404040009")
	if err != nil || id.Code != "40404040009" || id.Country != "EE" || e.st.calls != 1 {
		t.Fatalf("%+v %v", id, err)
	}
}

// One negative per §2.3.12.3 step and per bridge check.
func TestVerifyNegatives(t *testing.T) {
	other := smartidtest.NewPKI("other")
	for _, tc := range []struct {
		name, id, reason, detail string
		mut                      func(e *env) func(map[string]any)
	}{
		{"endResult refused", "PNOEE-30403039917", authn.ReasonRefused, "", nil},
		{"endResult timeout", "PNOEE-30403039983", authn.ReasonExpired, "", nil},
		{"endResult wrong VC", "PNOEE-30403039972", authn.ReasonWrongCode, "", nil},
		{"unknown endResult", "PNOEE-40404040009", authn.ReasonUnknownEndResult, "", func(*env) func(map[string]any) {
			return func(m map[string]any) { m["result"].(map[string]any)["endResult"] = "MAYBE" }
		}},
		{"missing cert", "PNOEE-40404040009", authn.ReasonVerificationFailed, "missing", func(*env) func(map[string]any) {
			return func(m map[string]any) { delete(m, "cert") }
		}},
		{"missing document number", "PNOEE-40404040009", authn.ReasonVerificationFailed, "missing", func(*env) func(map[string]any) {
			return func(m map[string]any) { delete(m["result"].(map[string]any), "documentNumber") }
		}},
		{"untrusted chain", "PNOEE-40404040009", authn.ReasonVerificationFailed, "chain", func(*env) func(map[string]any) {
			l := other.NewLeaf(smartidtest.LeafOptions{SerialNumber: "PNOEE-40404040009"})
			return func(m map[string]any) {
				m["cert"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString(l.Cert.Raw)
			}
		}},
		{"level below minimum", "PNOEE-40404040009", authn.ReasonVerificationFailed, "level", func(*env) func(map[string]any) {
			return func(m map[string]any) { m["cert"].(map[string]any)["certificateLevel"] = "ADVANCED" }
		}},
		{"other person's certificate", "PNOEE-40404040009", authn.ReasonIdentityMismatch, "", func(e *env) func(map[string]any) {
			l := e.srv.Leaf("PNOEE-40504040001")
			return func(m map[string]any) {
				m["cert"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString(l.Cert.Raw)
			}
		}},
		{"document number of someone else", "PNOEE-40404040009", authn.ReasonIdentityMismatch, "documentNumber", func(*env) func(map[string]any) {
			return func(m map[string]any) { m["result"].(map[string]any)["documentNumber"] = "PNOEE-40504040001-MOCK-Q" }
		}},
		{"weaker hash algorithm", "PNOEE-40404040009", authn.ReasonVerificationFailed, "SHA-512", func(*env) func(map[string]any) {
			return func(m map[string]any) { m["signature"].(map[string]any)["algorithm"] = "sha256WithRSAEncryption" }
		}},
		{"tampered signature", "PNOEE-40404040009", authn.ReasonVerificationFailed, "does not verify", func(*env) func(map[string]any) {
			return func(m map[string]any) {
				s := m["signature"].(map[string]any)
				b, _ := base64.StdEncoding.DecodeString(s["value"].(string))
				b[5] ^= 1
				s["value"] = base64.StdEncoding.EncodeToString(b)
			}
		}},
		{"signature not base64", "PNOEE-40404040009", authn.ReasonVerificationFailed, "Base64", func(*env) func(map[string]any) {
			return func(m map[string]any) { m["signature"].(map[string]any)["value"] = "%%" }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.mut != nil {
				e.srv.Mutate = tc.mut(e)
			}
			id, err := e.login(t, tc.id)
			if err == nil || id != nil {
				t.Fatalf("accepted %+v", id)
			}
			if authn.ReasonOf(err) != tc.reason || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("got %v want %s / %q", err, tc.reason, tc.detail)
			}
			if e.st.calls != 0 {
				t.Fatal("status checked before other checks passed")
			}
		})
	}
}

func TestVerifyStatusAndInput(t *testing.T) {
	e := newEnv(t)
	e.st.err = smartid.ErrRevoked
	if _, err := e.login(t, "PNOEE-40404040009"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %v", err)
	}
	for _, id := range []string{"PNOEE-40404040008", "40404040009", "PNOXX-1", ""} {
		if _, err := e.c.Start(context.Background(), id, "Log in"); authn.ReasonOf(err) != authn.ReasonInvalidInput {
			t.Errorf("%q: %v", id, err)
		}
	}
}

type harness struct{ e *env }

func (h *harness) Method() authn.Method {
	m, _ := NewMethod(MethodConfig{Client: h.e.c, DisplayText: "Log in", IsDemo: true, LongPoll: time.Second})
	return m
}
func (h *harness) Requests() []authn.StartRequest {
	return []authn.StartRequest{{Flow: authn.FlowNotification, Input: map[string]string{"country": "EE", "personal_code": "40404040009"}}}
}
func (h *harness) Drive(t *testing.T, p authn.Pending, _ authn.StartRequest, o authntest.Outcome) authn.Result {
	switch o {
	case authntest.Refuse:
		h.e.srv.Mutate = func(m map[string]any) {
			m["result"] = map[string]any{"endResult": "USER_REFUSED"}
			delete(m, "cert")
			delete(m, "signature")
		}
	case authntest.Timeout:
		h.e.srv.Mutate = func(m map[string]any) {
			m["result"] = map[string]any{"endResult": "TIMEOUT"}
			delete(m, "cert")
			delete(m, "signature")
		}
	case authntest.VerifyFail:
		h.e.srv.Mutate = func(m map[string]any) {
			m["signature"].(map[string]any)["value"] = base64.StdEncoding.EncodeToString(make([]byte, 256))
		}
	default:
		h.e.srv.Mutate = nil
	}
	defer func() { h.e.srv.Mutate = nil }()
	for range 5 {
		if r := p.Poll(context.Background()); r.Done {
			return r
		}
	}
	t.Fatal("no result")
	return authn.Result{}
}

// Story 7.5 AC: authntest.Run passes for v2.
func TestMethodContract(t *testing.T) { authntest.Run(t, &harness{e: newEnv(t)}) }
