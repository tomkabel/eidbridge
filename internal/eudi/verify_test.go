package eudi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

const clientID = "x509_hash:test-verifier"

type venv struct {
	prov *walletsim.Provider
	v    *Verifier
}

func newVEnv(t *testing.T) *venv {
	t.Helper()
	p := walletsim.NewProvider("unit")
	hs := httptest.NewServer(p.StatusHandler())
	t.Cleanup(hs.Close)
	p.StatusURI = hs.URL + "/status/1"
	return &venv{prov: p, v: &Verifier{Trust: smartid.NewTrustStore(p.Root), VCTs: []string{"urn:eudi:pid:1"}, Now: time.Now,
		Status: &StatusChecker{AllowedHosts: map[string]bool{strings.TrimPrefix(hs.URL, "http://"): true}}}}
}

func (e *venv) verify(w *walletsim.Wallet, nonce string, o walletsim.PresentOptions) (*Presentation, error) {
	return e.v.Verify(context.Background(), w.Present(nonce, clientID, o), nonce, clientID)
}

func TestVerifyValidPresentation(t *testing.T) {
	e := newVEnv(t)
	w := e.prov.Issue(walletsim.IssueOptions{})
	p, err := e.verify(w, "nonce-1", walletsim.PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Claims["given_name"] != "MARI" || p.Claims["personal_administrative_number"] != "49005170005" || p.VCT != "urn:eudi:pid:1" {
		t.Fatalf("%+v", p)
	}
	if _, ok := p.Claims["cnf"]; ok {
		t.Fatal("cnf leaked into claims")
	}
	// Selective disclosure: undisclosed claims stay hidden.
	p, err = e.verify(w, "nonce-1", walletsim.PresentOptions{Disclose: []string{"given_name"}})
	if err != nil || p.Claims["family_name"] != nil || p.Claims["given_name"] != "MARI" {
		t.Fatalf("selective: %+v %v", p, err)
	}
}

// One negative per verification step (Story 6.1 / child 6.1-b).
func TestVerifyNegatives(t *testing.T) {
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other := walletsim.NewProvider("other")
	type tc struct {
		name   string
		issue  walletsim.IssueOptions
		pres   walletsim.PresentOptions
		raw    func(e *venv, w *walletsim.Wallet) string
		status func(e *venv, w *walletsim.Wallet)
		reason string
		detail string
	}
	cases := []tc{
		{name: "1 no key binding", pres: walletsim.PresentOptions{NoKB: true}, reason: authn.ReasonVerificationFailed, detail: "key-binding JWT missing"},
		{name: "1 not an SD-JWT", raw: func(*venv, *walletsim.Wallet) string { return "abc" }, reason: authn.ReasonVerificationFailed, detail: "not an SD-JWT"},
		{name: "1 oversized", raw: func(*venv, *walletsim.Wallet) string { return strings.Repeat("a", MaxPresentation+1) + "~x" }, reason: authn.ReasonVerificationFailed, detail: "too large"},
		{name: "2 issuer typ", issue: walletsim.IssueOptions{Typ: "JWT"}, reason: authn.ReasonVerificationFailed, detail: "typ"},
		{name: "2 untrusted issuer CA", issue: walletsim.IssueOptions{SignWith: other.SignerKey(), X5C: nil}, raw: func(e *venv, _ *walletsim.Wallet) string {
			w := other.Issue(walletsim.IssueOptions{})
			return w.Present("n", clientID, walletsim.PresentOptions{})
		}, reason: authn.ReasonVerificationFailed, detail: "chain"},
		{name: "2 signed by a key other than the x5c leaf", issue: walletsim.IssueOptions{SignWith: stranger}, reason: authn.ReasonVerificationFailed, detail: "does not verify"},
		{name: "2 tampered issuer payload", pres: walletsim.PresentOptions{TamperIssuer: true}, reason: authn.ReasonVerificationFailed, detail: "does not verify"},
		{name: "2 alg none", raw: func(e *venv, w *walletsim.Wallet) string {
			p := strings.Split(w.IssuerJWT, ".")
			return b64.EncodeToString([]byte(`{"alg":"none","typ":"dc+sd-jwt"}`)) + "." + p[1] + ".~" + "x"
		}, reason: authn.ReasonVerificationFailed, detail: "not allowed"},
		{name: "3 wrong vct", issue: walletsim.IssueOptions{VCT: "urn:other"}, reason: authn.ReasonVerificationFailed, detail: "type not accepted"},
		{name: "3 expired", issue: walletsim.IssueOptions{Expired: true}, reason: authn.ReasonVerificationFailed, detail: "expired"},
		{name: "3 no exp", issue: walletsim.IssueOptions{NoExp: true}, reason: authn.ReasonVerificationFailed, detail: "no exp"},
		{name: "3 _sd_alg not sha-256", issue: walletsim.IssueOptions{SDAlg: "sha-512"}, reason: authn.ReasonVerificationFailed, detail: "_sd_alg"},
		{name: "3 no holder key", issue: walletsim.IssueOptions{NoCnf: true}, reason: authn.ReasonVerificationFailed, detail: "cnf.jwk"},
		{name: "4 injected disclosure", pres: walletsim.PresentOptions{ExtraDisclose: "personal_administrative_number"}, reason: authn.ReasonVerificationFailed, detail: "not referenced"},
		{name: "4 duplicate disclosure", pres: walletsim.PresentOptions{DupDisclosure: true, Disclose: []string{"given_name"}}, reason: authn.ReasonVerificationFailed, detail: "repeated"},
		{name: "4 clear claim overwritten by a disclosure", issue: walletsim.IssueOptions{AlwaysVis: []string{"issuing_country"}, AlsoSD: true},
			reason: authn.ReasonVerificationFailed, detail: "already present"},
		{name: "5 KB signed by another key", pres: walletsim.PresentOptions{KBKey: stranger}, reason: authn.ReasonVerificationFailed, detail: "key-binding JWT"},
		{name: "5 KB typ", pres: walletsim.PresentOptions{KBTyp: "JWT"}, reason: authn.ReasonVerificationFailed, detail: "kb+jwt"},
		{name: "5 wrong nonce (replay)", pres: walletsim.PresentOptions{Nonce: "old-nonce"}, reason: authn.ReasonVerificationFailed, detail: "nonce"},
		{name: "5 wrong audience", pres: walletsim.PresentOptions{Aud: "x509_hash:other"}, reason: authn.ReasonVerificationFailed, detail: "aud"},
		{name: "5 KB too old", pres: walletsim.PresentOptions{IAT: time.Now().Add(-10 * time.Minute)}, reason: authn.ReasonVerificationFailed, detail: "iat"},
		{name: "5 KB in the future", pres: walletsim.PresentOptions{IAT: time.Now().Add(10 * time.Minute)}, reason: authn.ReasonVerificationFailed, detail: "iat"},
		{name: "5 sd_hash mismatch", pres: walletsim.PresentOptions{BadSDHash: true}, reason: authn.ReasonVerificationFailed, detail: "sd_hash"},
		{name: "5 KB reused with fewer disclosures", raw: func(e *venv, w *walletsim.Wallet) string {
			full := w.Present("n", clientID, walletsim.PresentOptions{})
			kb := full[strings.LastIndex(full, "~")+1:]
			return w.IssuerJWT + "~" + w.Disclosures["given_name"] + "~" + kb
		}, reason: authn.ReasonVerificationFailed, detail: "sd_hash"},
		{name: "6 revoked (status list)", status: func(e *venv, w *walletsim.Wallet) { e.prov.SetStatus(w.StatusIdx, 1) }, reason: authn.ReasonVerificationFailed, detail: "revoked"},
		{name: "6 suspended (status list)", status: func(e *venv, w *walletsim.Wallet) { e.prov.SetStatus(w.StatusIdx, 2) }, reason: authn.ReasonVerificationFailed, detail: "suspended"},
		{name: "6 status host not allowed", status: func(e *venv, w *walletsim.Wallet) { e.v.Status.AllowedHosts = map[string]bool{} }, reason: authn.ReasonStatusUnavailable, detail: "allow-listed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newVEnv(t)
			w := e.prov.Issue(c.issue)
			if c.status != nil {
				c.status(e, w)
			}
			nonce := "n"
			pres := w.Present(nonce, clientID, c.pres)
			if c.raw != nil {
				pres = c.raw(e, w)
			}
			p, err := e.v.Verify(context.Background(), pres, nonce, clientID)
			if err == nil || p != nil {
				t.Fatalf("accepted: %+v", p)
			}
			if authn.ReasonOf(err) != c.reason || !strings.Contains(err.Error(), c.detail) {
				t.Fatalf("got %v, want %s / %q", err, c.reason, c.detail)
			}
		})
	}
}

func TestStatusRequiredAndMissingChecker(t *testing.T) {
	e := newVEnv(t)
	e.prov.StatusURI = ""
	w := e.prov.Issue(walletsim.IssueOptions{})
	e.v.RequireStatus = true
	if _, err := e.verify(w, "n", walletsim.PresentOptions{}); err == nil || !strings.Contains(err.Error(), "no status reference") {
		t.Fatalf("%v", err)
	}
	e2 := newVEnv(t)
	e2.v.Status = nil
	if _, err := e2.verify(e2.prov.Issue(walletsim.IssueOptions{}), "n", walletsim.PresentOptions{}); authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
		t.Fatalf("%v", err)
	}
}

func FuzzVerifyPresentation(f *testing.F) {
	p := walletsim.NewProvider("fuzz")
	w := p.Issue(walletsim.IssueOptions{})
	f.Add(w.Present("n", clientID, walletsim.PresentOptions{}))
	f.Add("a~b~c")
	f.Add("~~~")
	v := &Verifier{Trust: smartid.NewTrustStore(p.Root), VCTs: []string{"urn:eudi:pid:1"}, Now: time.Now}
	f.Fuzz(func(t *testing.T, s string) {
		if pr, err := v.Verify(context.Background(), s, "n", clientID); err == nil {
			if pr.Claims == nil || pr.VCT == "" {
				t.Fatal("accepted without claims")
			}
		}
	})
}
