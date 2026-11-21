package eudi

// Tests added for gremlins survivors (2026-11-21).

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
	"github.com/tomkabel/eidbridge/internal/smartid"
)

func statusRef(uri string, idx int) any {
	return map[string]any{"status_list": map[string]any{"idx": idx, "uri": uri}}
}

func TestStatusListWidths(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		e := newVEnv(t)
		e.prov.StatusBits = bits
		for i := 0; i < 20; i++ {
			e.prov.Issue(walletsim.IssueOptions{})
		}
		e.prov.SetStatus(3, 1)
		if bits > 1 {
			e.prov.SetStatus(7, 2)
			e.prov.SetStatus(9, 3)
		}
		trust := smartid.NewTrustStore(e.prov.Root)
		want := map[int]string{0: "", 2: "", 3: "revoked", 4: ""}
		if bits > 1 {
			want[7], want[9], want[8] = "suspended", "not valid", ""
		}
		for idx, w := range want {
			err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, idx), trust, time.Now())
			if (w == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), w)) {
				t.Errorf("bits %d idx %d: want %q got %v", bits, idx, w, err)
			}
		}
		// The last index inside the list is valid; the first outside is not.
		n := (20 + 8) * bits
		last := (n+7)/8*8/bits - 1
		if err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, last), trust, time.Now()); err != nil {
			t.Errorf("bits %d last index %d: %v", bits, last, err)
		}
		if err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, last+1), trust, time.Now()); authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
			t.Errorf("bits %d index %d outside: %v", bits, last+1, err)
		}
	}
	e := newVEnv(t)
	e.prov.StatusBits = 3
	e.prov.Issue(walletsim.IssueOptions{})
	if err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, 0), smartid.NewTrustStore(e.prov.Root), time.Now()); authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
		t.Fatalf("bits 3 accepted: %v", err)
	}
}

func TestStatusSchemeAndSizeCap(t *testing.T) {
	e := newVEnv(t)
	e.prov.Issue(walletsim.IssueOptions{})
	trust := smartid.NewTrustStore(e.prov.Root)
	host := strings.TrimPrefix(e.prov.StatusURI, "http://")
	err := e.v.Status.Check(context.Background(), statusRef("ftp://"+host, 0), trust, time.Now())
	if err == nil || !strings.Contains(err.Error(), "allow-listed") {
		t.Fatalf("ftp status URI: %v", err)
	}
	resp, _ := http.Get(e.prov.StatusURI)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	e.v.Status.MaxBytes = int64(len(body))
	if err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, 0), trust, time.Now()); err != nil {
		t.Fatalf("token exactly at the cap: %v", err)
	}
	e.v.Status.MaxBytes = int64(len(body)) - 1
	if err := e.v.Status.Check(context.Background(), statusRef(e.prov.StatusURI, 0), trust, time.Now()); authn.ReasonOf(err) != authn.ReasonStatusUnavailable {
		t.Fatalf("token over the cap: %v", err)
	}
	_ = httptest.NewRecorder
}

func TestIssuerKeyUsage(t *testing.T) {
	e := newVEnv(t)
	bad := e.prov.SignerCertWithKeyUsage(x509.KeyUsageCertSign)
	w := e.prov.Issue(walletsim.IssueOptions{X5C: []*x509.Certificate{bad, e.prov.Inter}})
	if _, err := e.verify(w, "n", walletsim.PresentOptions{}); err == nil || !strings.Contains(err.Error(), "not for signatures") {
		t.Fatalf("issuer cert without digitalSignature: %v", err)
	}
	none := e.prov.SignerCertWithKeyUsage(0)
	w = e.prov.Issue(walletsim.IssueOptions{X5C: []*x509.Certificate{none, e.prov.Inter}})
	if _, err := e.verify(w, "n", walletsim.PresentOptions{}); err != nil {
		t.Fatalf("issuer cert without key usage extension: %v", err)
	}
}

func TestX5CLengthCap(t *testing.T) {
	e := newVEnv(t)
	i := e.prov.Inter
	w := e.prov.Issue(walletsim.IssueOptions{X5C: []*x509.Certificate{e.prov.Signer, i, i, i, i}})
	if _, err := e.verify(w, "n", walletsim.PresentOptions{}); err != nil {
		t.Fatalf("x5c of 5: %v", err)
	}
	w = e.prov.Issue(walletsim.IssueOptions{X5C: []*x509.Certificate{e.prov.Signer, i, i, i, i, i}})
	if _, err := e.verify(w, "n", walletsim.PresentOptions{}); err == nil {
		t.Fatal("x5c of 6 accepted")
	}
}

func TestDefaultSkew(t *testing.T) {
	e := newVEnv(t)
	e.v.Skew = 0 // default 60 s
	w := e.prov.Issue(walletsim.IssueOptions{})
	if _, err := e.verify(w, "n", walletsim.PresentOptions{IAT: time.Now().Add(45 * time.Second)}); err != nil {
		t.Fatalf("KB-JWT 45 s ahead with the default skew: %v", err)
	}
	c := map[string]any{"exp": jsonNum(time.Now().Add(-30 * time.Second).Unix())}
	if err := timeClaims(c, time.Now(), time.Minute, true); err != nil {
		t.Fatalf("expired 30 s ago within skew: %v", err)
	}
	c["exp"] = jsonNum(time.Now().Add(-90 * time.Second).Unix())
	if timeClaims(c, time.Now(), time.Minute, true) == nil {
		t.Fatal("expired 90 s ago accepted")
	}
}

func nest(n int, leaf any) any {
	for i := 0; i < n; i++ {
		leaf = map[string]any{"x": leaf}
	}
	return leaf
}

func nestArr(n int, leaf any) any {
	for i := 0; i < n; i++ {
		leaf = []any{leaf}
	}
	return leaf
}

func pidWith(extra map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range walletsim.PID {
		c[k] = v
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestNestingDepth(t *testing.T) {
	e := newVEnv(t)
	cases := []struct {
		name   string
		claims map[string]any
		vis    []string
		ok     bool
	}{
		{"clear object depth 8", pidWith(map[string]any{"deep": nest(8, 1)}), []string{"deep"}, true},
		{"clear object depth 9", pidWith(map[string]any{"deep": nest(9, 1)}), []string{"deep"}, false},
		{"disclosed object depth 7", pidWith(map[string]any{"deep": nest(7, 1)}), nil, true},
		{"disclosed object depth 8", pidWith(map[string]any{"deep": nest(8, 1)}), nil, false},
		{"arrays then object", pidWith(map[string]any{"deep": nestArr(9, map[string]any{"a": 1})}), []string{"deep"}, false},
	}
	for _, c := range cases {
		w := e.prov.Issue(walletsim.IssueOptions{Claims: c.claims, AlwaysVis: c.vis})
		_, err := e.verify(w, "n", walletsim.PresentOptions{})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestUndisclosedArrayElementDropped(t *testing.T) {
	e := newVEnv(t)
	w := e.prov.Issue(walletsim.IssueOptions{AlwaysVis: []string{"nationalities"},
		Claims: pidWith(map[string]any{"nationalities": []any{map[string]any{"...": "bm90LWRpc2Nsb3NlZC1kaWdlc3QtdmFsdWUtMDAwMDA"}, "EE"}})})
	p, err := e.verify(w, "n", walletsim.PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Claims["nationalities"].([]any); len(got) != 1 || got[0] != "EE" {
		t.Fatalf("nationalities %#v", p.Claims["nationalities"])
	}
}

func jsonNum(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func TestMethodDefaultsAndTTLBoundary(t *testing.T) {
	h := newHarness(t)
	id, _ := NewSelfSignedIdentity("bridge.example")
	m, err := NewMethod(MethodConfig{Identity: id, Verifier: h.e.v, Flows: []string{authn.FlowQR}, IsDemo: true})
	if err != nil || m.cfg.TTL != 5*time.Minute || m.cfg.LongPoll != 10*time.Second {
		t.Fatalf("defaults %+v %v", m.cfg, err)
	}
	w := h.e.prov.Issue(walletsim.IssueOptions{})
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	r := wallet(t, p)
	h.clk.add(h.m.cfg.TTL) // exactly TTL: still valid
	if res := p.Callback(context.Background(), post(r, walletsim.VPToken(w.Present(r.Nonce, r.ClientID, walletsim.PresentOptions{IAT: h.clk.now()})), nil), nil); !res.Done || res.Identity == nil {
		t.Fatalf("response exactly at TTL: %+v", res)
	}
	if again := p.Poll(context.Background()); again.Identity != nil || again.Err == nil {
		t.Fatalf("identity delivered twice: %+v", again)
	}
	p2, _ := h.m.Start(context.Background(), h.Requests()[0])
	h.clk.add(h.m.cfg.TTL)
	if res := p2.Poll(context.Background()); res.Done && res.Err != nil {
		t.Fatalf("poll exactly at TTL expired the flow: %+v", res)
	}
	h.clk.add(time.Nanosecond)
	if res := p2.Poll(context.Background()); !res.Done || authn.ReasonOf(res.Err) != authn.ReasonExpired {
		t.Fatalf("poll after TTL: %+v", res)
	}
}

func TestIdentifierLength(t *testing.T) {
	for n, ok := range map[int]bool{64: true, 65: false} {
		p := &Presentation{Claims: map[string]any{"personal_administrative_number": strings.Repeat("1", n), "issuing_country": "ee"}}
		if _, err := identityFrom(p); (err == nil) != ok {
			t.Errorf("code length %d: %v", n, err)
		}
	}
	if _, err := identityFrom(&Presentation{Claims: map[string]any{"personal_administrative_number": "1", "issuing_country": "EST"}}); err == nil {
		t.Error("three-letter country accepted")
	}
}
