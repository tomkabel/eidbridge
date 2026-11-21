package webeid

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
)

// Tests added to kill surviving mutants (gremlins, 2026-11-20).

func TestMethodDefaults(t *testing.T) {
	v := &Validator{Trust: smartid.NewTrustStore(webeidtest.NewPKI("d").Root), Status: smartid.NoStatusCheck{}, Now: time.Now}
	m, _ := NewMethod(MethodConfig{Validator: v})
	m2, _ := NewMethod(MethodConfig{Validator: v, NonceTTL: time.Minute, LongPoll: time.Second})
	if m.cfg.NonceTTL != 5*time.Minute || m.cfg.LongPoll != 10*time.Second || m2.cfg.NonceTTL != time.Minute || m2.cfg.LongPoll != time.Second {
		t.Fatal("defaults")
	}
	if _, err := NewMethod(MethodConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

// The nonce is valid for exactly NonceTTL.
func TestNonceTTLBoundary(t *testing.T) {
	h := newHarness(t)
	leaf := h.e.pki.NewLeaf(webeidtest.LeafOptions{})
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	ui, _ := p.UI(time.Now())
	h.clk.add(5 * time.Minute)
	if r := p.Poll(context.Background()); r.Done {
		t.Fatalf("expired at exactly the TTL: %+v", r)
	}
	if r := p.Callback(context.Background(), nil, leaf.Token("ES384", origin, ui.Challenge)); r.Identity == nil {
		t.Fatalf("token at exactly the TTL refused: %+v", r)
	}
	if r := p.Poll(context.Background()); r.Identity != nil || authn.ReasonOf(r.Err) != authn.ReasonUpstreamError {
		t.Fatalf("identity delivered twice: %+v", r)
	}
	p2, _ := h.m.Start(context.Background(), h.Requests()[0])
	ui2, _ := p2.UI(time.Now())
	h.clk.add(5*time.Minute + time.Nanosecond)
	if r := p2.Callback(context.Background(), nil, leaf.Token("ES384", origin, ui2.Challenge)); authn.ReasonOf(r.Err) != authn.ReasonExpired {
		t.Fatalf("token after the TTL: %+v", r)
	}
}

func TestBrowserErrorSizeBoundary(t *testing.T) {
	h := newHarness(t)
	body := `{"code":"ERR_WEBEID_USER_CANCELLED"}`
	body += strings.Repeat(" ", 256-len(body))
	p, _ := h.m.Start(context.Background(), h.Requests()[0])
	if r := p.Callback(context.Background(), nil, []byte(body)); authn.ReasonOf(r.Err) != authn.ReasonRefused {
		t.Fatalf("256-byte error body: %+v", r)
	}
}

func TestParserBoundaries(t *testing.T) {
	pki := webeidtest.NewPKI("b")
	l := pki.NewLeaf(webeidtest.LeafOptions{})
	n := webeidtest.Nonce()
	tok := l.Token("ES384", origin, n)
	padded := append(append([]byte{}, tok...), []byte(strings.Repeat(" ", MaxTokenBytes-len(tok)))...)
	if _, err := ParseToken(padded); err != nil {
		t.Fatalf("token of exactly MaxTokenBytes refused: %v", err)
	}
	for f, ok := range map[string]bool{"web-eid:1.123": true, "web-eid:1.1234": false} {
		if _, err := ParseToken(l.TokenWith("ES384", origin, n, func(m map[string]any) { m["format"] = f })); (err == nil) != ok {
			t.Errorf("format %s: %v", f, err)
		}
	}
	for size, ok := range map[int]bool{1024: true, 1025: false} {
		sig := base64.StdEncoding.EncodeToString(make([]byte, size))
		if _, err := ParseToken(l.TokenWith("ES384", origin, n, func(m map[string]any) { m["signature"] = sig })); (err == nil) != ok {
			t.Errorf("signature %d bytes: %v", size, err)
		}
	}
	c := base64.StdEncoding.EncodeToString(pki.Inter.Raw)
	if _, err := ParseToken(l.TokenWith("ES384", origin, n, func(m map[string]any) {
		m["format"] = "web-eid:1.1"
		m["unverifiedIntermediateCertificates"] = []string{c, c, c, c}
	})); err != nil {
		t.Fatalf("four intermediates refused: %v", err)
	}
}

// A card certificate issued directly by a trusted root is a valid
// two-certificate chain.
func TestTwoCertificateChain(t *testing.T) {
	e := newVEnv(t)
	n := webeidtest.Nonce()
	l := e.pki.NewLeaf(webeidtest.LeafOptions{ByRoot: true})
	pt, _ := ParseToken(l.Token("ES384", origin, n))
	e.v.Status = smartid.NoStatusCheck{} // the root does not answer OCSP
	if _, err := e.v.Validate(context.Background(), pt, origin, n); err != nil {
		t.Fatal(err)
	}
}

// DEL (0x7f) in a host never reaches the ASCII check: url.Parse refuses it.
func TestASCIIOriginControlCharacter(t *testing.T) {
	if _, err := url.Parse("https://a\x7f.example"); err == nil {
		t.Skip("url.Parse accepts DEL; the > 127 boundary would then matter")
	}
	if _, err := ASCIIOrigin("https://a\x7f.example"); err == nil {
		t.Fatal("DEL accepted")
	}
}
