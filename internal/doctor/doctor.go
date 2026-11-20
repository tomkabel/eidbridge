// Package doctor checks upstream connectivity and trust material on demand
// (Story 7.3, FR-026). It contacts only the configured upstream base URLs
// and never runs in the request path: readiness stays independent of
// upstreams (ADR-009).
package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/tomkabel/eidbridge/internal/tlspin"
)

// Target is one configured upstream.
type Target struct {
	Component    string // smartid, mobileid
	Env          string
	BaseURL      string
	Pins         []tlspin.Pin
	PinsDisabled bool
	Roots        *x509.CertPool // nil: system roots
}

// Bundle is one configured trust bundle.
type Bundle struct {
	Component string
	Certs     []*x509.Certificate
}

// Result is one line of the report. The JSON form is documented in
// docs/doctor.md.
type Result struct {
	Component  string `json:"component"`
	Kind       string `json:"kind"` // upstream or trust
	Env        string `json:"env,omitempty"`
	Host       string `json:"host,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Pin        string `json:"pin,omitempty"` // ok, mismatch, disabled
	ExpiresIn  int    `json:"cert_expires_in_days"`
	RTTMillis  int64  `json:"rtt_ms,omitempty"`
	Certs      int    `json:"certs,omitempty"`
	Status     string `json:"status"` // OK, WARN, FAIL
	Detail     string `json:"detail,omitempty"`
}

// WarnDays is the expiry warning threshold.
const WarnDays = 30

// Run checks every target and bundle.
func Run(ctx context.Context, targets []Target, bundles []Bundle, now time.Time) []Result {
	var out []Result
	for _, t := range targets {
		out = append(out, checkTarget(ctx, t, now))
	}
	for _, b := range bundles {
		out = append(out, checkBundle(b, now))
	}
	return out
}

func days(t, now time.Time) int { return int(t.Sub(now).Hours() / 24) }

func checkTarget(ctx context.Context, t Target, now time.Time) Result {
	r := Result{Component: t.Component, Kind: "upstream", Env: t.Env, Status: "FAIL"}
	u, err := url.Parse(t.BaseURL)
	if err != nil || u.Host == "" {
		r.Detail = "invalid base URL"
		return r
	}
	r.Host = u.Host
	var state *tls.ConnectionState
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: t.Roots}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		state = &cs
		return nil
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: cfg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, t.BaseURL, nil)
	start := time.Now()
	resp, err := hc.Do(req)
	r.RTTMillis = time.Since(start).Milliseconds()
	if err != nil {
		r.Detail = "connection failed: " + err.Error()
		return r
	}
	resp.Body.Close()
	if state == nil || len(state.PeerCertificates) == 0 {
		r.Detail = "no TLS connection state"
		return r
	}
	r.TLSVersion = tls.VersionName(state.Version)
	r.Cipher = tls.CipherSuiteName(state.CipherSuite)
	leaf := state.PeerCertificates[0]
	r.ExpiresIn = days(leaf.NotAfter, now)
	switch {
	case t.PinsDisabled:
		r.Pin = "disabled"
	case tlspin.CheckPins(*state, t.Pins) == nil:
		r.Pin = "ok"
	default:
		r.Pin = "mismatch"
		r.Detail = "no configured pin matches the served chain"
		return r
	}
	r.Status = "OK"
	if r.ExpiresIn < WarnDays {
		r.Status = "WARN"
		r.Detail = fmt.Sprintf("server certificate expires in %d days", r.ExpiresIn)
	}
	if t.PinsDisabled {
		r.Status = "WARN"
		r.Detail = joinDetail(r.Detail, "pins disabled")
	}
	return r
}

func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func checkBundle(b Bundle, now time.Time) Result {
	r := Result{Component: b.Component, Kind: "trust", Certs: len(b.Certs), Status: "FAIL"}
	if len(b.Certs) == 0 {
		r.Detail = "no CA certificates"
		return r
	}
	earliest := b.Certs[0].NotAfter
	for _, c := range b.Certs[1:] {
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
	}
	r.ExpiresIn = days(earliest, now)
	r.Detail = "earliest expiry " + earliest.UTC().Format("2006-01-02")
	switch {
	case !now.Before(earliest):
		r.Detail = "a CA certificate has expired (" + earliest.UTC().Format("2006-01-02") + ")"
	case r.ExpiresIn < WarnDays:
		r.Status = "WARN"
	default:
		r.Status = "OK"
	}
	return r
}

// Failed reports whether any result is FAIL.
func Failed(rs []Result) bool {
	for _, r := range rs {
		if r.Status == "FAIL" {
			return true
		}
	}
	return false
}
