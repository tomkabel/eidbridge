// Package tlspin builds outbound HTTPS clients for eID endpoints: normal
// chain and hostname verification stay on, TLS 1.2 is the minimum, and an
// additional SPKI SHA-256 pin check (current and next pin) runs after the
// standard verification. Disabling pins skips only that extra check.
package tlspin

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Pin is a SHA-256 hash of a certificate's SubjectPublicKeyInfo.
type Pin [32]byte

func (p Pin) String() string { return "sha256/" + base64.StdEncoding.EncodeToString(p[:]) }

// ParsePins parses "sha256/<base64>[,sha256/<base64>...]".
func ParsePins(v string) ([]Pin, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("tlspin: pin list is empty")
	}
	var out []Pin
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		b, ok := strings.CutPrefix(f, "sha256/")
		if !ok {
			return nil, fmt.Errorf("tlspin: pin %q must start with sha256/", f)
		}
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("tlspin: pin %q is not a base64 SHA-256 value", f)
		}
		var p Pin
		copy(p[:], raw)
		out = append(out, p)
	}
	return out, nil
}

// PinOf returns the pin of a certificate.
func PinOf(c *x509.Certificate) Pin { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// Options configures NewClient.
type Options struct {
	Pins     []Pin
	Disabled bool           // skip only the pin check (explicit operator choice)
	Roots    *x509.CertPool // nil: system roots for TLS (separate from auth trust)
	Timeout  time.Duration  // per request, default 130 s (covers a 120 s long poll)
}

// NewClient returns a client that never follows redirects.
func NewClient(o Options) *http.Client {
	if o.Timeout == 0 {
		o.Timeout = 130 * time.Second
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.Roots}
	if !o.Disabled {
		pins := append([]Pin(nil), o.Pins...)
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { return checkPins(cs, pins) }
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       cfg,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// CheckPins reports whether a verified chain of cs contains a pinned key.
func CheckPins(cs tls.ConnectionState, pins []Pin) error { return checkPins(cs, pins) }

// checkPins runs after Go's standard chain and hostname verification. It
// accepts the connection when any certificate of a verified chain matches.
func checkPins(cs tls.ConnectionState, pins []Pin) error {
	if len(pins) == 0 {
		return errors.New("tlspin: no pins configured")
	}
	if len(cs.VerifiedChains) == 0 {
		return errors.New("tlspin: no verified chain")
	}
	var observed []string
	for _, chain := range cs.VerifiedChains {
		for _, c := range chain {
			got := PinOf(c)
			for _, want := range pins {
				if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
					return nil
				}
			}
		}
	}
	for _, c := range cs.PeerCertificates {
		observed = append(observed, PinOf(c).String())
	}
	want := make([]string, len(pins))
	for i, p := range pins {
		want[i] = p.String()
	}
	return fmt.Errorf("tlspin: pin mismatch for %s: observed %s; expected one of %s; update EIDBRIDGE_SMARTID_TLS_PINS (see docs/security.md)",
		cs.ServerName, strings.Join(observed, ","), strings.Join(want, ","))
}

// Resolved is the effective pin policy for a mode.
type Resolved struct {
	Pins      []Pin
	Disabled  bool
	Warning   string // log at startup when non-empty
	Deviation string // published deviation record when non-empty
}

// Policy resolves EIDBRIDGE_SMARTID_TLS_PINS for a mode (architecture
// configuration invariants): unset, empty or invalid values fail in both
// modes; "disabled" warns in demo and needs the acknowledgement flag in
// production, where it also produces a deviation record.
func Policy(mode, value string, acknowledged bool) (Resolved, error) {
	if mode != "demo" && mode != "production" {
		return Resolved{}, errors.New("tlspin: mode must be demo or production")
	}
	if strings.TrimSpace(value) == "disabled" {
		r := Resolved{Disabled: true, Warning: "TLS pin check disabled: CA and hostname validation remain on; this deployment cannot claim to be hardened"}
		if mode == "production" {
			if !acknowledged {
				return Resolved{}, errors.New("tlspin: production EIDBRIDGE_SMARTID_TLS_PINS=disabled requires EIDBRIDGE_SMARTID_TLS_PINS_DISABLED_ACK=I_UNDERSTAND")
			}
			r.Deviation = "NFR-006 deviation: RP API TLS pin check disabled by operator acknowledgement; CA and hostname validation remain enabled"
		}
		return r, nil
	}
	pins, err := ParsePins(value)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{Pins: pins}, nil
}
