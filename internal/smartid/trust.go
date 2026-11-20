package smartid

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// TrustStore holds explicitly configured authentication CA certificates.
// Self-signed certificates are roots; the rest are intermediates.
type TrustStore struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	certs         []*x509.Certificate
}

// NewTrustStore builds a store from certificates.
func NewTrustStore(certs ...*x509.Certificate) *TrustStore {
	t := &TrustStore{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	for _, c := range certs {
		t.add(c)
	}
	return t
}

func (t *TrustStore) add(c *x509.Certificate) {
	if c.CheckSignatureFrom(c) == nil && c.IsCA {
		t.Roots.AddCert(c)
	} else {
		t.Intermediates.AddCert(c)
	}
	t.certs = append(t.certs, c)
}

// Empty reports whether no root is configured.
func (t *TrustStore) Empty() bool {
	for _, c := range t.certs {
		if c.CheckSignatureFrom(c) == nil && c.IsCA {
			return false
		}
	}
	return true
}

// Certificates returns the configured certificates (for `trust show`).
func (t *TrustStore) Certificates() []*x509.Certificate {
	return append([]*x509.Certificate(nil), t.certs...)
}

// Issuer returns the configured certificate that issued leaf, if any.
func (t *TrustStore) Issuer(leaf *x509.Certificate) *x509.Certificate {
	for _, c := range t.certs {
		if leaf.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

// LoadCADir loads every *.pem and *.crt (PEM or DER) file in dir.
func LoadCADir(dir string) (*TrustStore, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("smartid: read trust dir: %w", err)
	}
	t := NewTrustStore()
	names := []string{}
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		ext := filepath.Ext(n)
		if ext != ".pem" && ext != ".crt" && ext != ".cer" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		cs, err := parseCerts(b)
		if err != nil {
			return nil, fmt.Errorf("smartid: %s: %w", n, err)
		}
		for _, c := range cs {
			t.add(c)
		}
	}
	if t.Empty() {
		return nil, errors.New("smartid: no root CA in trust dir " + dir)
	}
	return t, nil
}

func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, errors.New("no certificate found")
		}
		out = append(out, c)
	}
	return out, nil
}

// StatusChecker checks the revocation status of a verified end-entity
// certificate. It must return a non-nil error when status is unknown, stale
// or unreachable; the caller maps that to status_unavailable.
type StatusChecker interface {
	Check(ctx context.Context, leaf, issuer *x509.Certificate) error
}

// ErrRevoked is returned by a StatusChecker for a revoked certificate.
var ErrRevoked = errors.New("certificate revoked")

// NoStatusCheck skips revocation checking. Only fixtures and the spike use it;
// configuration invariants reject it in production mode.
type NoStatusCheck struct{ Reason string }

// Check always succeeds.
func (NoStatusCheck) Check(context.Context, *x509.Certificate, *x509.Certificate) error { return nil }
