// Package revocation checks end-entity certificate status by OCSP (from the
// certificate's AIA) with CRL fallback. Only explicitly allow-listed hosts
// are contacted, every fetch has a deadline and a size cap, redirects are
// refused, and unknown, stale or unreachable status is an error: callers map
// it to status_unavailable and never to success.
package revocation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrRevoked reports a revoked certificate.
var ErrRevoked = errors.New("revocation: certificate revoked")

// Checker implements smartid.StatusChecker and the Web eID status check.
type Checker struct {
	HTTP         *http.Client
	AllowedHosts map[string]bool // host[:port] of OCSP responders and CRL distribution points
	Timeout      time.Duration   // per fetch, default 5 s
	MaxBytes     int64           // default 4 MiB (SK demo CRL was 652 KB on 2026-11-20)
	MaxAge       time.Duration   // reject responses whose thisUpdate is older, default 48 h
	CRLFallback  bool
	Now          func() time.Time
	// Revoked is returned instead of ErrRevoked when set (lets callers use
	// their own sentinel, for example smartid.ErrRevoked).
	Revoked error

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	err     error
	expires time.Time
}

func (c *Checker) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 4 << 20
	}
	if c.MaxAge == 0 {
		c.MaxAge = 48 * time.Hour
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
}

func (c *Checker) revoked() error {
	if c.Revoked != nil {
		return c.Revoked
	}
	return ErrRevoked
}

// Check returns nil only for a fresh, correctly signed "good" status.
func (c *Checker) Check(ctx context.Context, leaf, issuer *x509.Certificate) error {
	c.defaults()
	if leaf == nil || issuer == nil {
		return errors.New("revocation: missing certificate or issuer")
	}
	key := string(issuer.RawSubjectPublicKeyInfo) + "|" + leaf.SerialNumber.String()
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.err
	}
	c.mu.Unlock()
	err, until := c.ocsp(ctx, leaf, issuer)
	if err != nil && !errors.Is(err, c.revoked()) && c.CRLFallback {
		if cerr, cuntil := c.crl(ctx, leaf, issuer); cerr == nil || errors.Is(cerr, c.revoked()) {
			err, until = cerr, cuntil
		} else {
			err = fmt.Errorf("%w; crl: %v", err, cerr)
		}
	}
	if err == nil || errors.Is(err, c.revoked()) {
		c.mu.Lock()
		if c.cache == nil {
			c.cache = map[string]cached{}
		}
		if len(c.cache) > 10000 {
			c.cache = map[string]cached{}
		}
		c.cache[key] = cached{err: err, expires: until}
		c.mu.Unlock()
	}
	return err
}

func (c *Checker) allowed(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !c.AllowedHosts[u.Host] {
		return nil, fmt.Errorf("revocation: endpoint host not allow-listed")
	}
	return u, nil
}

func (c *Checker) fetch(ctx context.Context, req *http.Request) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	resp, err := c.HTTP.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("revocation: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation: http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.MaxBytes {
		return nil, errors.New("revocation: response exceeds size cap")
	}
	return b, nil
}

func (c *Checker) ocsp(ctx context.Context, leaf, issuer *x509.Certificate) (error, time.Time) {
	if len(leaf.OCSPServer) == 0 {
		return errors.New("revocation: certificate has no OCSP responder"), time.Time{}
	}
	u, err := c.allowed(leaf.OCSPServer[0])
	if err != nil {
		return err, time.Time{}
	}
	body, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return err, time.Time{}
	}
	req, _ := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/ocsp-request")
	raw, err := c.fetch(ctx, req)
	if err != nil {
		return err, time.Time{}
	}
	r, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil {
		return fmt.Errorf("revocation: ocsp response: %w", err), time.Time{}
	}
	if r.Certificate != nil && !r.Certificate.Equal(issuer) {
		// Delegated responder: must be issued by the CA and carry OCSPSigning.
		ok := false
		for _, u := range r.Certificate.ExtKeyUsage {
			ok = ok || u == x509.ExtKeyUsageOCSPSigning
		}
		if !ok {
			return errors.New("revocation: delegated OCSP responder lacks OCSPSigning"), time.Time{}
		}
	}
	now := c.Now()
	if r.ThisUpdate.After(now.Add(5*time.Minute)) || now.Sub(r.ThisUpdate) > c.MaxAge ||
		(!r.NextUpdate.IsZero() && now.After(r.NextUpdate)) {
		return errors.New("revocation: stale OCSP response"), time.Time{}
	}
	until := now.Add(5 * time.Minute)
	if !r.NextUpdate.IsZero() && r.NextUpdate.Before(until) {
		until = r.NextUpdate
	}
	switch r.Status {
	case ocsp.Good:
		return nil, until
	case ocsp.Revoked:
		return c.revoked(), until
	}
	return errors.New("revocation: OCSP status unknown"), time.Time{}
}

func (c *Checker) crl(ctx context.Context, leaf, issuer *x509.Certificate) (error, time.Time) {
	if len(leaf.CRLDistributionPoints) == 0 {
		return errors.New("revocation: no CRL distribution point"), time.Time{}
	}
	u, err := c.allowed(leaf.CRLDistributionPoints[0])
	if err != nil {
		return err, time.Time{}
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	raw, err := c.fetch(ctx, req)
	if err != nil {
		return err, time.Time{}
	}
	l, err := x509.ParseRevocationList(raw)
	if err != nil {
		return fmt.Errorf("revocation: crl parse: %w", err), time.Time{}
	}
	if err := l.CheckSignatureFrom(issuer); err != nil {
		return errors.New("revocation: crl signature"), time.Time{}
	}
	now := c.Now()
	if l.NextUpdate.IsZero() || now.After(l.NextUpdate) || now.Sub(l.ThisUpdate) > c.MaxAge {
		return errors.New("revocation: stale CRL"), time.Time{}
	}
	for _, e := range l.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return c.revoked(), l.NextUpdate
		}
	}
	return nil, l.NextUpdate
}
