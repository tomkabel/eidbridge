package revocation

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"golang.org/x/crypto/ocsp"
)

// E02c: OCSP and CRL fetches never follow redirects, even to an
// allow-listed host serving a valid answer.
func TestStatusFetchesRefuseRedirects(t *testing.T) {
	p := smartidtest.NewPKI("ocsp")
	now := time.Now()
	good := &responder{pki: p, status: ocsp.Good, this: now.Add(-time.Minute), next: now.Add(time.Hour), crl: nil}
	good.crl = crlFor(t, p, nil, now.Add(-time.Minute), now.Add(time.Hour))
	target := httptest.NewServer(good)
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	tu, _ := url.Parse(target.URL)
	ru, _ := url.Parse(redir.URL)
	allowed := map[string]bool{tu.Host: true, ru.Host: true}
	for name, mod := range map[string]func(*Checker, *x509.Certificate){
		"ocsp": func(c *Checker, l *x509.Certificate) {
			l.OCSPServer, l.CRLDistributionPoints = []string{redir.URL + "/ocsp"}, nil
		},
		"crl": func(c *Checker, l *x509.Certificate) {
			l.OCSPServer, l.CRLDistributionPoints = nil, []string{redir.URL + "/crl"}
			c.CRLFallback = true
		},
	} {
		leaf := p.NewLeaf(smartidtest.LeafOptions{}).Cert
		c := &Checker{AllowedHosts: allowed}
		mod(c, leaf)
		before := good.hits.Load()
		if err := c.Check(context.Background(), leaf, p.Inter); err == nil {
			t.Errorf("%s: redirect followed to a good answer", name)
		}
		if good.hits.Load() != before {
			t.Errorf("%s: the redirect target was contacted", name)
		}
	}
}
