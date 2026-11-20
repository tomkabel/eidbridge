package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/eudi"
	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/tlspin"
)

func init() { extraMethods["eudi"] = buildEUDI }

// eudiFixture is the simulated PID provider in mock mode.
var eudiFixture *walletsim.Provider

func buildEUDI(cfg *config.Config, log *slog.Logger) (authn.Method, func(), error) {
	e := cfg.EUDI
	u, _ := url.Parse(cfg.BaseURL)
	var id *eudi.VerifierIdentity
	var err error
	if e.CertFile != "" {
		id, err = loadVerifierIdentity(e.CertFile, e.KeyFile)
	} else {
		id, err = eudi.NewSelfSignedIdentity(u.Hostname())
		log.Warn("EUDI verifier uses a self-signed demo certificate; wallets that check relying-party certificates will refuse it")
	}
	if err != nil {
		return nil, nil, err
	}
	v := &eudi.Verifier{Trust: e.Trust, VCTs: e.VCTs, RequireStatus: e.RequireStatus, Now: time.Now}
	hosts := map[string]bool{}
	for _, h := range e.StatusHosts {
		hosts[h] = true
	}
	v.Status = &eudi.StatusChecker{AllowedHosts: hosts, HTTP: tlspin.NewClient(tlspin.Options{Disabled: true, Timeout: 5 * time.Second})}
	if e.Env == "mock" {
		eudiFixture = walletsim.NewProvider("eidbridge mock")
		v.Trust = smartid.NewTrustStore(eudiFixture.Root)
	}
	m, err := eudi.NewMethod(eudi.MethodConfig{Identity: id, Verifier: v, Flows: e.Flows, IsDemo: cfg.Demo})
	if err == nil {
		log.Info("EUDI verifier ready", "client_id", id.ClientID())
	}
	return m, nil, err
}

func loadVerifierIdentity(certFile, keyFile string) (*eudi.VerifierIdentity, error) {
	st, err := os.Stat(keyFile)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be readable by group or others", keyFile)
	}
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for blk, rest := pem.Decode(cb); blk != nil; blk, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil || len(chain) == 0 {
		return nil, errors.New("verifier certificate or key PEM missing")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	}
	if key == nil {
		return nil, errors.New("verifier key must be an EC P-256 key")
	}
	return &eudi.VerifierIdentity{Key: key, Chain: chain}, nil
}
