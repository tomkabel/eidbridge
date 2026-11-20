package main

import (
	"encoding/asn1"
	"log/slog"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/tlspin"
	"github.com/tomkabel/eidbridge/internal/webeid"
	"github.com/tomkabel/eidbridge/internal/webeid/webeidtest"
)

func init() { extraMethods["webeid"] = buildWebEID }

// webeidFixture is the synthetic card PKI in mock mode (tests use it to
// make tokens; a browser cannot without a card).
var webeidFixture *webeidtest.PKI

func buildWebEID(cfg *config.Config, log *slog.Logger) (authn.Method, func(), error) {
	w := cfg.WebEID
	var disallowed []asn1.ObjectIdentifier
	for _, o := range w.DisallowedPolicies {
		oid, err := parseOID(o)
		if err != nil {
			return nil, nil, err
		}
		disallowed = append(disallowed, oid)
	}
	v := &webeid.Validator{Trust: w.Trust, DisallowedPolicies: disallowed, Now: time.Now,
		Status: smartid.NoStatusCheck{Reason: "disabled by configuration (demo only)"}}
	switch {
	case w.Env == "mock":
		webeidFixture = webeidtest.NewPKI("eidbridge mock")
		v.Trust = smartid.NewTrustStore(webeidFixture.Root, webeidFixture.Inter)
		log.Info("Web eID trusts the synthetic card CA (mock)")
	case w.CertStatus == "ocsp":
		hosts := map[string]bool{}
		for _, h := range w.StatusHosts {
			hosts[h] = true
		}
		v.Status = &revocation.Checker{AllowedHosts: hosts, CRLFallback: true, Revoked: smartid.ErrRevoked,
			HTTP: tlspin.NewClient(tlspin.Options{Disabled: true, Timeout: 5 * time.Second})}
	}
	m, err := webeid.NewMethod(webeid.MethodConfig{Validator: v, IsDemo: cfg.Demo})
	return m, nil, err
}
