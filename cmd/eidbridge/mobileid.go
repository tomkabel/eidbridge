package main

import (
	"encoding/asn1"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/mobileid"
	"github.com/tomkabel/eidbridge/internal/mobileid/mobileidtest"
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/tlspin"
)

func init() { extraMethods["mobileid"] = buildMobileID }

// buildMobileID wires Story 4.2. In mock mode a synthetic MID REST API runs
// on a loopback port (demo only, enforced by configuration invariants).
func buildMobileID(cfg *config.Config, log *slog.Logger) (authn.Method, func(), error) {
	m := cfg.MobileID
	var closer func()
	trust, base := m.Trust, m.BaseURL
	httpClient := tlspin.NewClient(tlspin.Options{Pins: m.Pins.Pins, Disabled: m.Pins.Disabled, Timeout: 75 * time.Second})
	var status smartid.StatusChecker = smartid.NoStatusCheck{Reason: "disabled by configuration (demo only)"}
	var oids []asn1.ObjectIdentifier
	for _, o := range m.PolicyOIDs {
		oid, err := parseOID(o)
		if err != nil {
			return nil, nil, err
		}
		oids = append(oids, oid)
	}
	if m.Env == "mock" {
		fx := mobileidtest.NewServer(mobileidtest.NewPKI("eidbridge mock"))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		hs := &httptest.Server{Listener: ln, Config: &http.Server{Handler: fx, ReadHeaderTimeout: 5 * time.Second}}
		hs.Start()
		closer = hs.Close
		trust, base, httpClient = smartid.NewTrustStore(fx.PKI.Root, fx.PKI.Inter), hs.URL, hs.Client()
		oids = []asn1.ObjectIdentifier{mobileid.MIDPolicyOID}
		log.Info("Mobile-ID fixture upstream listening", "address", hs.URL, "ok_phone", mobileidtest.DefaultPhone)
	} else if m.CertStatus == "ocsp" {
		hosts := map[string]bool{}
		for _, h := range m.StatusHosts {
			hosts[h] = true
		}
		status = &revocation.Checker{AllowedHosts: hosts, CRLFallback: true, Revoked: smartid.ErrRevoked,
			HTTP: tlspin.NewClient(tlspin.Options{Disabled: true, Timeout: 5 * time.Second})}
	}
	c, err := mobileid.NewClient(mobileid.Config{BaseURL: base, RPUUID: m.RPUUID, RPName: m.RPName, HTTP: httpClient,
		Trust: trust, PolicyOIDs: oids, Status: status})
	if err != nil {
		return nil, closer, err
	}
	meth, err := mobileid.NewMethod(mobileid.MethodConfig{Client: c, DisplayText: map[string]string{"en": m.DisplayText}, IsDemo: cfg.Demo})
	return meth, closer, err
}
