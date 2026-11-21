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
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
	v2 "github.com/tomkabel/eidbridge/internal/smartid/v2"
	"github.com/tomkabel/eidbridge/internal/smartid/v2/v2test"
	"github.com/tomkabel/eidbridge/internal/tlspin"
)

func init() { extraMethods["smartid-v2"] = buildSmartIDV2 }

// buildSmartIDV2 wires the legacy RP API v2 (Story 7.5). It reuses the
// Smart-ID host, pins, trust and status settings.
func buildSmartIDV2(cfg *config.Config, log *slog.Logger) (authn.Method, func(), error) {
	s := cfg.SmartID
	base, trust := s.BaseURL+"/v2", s.Trust
	httpClient := tlspin.NewClient(tlspin.Options{Pins: s.Pins.Pins, Disabled: s.Pins.Disabled})
	var status smartid.StatusChecker = smartid.NoStatusCheck{Reason: "disabled by configuration (demo only)"}
	var closer func()
	var oids []asn1.ObjectIdentifier
	for _, o := range s.PolicyOIDs {
		oid, err := parseOID(o)
		if err != nil {
			return nil, nil, err
		}
		oids = append(oids, oid)
	}
	switch {
	case s.Env == "mock":
		fx := v2test.NewServer()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		hs := &httptest.Server{Listener: ln, Config: &http.Server{Handler: fx, ReadHeaderTimeout: 5 * time.Second}}
		hs.Start()
		closer = hs.Close
		base, trust, httpClient, oids = hs.URL+"/smart-id-rp/v2", smartid.NewTrustStore(fx.PKI.Root, fx.PKI.Inter), hs.Client(), smartid.DemoPolicyOIDs
	case s.CertStatus == "ocsp":
		hosts := map[string]bool{}
		for _, h := range s.StatusHosts {
			hosts[h] = true
		}
		status = &revocation.Checker{AllowedHosts: hosts, CRLFallback: true, Revoked: smartid.ErrRevoked,
			HTTP: tlspin.NewClient(tlspin.Options{Disabled: true, Timeout: 5 * time.Second})}
	}
	c, err := v2.NewClient(v2.Config{BaseURL: base, RPUUID: cfg.SmartIDV2.RPUUID, RPName: cfg.SmartIDV2.RPName, HTTP: httpClient,
		Trust: trust, MinCertLevel: s.CertLevel, PolicyOIDs: oids, Status: status})
	if err != nil {
		return nil, closer, err
	}
	log.Warn("Smart-ID RP API v2 is legacy; plan the move to v3")
	m, err := v2.NewMethod(v2.MethodConfig{Client: c, DisplayText: s.DisplayText, IsDemo: cfg.Demo})
	return m, closer, err
}
