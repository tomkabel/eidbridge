package config

import (
	"net"
	"strings"
)

// Known demo indicators: the one table to update when SK changes demo
// endpoints (Story 2.7). Values from the pinned environments page and the
// 2026-11-20 spike (docs/adr/0001-spike-outcome.md).
var (
	DemoRPUUID = "00000000-0000-4000-8000-000000000000"
	DemoRPName = "DEMO"
	// DemoHosts are eID demo API hosts. Production refuses all of them.
	DemoHosts = map[string]bool{"sid.demo.sk.ee": true, "tsp.demo.sk.ee": true, "demo.sk.ee": true, "aia.demo.sk.ee": true}
	// DemoCAFingerprints are SHA-256 (DER, hex) of demo authentication CAs.
	DemoCAFingerprints = map[string]string{
		"84242dd8e1a1878f76ff2b5ca0c8ef22c8a8863cf072e56a9f0dc28add96b143": "TEST of SK ID Solutions ROOT G1E",
		"063a4e908785a2b45fba27a22d45d9f2bbaa9a382e5b103e1d1036832cee6ac2": "TEST of SK ID Solutions EID-Q 2024E",
		"994477a5a63d1087bbcfa0d6721c401c8e1a778987503b0e202777b3c3cb1ff6": "TEST of SK ID Solutions EID-Q 2021E",
	}
	// ProductionHosts are the live RP API hosts. Demo refuses them.
	ProductionHosts = map[string]bool{"rp-api.smart-id.com": true, "mid.sk.ee": true}
)

// demoDomain is SK's demo domain: every host at or under it is a demo host.
const demoDomain = "demo.sk.ee"

// NormalizeHost lowercases a host name and strips one trailing dot, so
// "SID.DEMO.SK.EE." and "sid.demo.sk.ee" compare equal.
func NormalizeHost(h string) string {
	h = strings.ToLower(h)
	return strings.TrimSuffix(h, ".")
}

// IsDemoHost reports whether h (any case, optional trailing dot, optional
// :port) is a known demo host or under the demo domain.
func IsDemoHost(h string) bool {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = NormalizeHost(h)
	return DemoHosts[h] || h == demoDomain || strings.HasSuffix(h, "."+demoDomain)
}

// IsProductionHost reports whether h is a known live eID API host.
func IsProductionHost(h string) bool {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return ProductionHosts[NormalizeHost(h)]
}
