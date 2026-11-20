package config

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
	}
	// ProductionHosts are the live RP API hosts. Demo refuses them.
	ProductionHosts = map[string]bool{"rp-api.smart-id.com": true, "mid.sk.ee": true}
)
