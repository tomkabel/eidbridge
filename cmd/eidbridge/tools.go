package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	doctorpkg "github.com/tomkabel/eidbridge/internal/doctor"
	"io"
	"time"

	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/jose"
	"github.com/tomkabel/eidbridge/internal/oidc"
)

func trustShow(getenv config.Getenv, demo bool, root string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(getenv, demo, root)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge:", err)
		return 1
	}
	s := cfg.SmartID
	fmt.Fprintf(stdout, "smartid env=%s base=%s\n", s.Env, s.BaseURL)
	if s.Pins.Disabled {
		fmt.Fprintln(stdout, "tls pins: DISABLED (CA and hostname validation remain on)")
	}
	for _, p := range s.Pins.Pins {
		fmt.Fprintln(stdout, "tls pin:", p.String())
	}
	if s.Trust != nil {
		for _, c := range s.Trust.Certificates() {
			sum := sha256.Sum256(c.Raw)
			fmt.Fprintf(stdout, "auth CA: %s  not_after=%s  sha256=%s\n", c.Subject.CommonName, c.NotAfter.Format("2006-01-02"), hex.EncodeToString(sum[:]))
		}
	}
	return 0
}

func keysCmd(args []string, getenv config.Getenv, demo bool, root string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(getenv, demo, root)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge:", err)
		return 1
	}
	ks, err := oidc.LoadKeys(cfg.KeyDir, cfg.Demo, cfg.DenyFP, nil)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge:", err)
		return 1
	}
	switch {
	case len(args) == 1 && args[0] == "list":
		json.NewEncoder(stdout).Encode(ks.Entries())
		return 0
	case len(args) == 2 && args[0] == "rotate" && (args[1] == jose.RS256 || args[1] == jose.ES256):
		// Retired key stays in JWKS for the longest token lifetime plus skew.
		kid, err := ks.Rotate(args[1], cfg.AccessTokenTTL+cfg.ClockSkew+time.Minute)
		if err != nil {
			fmt.Fprintln(stderr, "eidbridge:", err)
			return 1
		}
		fmt.Fprintln(stdout, "new active key:", kid, "(restart the bridge to load it)")
		return 0
	case len(args) == 2 && args[0] == "revoke":
		if err := ks.Revoke(args[1]); err != nil {
			fmt.Fprintln(stderr, "eidbridge:", err)
			return 1
		}
		fmt.Fprintln(stdout, "revoked", args[1], "- restart the bridge now: the restart also replaces the sealing key, so every client must re-authenticate")
		return 0
	}
	fmt.Fprintln(stderr, "usage: eidbridge keys list | keys rotate RS256|ES256 | keys revoke <kid>")
	return 2
}

// doctor checks the configured upstreams and trust bundles (Story 7.3).
var doctor = func(args []string, getenv config.Getenv, demo bool, root string, stdout, stderr io.Writer) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 1 || (len(args) == 1 && !asJSON) {
		fmt.Fprintln(stderr, "usage: eidbridge doctor [--json]")
		return 2
	}
	cfg, err := config.Load(getenv, demo, root)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge:", err)
		return 1
	}
	var targets []doctorpkg.Target
	var bundles []doctorpkg.Bundle
	if contains(cfg.Methods, "smartid") && cfg.SmartID.Env != "mock" {
		s := cfg.SmartID
		targets = append(targets, doctorpkg.Target{Component: "smartid", Env: s.Env, BaseURL: s.BaseURL, Pins: s.Pins.Pins, PinsDisabled: s.Pins.Disabled})
		bundles = append(bundles, doctorpkg.Bundle{Component: "smartid", Certs: s.Trust.Certificates()})
	}
	if contains(cfg.Methods, "mobileid") && cfg.MobileID.Env != "mock" {
		m := cfg.MobileID
		targets = append(targets, doctorpkg.Target{Component: "mobileid", Env: m.Env, BaseURL: m.BaseURL, Pins: m.Pins.Pins, PinsDisabled: m.Pins.Disabled})
		bundles = append(bundles, doctorpkg.Bundle{Component: "mobileid", Certs: m.Trust.Certificates()})
	}
	if contains(cfg.Methods, "webeid") && cfg.WebEID.Env != "mock" {
		bundles = append(bundles, doctorpkg.Bundle{Component: "webeid", Certs: cfg.WebEID.Trust.Certificates()})
	}
	if contains(cfg.Methods, "eudi") && cfg.EUDI.Env != "mock" {
		bundles = append(bundles, doctorpkg.Bundle{Component: "eudi", Certs: cfg.EUDI.Trust.Certificates()})
	}
	rs := doctorpkg.Run(context.Background(), targets, bundles, time.Now())
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"version": 1, "results": rs})
	} else {
		for _, r := range rs {
			if r.Kind == "upstream" {
				fmt.Fprintf(stdout, "%-9s %-10s %-24s %-8s %-24s pin %-8s cert expires in %dd  rtt %dms  %s %s\n",
					r.Component, r.Env, r.Host, r.TLSVersion, r.Cipher, r.Pin, r.ExpiresIn, r.RTTMillis, r.Status, r.Detail)
			} else {
				fmt.Fprintf(stdout, "%-9s trust      %d certs, %s  %s\n", r.Component, r.Certs, r.Detail, r.Status)
			}
		}
	}
	if doctorpkg.Failed(rs) {
		return 1
	}
	return 0
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
