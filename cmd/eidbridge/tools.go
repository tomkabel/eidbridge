package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// doctor is extended by Story 7.3.
var doctor = func(args []string, getenv config.Getenv, demo bool, root string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "doctor: not available")
	return 2
}
