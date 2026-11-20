// Command eidbridge is a self-hosted Smart-ID RP API v3 to OpenID Connect
// bridge. Unofficial; see docs/legal.md.
//
//	eidbridge [--demo] [serve]      run the bridge
//	eidbridge config docs           print docs/configuration.md
//	eidbridge trust show            print active pins and CA subjects
//	eidbridge keys list|rotate|revoke
//	eidbridge doctor [--json]       upstream diagnostics (configured endpoints only)
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv config.Getenv, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eidbridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	demo := fs.Bool("demo", false, "demo mode (public demo environments, demo key, acr=demo)")
	root := fs.String("root", ".", "directory that relative paths (trust/, data/) resolve against")
	showVersion := fs.Bool("version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	rest := fs.Args()
	cmd := "serve"
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
		// Accept the global flags after the subcommand too ("serve --demo");
		// everything else belongs to the subcommand ("doctor --json").
		var pos []string
		for i := 0; i < len(rest); i++ {
			switch a := strings.TrimLeft(rest[i], "-"); {
			case strings.HasPrefix(rest[i], "-") && (a == "demo" || a == "demo=true"):
				*demo = true
			case strings.HasPrefix(rest[i], "-") && a == "root" && i+1 < len(rest):
				*root = rest[i+1]
				i++
			case strings.HasPrefix(rest[i], "-") && strings.HasPrefix(a, "root="):
				*root = strings.TrimPrefix(a, "root=")
			default:
				pos = append(pos, rest[i])
			}
		}
		rest = pos
	}
	switch cmd {
	case "serve":
		return serve(getenv, *demo, *root, stderr)
	case "config":
		if len(rest) == 1 && rest[0] == "docs" {
			fmt.Fprint(stdout, config.Markdown())
			return 0
		}
	case "trust":
		if len(rest) == 1 && rest[0] == "show" {
			return trustShow(getenv, *demo, *root, stdout, stderr)
		}
	case "keys":
		return keysCmd(rest, getenv, *demo, *root, stdout, stderr)
	case "doctor":
		return doctor(rest, getenv, *demo, *root, stdout, stderr)
	}
	fmt.Fprintln(stderr, "usage: eidbridge [--demo] [serve|config docs|trust show|keys list|keys rotate <alg>|keys revoke <kid>|doctor [--json]]")
	return 2
}
