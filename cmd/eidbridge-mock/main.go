// Command eidbridge-mock is an offline Smart-ID RP API v3 server for tests
// and demos (Story 7.4, FR-027). Responses are signed by a test CA
// generated at start; --ca-out writes that CA so a bridge (or any RP) can
// trust it. Identities are SK's published demo test codes, clearly test
// data. It is not a copy of SK's service and must not face the internet.
//
//	eidbridge-mock --listen 127.0.0.1:8090 --ca-out mock-ca.pem [--scenario scenarios.yaml] [--auto DOC]
//
// Control API (besides the RP API under /smart-id-rp/v3):
//
//	GET  /_mock/sessions                       pending session ids
//	POST /_mock/sessions/{id}/complete[?document=…]
//	POST /_mock/sessions/{id}/refuse|timeout|wrong-vc
package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, nil)) }

// run starts the server; ready (tests) receives the bound address.
func run(args []string, stdout, stderr io.Writer, ready chan<- string) int {
	fs := flag.NewFlagSet("eidbridge-mock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8090", "listen address (loopback unless --allow-remote)")
	allowRemote := fs.Bool("allow-remote", false, "allow a non-loopback listen address")
	caOut := fs.String("ca-out", "", "write the test CA certificates (PEM) here")
	scenario := fs.String("scenario", "", "YAML map of document number to endResult, added to the defaults")
	auto := fs.String("auto", "", "resolve device-link sessions with this document on first poll")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := checkListen(*listen, *allowRemote); err != nil {
		fmt.Fprintln(stderr, "eidbridge-mock:", err)
		return 2
	}
	srv := smartidtest.NewServer()
	srv.MaxWait = 2 * time.Second
	srv.AutoResolve = *auto
	sc := map[string]string{}
	for k, v := range smartidtest.DefaultScenarios {
		sc[k] = v
	}
	if *scenario != "" {
		b, err := os.ReadFile(*scenario)
		if err != nil {
			fmt.Fprintln(stderr, "eidbridge-mock:", err)
			return 2
		}
		var extra map[string]string
		if err := yaml.Unmarshal(b, &extra); err != nil {
			fmt.Fprintln(stderr, "eidbridge-mock: scenario:", err)
			return 2
		}
		for k, v := range extra {
			sc[k] = v
		}
	}
	srv.Scenarios = sc
	if *caOut != "" {
		pemBytes := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.PKI.Root.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.PKI.Inter.Raw})...)
		if err := os.WriteFile(*caOut, pemBytes, 0o644); err != nil {
			fmt.Fprintln(stderr, "eidbridge-mock:", err)
			return 2
		}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge-mock:", err)
		return 1
	}
	fmt.Fprintf(stdout, "eidbridge-mock: RP API at http://%s/smart-id-rp (test data only)\n", ln.Addr())
	if ready != nil {
		ready <- ln.Addr().String()
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 5 * time.Second}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "eidbridge-mock:", err)
		return 1
	}
	return 0
}

func checkListen(addr string, allowRemote bool) error {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(h)
	if h == "localhost" || (ip != nil && ip.IsLoopback()) || allowRemote {
		return nil
	}
	return fmt.Errorf("refusing to listen on non-loopback %s without --allow-remote", addr)
}
