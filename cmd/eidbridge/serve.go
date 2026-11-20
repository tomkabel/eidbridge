package main

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"github.com/tomkabel/eidbridge/internal/clock"
	"github.com/tomkabel/eidbridge/internal/config"
	"github.com/tomkabel/eidbridge/internal/logx"
	"github.com/tomkabel/eidbridge/internal/oidc"
	"github.com/tomkabel/eidbridge/internal/revocation"
	"github.com/tomkabel/eidbridge/internal/smartid"
	"github.com/tomkabel/eidbridge/internal/smartid/smartidtest"
	"github.com/tomkabel/eidbridge/internal/store"
	"github.com/tomkabel/eidbridge/internal/tlspin"
	"github.com/tomkabel/eidbridge/internal/version"
	"github.com/tomkabel/eidbridge/internal/web"
)

// App is a fully wired bridge (also used by integration tests).
type App struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Handler  http.Handler
	Web      *web.Server
	Provider *oidc.Provider
	Codes    *store.Codes
	Fixture  *smartidtest.Server
	closers  []func()
}

// Close releases background resources.
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
}

func newLogger(w io.Writer, debug bool) *slog.Logger {
	lvl := slog.LevelInfo
	if debug {
		lvl = slog.LevelDebug
	}
	return logx.New(w, lvl)
}

// Build wires configuration into a running handler without listening.
func Build(cfg *config.Config, log *slog.Logger, clk clock.Clock) (*App, error) {
	a := &App{Cfg: cfg, Log: log}
	ks, err := oidc.LoadKeys(cfg.KeyDir, cfg.Demo, cfg.DenyFP, clk.Now)
	if err != nil {
		return nil, err
	}
	if err := oidc.CheckSubjectLock(cfg.KeyDir, cfg.Clients, cfg.Subjects); err != nil {
		return nil, err
	}
	var methods []authn.Method
	for _, name := range cfg.Methods {
		m, closer, err := buildMethod(name, cfg, log, a)
		if err != nil {
			a.Close()
			return nil, err
		}
		if closer != nil {
			a.closers = append(a.closers, closer)
		}
		methods = append(methods, m)
	}
	reg, err := authn.NewRegistry(methods...)
	if err != nil {
		return nil, err
	}
	a.Codes = store.NewCodes(store.CodesConfig{Cap: cfg.CodeCap, CodeTTL: 60 * time.Second, TombstoneTTL: cfg.AccessTokenTTL + cfg.ClockSkew, Clock: clk})
	prov, err := oidc.New(oidc.Config{Issuer: cfg.Issuer, Demo: cfg.Demo, Clients: cfg.Clients, Keys: ks, Subjects: cfg.Subjects,
		AccessTokenTTL: cfg.AccessTokenTTL, CodeTTL: 60 * time.Second, ClockSkew: cfg.ClockSkew, MethodACR: cfg.MethodACR,
		Methods: reg.Names(), Clock: clk, Codes: a.Codes})
	if err != nil {
		return nil, err
	}
	tk := make([]byte, 32)
	rand.Read(tk)
	origin := originOf(cfg.BaseURL)
	ws, err := web.New(web.Config{Provider: prov, Registry: reg, Clock: clk, Log: log, PublicOrigin: origin, Demo: cfg.Demo,
		FlowTTL: cfg.FlowTTL, MaxFlows: cfg.MaxFlows, PollSlots: cfg.PollSlots,
		UpstreamRate: web.Bucket{Burst: cfg.UpstreamRate, Rate: cfg.UpstreamRate},
		PerIP:        web.Bucket{Burst: cfg.PerIP[0], Rate: cfg.PerIP[1]}, PerClient: web.Bucket{Burst: cfg.PerClient[0], Rate: cfg.PerClient[1]},
		PerTarget: web.Bucket{Burst: cfg.PerTarget[0], Rate: cfg.PerTarget[1]}, BucketCap: cfg.BucketCap,
		RetryAttempts: cfg.RetryBudget, RetryBase: cfg.RetryBase, TrustedProxies: cfg.TrustedProxies,
		DefaultLocale: cfg.DefaultLocale, TargetKey: tk, RememberMethod: cfg.RememberMethod})
	if err != nil {
		return nil, err
	}
	a.closers = append(a.closers, ws.Close)
	prov.SetFrontend(ws)
	mux := http.NewServeMux()
	prov.Register(mux)
	ws.Register(mux)
	a.Handler, a.Web, a.Provider = web.AccessLog(log, mux), ws, prov
	return a, nil
}

func originOf(base string) string {
	i := strings.Index(base, "://")
	if i < 0 {
		return base
	}
	if j := strings.Index(base[i+3:], "/"); j >= 0 {
		return base[:i+3+j]
	}
	return base
}

func buildMethod(name string, cfg *config.Config, log *slog.Logger, a *App) (authn.Method, func(), error) {
	switch name {
	case "smartid":
		return buildSmartID(cfg, log, a)
	}
	if b := extraMethods[name]; b != nil {
		return b(cfg, log)
	}
	return nil, nil, fmt.Errorf("method %q is not built into this binary", name)
}

// extraMethods is filled by later methods (Mobile-ID, Web eID, EUDI, v2).
var extraMethods = map[string]func(*config.Config, *slog.Logger) (authn.Method, func(), error){}

func buildSmartID(cfg *config.Config, log *slog.Logger, a *App) (authn.Method, func(), error) {
	s := cfg.SmartID
	scheme := smartid.SchemeLive
	if cfg.Demo {
		scheme = smartid.SchemeDemo
	}
	var closer func()
	trust, base := s.Trust, s.BaseURL
	httpClient := tlspin.NewClient(tlspin.Options{Pins: s.Pins.Pins, Disabled: s.Pins.Disabled})
	var status smartid.StatusChecker = smartid.NoStatusCheck{Reason: "disabled by configuration (demo only)"}
	if s.Env == "mock" {
		fx := smartidtest.NewServer()
		fx.AutoResolve = envOr("EIDBRIDGE_MOCK_DOCUMENT", "PNOEE-40404040009-MOCK-Q")
		fx.MaxWait = 2 * time.Second
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		hs := &httptest.Server{Listener: ln, Config: &http.Server{Handler: fx, ReadHeaderTimeout: 5 * time.Second}}
		hs.Start()
		closer = hs.Close
		trust, base, httpClient = smartid.NewTrustStore(fx.PKI.Root, fx.PKI.Inter), hs.URL+"/smart-id-rp", hs.Client()
		a.Fixture = fx
	} else if s.CertStatus == "ocsp" {
		hosts := map[string]bool{}
		for _, h := range s.StatusHosts {
			hosts[h] = true
		}
		status = &revocation.Checker{AllowedHosts: hosts, CRLFallback: true, Revoked: smartid.ErrRevoked,
			HTTP: tlspin.NewClient(tlspin.Options{Disabled: true, Timeout: 5 * time.Second})}
	}
	var oids []asn1.ObjectIdentifier
	for _, o := range s.PolicyOIDs {
		oid, err := parseOID(o)
		if err != nil {
			return nil, nil, err
		}
		oids = append(oids, oid)
	}
	if s.Env == "mock" {
		oids = smartid.DemoPolicyOIDs
	}
	c, err := smartid.NewClient(smartid.Config{BaseURL: base, RPUUID: s.RPUUID, RPName: s.RPName, SchemeName: scheme, HTTP: httpClient,
		Trust: trust, MinCertLevel: s.CertLevel, PolicyOIDs: oids, Status: status})
	if err != nil {
		return nil, closer, err
	}
	texts := map[string]string{"en": s.DisplayText}
	m, err := smartid.NewMethod(smartid.MethodConfig{Client: c, Flows: s.Flows, DisplayText: texts, IsDemo: cfg.Demo})
	return m, closer, err
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	return oid, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func serve(getenv config.Getenv, demo bool, root string, stderr io.Writer) int {
	disableCoreDumps()
	cfg, err := config.Load(getenv, demo, root)
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge: startup refused:", err)
		return 1
	}
	log := newLogger(stderr, cfg.LogDebug)
	log.Info("starting", "version", version.String(), "mode", cfg.Mode, "issuer", cfg.Issuer, "methods", strings.Join(cfg.Methods, ","))
	if cfg.LogDebug {
		log.Warn("DEBUG logging enabled; redaction still applies at every level")
	}
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	for _, d := range cfg.Deviations {
		log.Warn("deviation", "record", d)
	}
	a, err := Build(cfg, log, clock.Real())
	if err != nil {
		fmt.Fprintln(stderr, "eidbridge: startup refused:", err)
		return 1
	}
	defer a.Close()
	srv := &http.Server{Addr: cfg.Listen, Handler: a.Handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	if cfg.Demo {
		go demoNag(log, stop)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "eidbridge:", err)
			return 1
		}
	case <-stop:
		log.Info("SIGTERM: draining", "grace_seconds", int(cfg.Grace/time.Second))
		a.Web.DrainAndWait(cfg.Grace, a.Codes.LiveCodeDeadline)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		log.Info("stopped")
	}
	return 0
}

func demoNag(log *slog.Logger, stop chan os.Signal) {
	msg := "DEMO ENVIRONMENT - identities are not real; do not use for production users"
	log.Warn(msg)
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		log.Warn(msg)
	}
}
