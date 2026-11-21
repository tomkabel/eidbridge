package web

import (
	"log/slog"
	"net/http"
	"time"
)

// AccessLog logs method, matched route template, status and duration only:
// never raw paths, queries, flow IDs or client IPs (ADR-002 logging rule).
func AccessLog(log *slog.Logger, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		_, pattern := mux.Handler(r)
		mux.ServeHTTP(sw, r)
		if pattern == "" {
			pattern = "unmatched"
		}
		log.Info("http", "route", pattern, "status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// DrainAndWait performs the SIGTERM drain: readiness fails, new
// authorizations, QR page loads, polling and callbacks stop, and it returns
// once every issued code has expired (liveCodeDeadline is the latest
// monotonic code deadline) or grace passes. Token and userinfo keep serving
// meanwhile.
func (s *Server) DrainAndWait(grace time.Duration, liveCodeDeadline func() time.Duration) {
	s.Drain()
	end := s.cfg.Clock.Mono() + grace
	for {
		now := s.cfg.Clock.Mono()
		if now >= end || now >= liveCodeDeadline() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
