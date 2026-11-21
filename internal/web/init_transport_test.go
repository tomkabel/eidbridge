package web

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// TestSessionInitTransportBounds (epics 2.5 RV): redirected, oversized,
// failed and timed-out device-link and notification inits fail the flow,
// release its reservation and poll slot, and are not retried.
func TestSessionInitTransportBounds(t *testing.T) {
	var cancelled atomic.Bool
	cancelled.Store(true)
	hooks := map[string]func(http.ResponseWriter, *http.Request) bool{
		"redirect": func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Location", "https://elsewhere.example/v3/authentication/device-link/anonymous")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return true
		},
		"oversized": func(w http.ResponseWriter, r *http.Request) bool {
			w.Write([]byte(`{"sessionID":"` + strings.Repeat("a", 70<<10) + `"}`))
			return true
		},
		"uncertain 500": func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		},
		"timeout": func(w http.ResponseWriter, r *http.Request) bool {
			io.Copy(io.Discard, r.Body) // lets the server notice the client hanging up
			select {                    // never answers; the bridge's start deadline must cancel it
			case <-r.Context().Done():
			case <-time.After(45 * time.Second):
				cancelled.Store(false)
			}
			return true
		},
	}
	t.Cleanup(func() {
		if !cancelled.Load() {
			t.Error("a timed-out init request was not cancelled upstream")
		}
	})
	for name, hook := range hooks {
		for _, fl := range []string{authn.FlowQR, authn.FlowNotification} {
			t.Run(name+"/"+fl, func(t *testing.T) {
				t.Parallel()
				e := newWeb(t, wopt{})
				e.up.CreateHook = hook
				b := e.browser()
				id, page, _ := b.begin(nil)
				var extra map[string][]string
				if fl == authn.FlowNotification {
					extra = map[string][]string{"country": {"EE"}, "personal_code": {"40404040009"}}
				}
				start := time.Now()
				resp := b.start(id, page, "smartid", fl, extra)
				resp.Body.Close()
				if st := e.waitState(id, StateFailed, StateExpired); st != StateFailed {
					t.Fatalf("state %s", st)
				}
				if n := e.up.Creates.Load(); n != 1 {
					t.Fatalf("%d init attempts (no blind retry allowed)", n)
				}
				if r, _, _ := e.codes.Counts(); r != 0 {
					t.Fatalf("%d code reservations held after a failed init", r)
				}
				if e.web.slots != nil && len(e.web.slots) != 0 {
					t.Fatalf("%d poll slots held", len(e.web.slots))
				}
				t.Logf("%s/%s: failed after %v", name, fl, time.Since(start))
				if name != "timeout" && time.Since(start) > 5*time.Second {
					t.Fatalf("%s took %v", name, time.Since(start))
				}
			})
		}
	}
}
