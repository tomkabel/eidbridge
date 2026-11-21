package smartid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPR31MockDestination(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	m := MockDeviceLink{DocumentNumber: "fixture", DeviceLink: "https://example.invalid"}
	if err := MockSubmit(ctx, srv.URL+"/mock", m, nil); err != nil {
		t.Fatalf("loopback request failed: %v", err)
	}
	before := hits.Load()
	for _, base := range []string{
		strings.Replace(srv.URL, "://", "://127.0.0.1@", 1),
		"http://127.0.0.1.example.invalid",
		srv.URL + "/mock?ignored=1",
		srv.URL + "/mock#fragment",
	} {
		err := MockSubmit(ctx, base, m, nil)
		if err == nil || !strings.Contains(err.Error(), "demo-only") {
			t.Errorf("invalid base reached HTTP handling: %v", err)
		}
	}
	if hits.Load() != before {
		t.Error("invalid destination generated a network request")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := MockSubmit(ctx, redirect.URL, m, nil); err == nil || hits.Load() != before {
		t.Error("MockSubmit followed or accepted a redirect")
	}
	if _, err := MockCallbackURL(ctx, redirect.URL, "fixture", nil); err == nil || hits.Load() != before {
		t.Error("MockCallbackURL followed or accepted a redirect")
	}
}
