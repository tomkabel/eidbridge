package doctor

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPR31DiagnosticRedaction(t *testing.T) {
	srv := httptest.NewServer(nil)
	srv.Close()
	for _, raw := range []string{
		srv.URL + "/private-path?api_key=private-query#private-fragment",
		strings.Replace(srv.URL, "://", "://private-user:private-password@", 1),
		"https://bad host/path?secret=private-query",
	} {
		r := Run(context.Background(), []Target{{Component: "smartid", BaseURL: raw}}, nil, time.Now())[0]
		b, err := json.Marshal(r)
		if err != nil || r.Status != "FAIL" || r.Detail == "" {
			t.Fatalf("expected actionable failure, got %+v", r)
		}
		if strings.Contains(string(b), "private-") {
			t.Errorf("diagnostic includes a sensitive URL component")
		}
	}
}
