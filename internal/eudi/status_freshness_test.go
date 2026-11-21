package eudi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStatusTimeClaims(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		claims map[string]any
		valid  bool
	}{
		{"fresh", map[string]any{"iat": json.Number("1795262340"), "exp": json.Number("1795269660")}, true},
		{"missing iat", map[string]any{"exp": json.Number("1795269660")}, false},
		{"missing exp", map[string]any{"iat": json.Number("1795262340")}, false},
		{"string exp", map[string]any{"iat": json.Number("1795262340"), "exp": "1795269660"}, false},
		{"expired at boundary", map[string]any{"iat": json.Number("1795262340"), "exp": json.Number("1795262400")}, false},
		{"exp before issuance", map[string]any{"iat": json.Number("1795262460"), "exp": json.Number("1795262400")}, false},
		{"future within skew", map[string]any{"iat": json.Number("1795262460"), "exp": json.Number("1795269660")}, true},
		{"future beyond skew", map[string]any{"iat": json.Number("1795262461"), "exp": json.Number("1795269660")}, false},
		{"at replay cap", map[string]any{"iat": json.Number("1795176000"), "exp": json.Number("1795269660")}, true},
		{"past replay cap", map[string]any{"iat": json.Number("1795175999"), "exp": json.Number("1795269660")}, false},
		{"ttl before issuance window ends", map[string]any{"iat": json.Number("1795262220"), "exp": json.Number("1795269660"), "ttl": json.Number("300")}, true},
		{"ttl stale from issuance", map[string]any{"iat": json.Number("1795262220"), "exp": json.Number("1795269660"), "ttl": json.Number("120")}, false},
		{"zero ttl", map[string]any{"iat": json.Number("1795262340"), "exp": json.Number("1795269660"), "ttl": json.Number("0")}, false},
		{"malformed ttl", map[string]any{"iat": json.Number("1795262340"), "exp": json.Number("1795269660"), "ttl": "60"}, false},
		{"future nbf beyond skew", map[string]any{"iat": json.Number("1795262340"), "exp": json.Number("1795269660"), "nbf": json.Number("1795262461")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := statusTimeClaims(tt.claims, now)
			if (err == nil) != tt.valid {
				t.Fatalf("statusTimeClaims() error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}
