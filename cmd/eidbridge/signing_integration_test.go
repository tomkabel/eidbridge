package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSigningRelayThroughBridge runs the signing API over the real wiring
// with the fixture upstream (Story 8.1-a/b).
func TestSigningRelayThroughBridge(t *testing.T) {
	dir := t.TempDir()
	clients := `[{"client_id":"signer","client_secret":"` + testSecret + `","token_endpoint_auth_method":"client_secret_basic",
		"redirect_uris":["https://rp.example/cb"],"sub_mode":"pairwise","signing_allowed":true},
		{"client_id":"login-only","client_secret":"` + testSecret + `","token_endpoint_auth_method":"client_secret_basic",
		"redirect_uris":["https://rp2.example/cb"],"sub_mode":"pairwise","sector_id":"rp2.example"}]`
	f := filepath.Join(dir, "clients.json")
	os.WriteFile(f, []byte(clients), 0o600)
	s := newStack(t, map[string]string{"EIDBRIDGE_SIGNING_ENABLED": "true", "EIDBRIDGE_CLIENTS_FILE": f})
	do := func(method, path, user string, in any) (int, map[string]any) {
		b, _ := json.Marshal(in)
		req, _ := http.NewRequest(method, s.srv.URL+path, bytes.NewReader(b))
		if user != "" {
			req.SetBasicAuth(user, testSecret)
		}
		resp, err := s.nr.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		return resp.StatusCode, out
	}
	waitJob := func(id string) map[string]any {
		for i := 0; i < 200; i++ {
			_, out := do("GET", "/api/v1/sign/"+id, "signer", nil)
			if out["status"] != "pending" {
				return out
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("timeout")
		return nil
	}
	if code, _ := do("POST", "/api/v1/sign/certificate", "", map[string]string{"signer": "PNOEE-40404040009"}); code != 401 {
		t.Fatalf("unauthenticated: %d", code)
	}
	if code, _ := do("POST", "/api/v1/sign/certificate", "login-only", map[string]string{"signer": "PNOEE-40404040009"}); code != 401 {
		t.Fatalf("client without signing_allowed: %d", code)
	}
	code, out := do("POST", "/api/v1/sign/certificate", "signer", map[string]string{"signer": "PNOEE-40404040009"})
	if code != 202 {
		t.Fatalf("certificate: %d %v", code, out)
	}
	certID := out["id"].(string)
	if res := waitJob(certID); res["status"] != "complete" {
		t.Fatalf("certificate job %v", res)
	}
	d := sha256.Sum256([]byte("synthetic document"))
	code, out = do("POST", "/api/v1/sign", "signer", map[string]string{"certificate": certID, "digest": base64.StdEncoding.EncodeToString(d[:]),
		"hash_algorithm": "SHA-256", "signature_algorithm": "rsassa-pss", "display_text": "Sign the synthetic document"})
	if code != 202 {
		t.Fatalf("sign: %d %v", code, out)
	}
	res := waitJob(out["id"].(string))
	if res["status"] != "complete" || res["signature"] == nil {
		t.Fatalf("signature job %v", res)
	}
	if strings.Contains(s.logs.String(), "40404040009") {
		t.Fatal("signer identity in DEBUG logs")
	}
}
