package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/eudi/walletsim"
)

var authQ = url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"},
	"scope": {"openid profile"}, "state": {"st123"}, "nonce": {"nonce123"},
	"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}

func (s *stack) startMethod(method, flow string) string {
	s.t.Helper()
	resp, err := s.b.Get(s.issuer + "/authorize?" + authQ.Encode())
	if err != nil {
		s.t.Fatal(err)
	}
	page := body(resp)
	id := strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
	ft := ftRe.FindStringSubmatch(page)[1]
	r, _ := s.b.PostForm(s.issuer+"/flow/"+id+"/start", url.Values{"ft": {ft}, "method": {method}, "flow": {flow}})
	body(r)
	return id
}

func (s *stack) flowState(id string) string {
	r, _ := s.b.Get(s.issuer + "/flow/" + id + "/status")
	var st struct{ State, Next string }
	json.NewDecoder(r.Body).Decode(&st)
	r.Body.Close()
	return st.State + "|" + st.Next
}

// Red-team #2 F3: an EUDI same-device login completes only in the browser
// that started it; a relaying browser gets nothing.
func TestEUDISameDeviceBoundToBrowser(t *testing.T) {
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,eudi", "EIDBRIDGE_EUDI_ENV": "mock"})
	id := s.startMethod("eudi", "same-device")
	ui, ok := s.app.Web.PendingUI(id)
	if !ok || !strings.HasPrefix(ui.AppLink, "openid4vp://") {
		t.Fatalf("no wallet link: %+v", ui)
	}
	wallet := &http.Client{Transport: s.nr.Transport}
	req, err := walletsim.FetchRequest(wallet, ui.AppLink)
	if err != nil {
		t.Fatal(err)
	}
	w := eudiFixture.Issue(walletsim.IssueOptions{})
	resp, err := walletsim.Respond(wallet, req, walletsim.VPToken(w.Present(req.Nonce, req.ClientID, walletsim.PresentOptions{})), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("wallet response: %v", err)
	}
	var out struct {
		RedirectURI string `json:"redirect_uri"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if !strings.HasPrefix(out.RedirectURI, s.issuer+"/flow/"+id+"/wallet-return?response_code=") {
		t.Fatalf("redirect_uri %q", out.RedirectURI)
	}
	time.Sleep(50 * time.Millisecond)
	if st := s.flowState(id); strings.Contains(st, "|/") {
		t.Fatalf("flow completed before the browser returned: %s", st)
	}
	// Another browser (no flow cookie) following the redirect gets nothing.
	r, _ := wallet.Get(out.RedirectURI)
	body(r)
	if st := s.flowState(id); strings.Contains(st, "|/") {
		t.Fatalf("relaying browser completed the flow: %s", st)
	}
	// The login browser completes it.
	r, _ = s.nr.Get(out.RedirectURI)
	r.Body.Close()
	r, _ = s.nr.Get(s.srv.URL + r.Header.Get("Location"))
	r.Body.Close()
	u, _ := url.Parse(r.Header.Get("Location"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("login browser got no code: %v", r.Header.Get("Location"))
	}
}

// Red-team #2 F4: a wallet response posted to a non-wallet flow is refused
// and leaves the flow pending.
func TestWalletResponseCannotEndOtherFlows(t *testing.T) {
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,eudi", "EIDBRIDGE_EUDI_ENV": "mock", "EIDBRIDGE_MOCK_DOCUMENT": "manual"})
	id := s.startMethod("smartid", "qr")
	stranger := &http.Client{Transport: s.nr.Transport}
	r, _ := stranger.PostForm(s.issuer+"/wallet/response/"+id, url.Values{"vp_token": {"x"}, "state": {"y"}})
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("status %d", r.StatusCode)
	}
	if st := s.flowState(id); !strings.HasPrefix(st, "pending") {
		t.Fatalf("flow after stray wallet response: %s", st)
	}
}

// Red-team #2 F7: JSON responses carry nosniff; HSTS when the bridge
// terminates TLS.
func TestBaseHeaders(t *testing.T) {
	s := newStack(t, nil)
	r, _ := s.nr.Get(s.issuer + "/.well-known/openid-configuration")
	r.Body.Close()
	if r.Header.Get("X-Content-Type-Options") != "nosniff" || r.Header.Get("Strict-Transport-Security") != "" {
		t.Fatalf("discovery headers %v", r.Header)
	}
	rec := httptest.NewRecorder()
	baseHeaders(http.NotFoundHandler(), true).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("HSTS missing with own TLS: %v", rec.Header())
	}
}
