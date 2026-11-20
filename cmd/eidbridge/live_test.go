package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/smartid"
)

// TestLiveDemoBridgeLogin runs the whole bridge against sid.demo.sk.ee and
// SK's automated testing interface (EIDBRIDGE_LIVE=1). Certificate status is
// off because SK's demo OCSP reports mock-account certificates as non-issued
// (ADR 0001).
func TestLiveDemoBridgeLogin(t *testing.T) {
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1")
	}
	s := newStack(t, map[string]string{"EIDBRIDGE_SMARTID_ENV": "demo", "EIDBRIDGE_SMARTID_CERT_STATUS": "none"})
	q := url.Values{"client_id": {"demo-rp"}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"}, "scope": {"openid profile"},
		"state": {"live"}, "nonce": {"live"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	resp, err := s.b.Get(s.issuer + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := body(resp)
	id := strings.TrimPrefix(resp.Request.URL.Path, strings.TrimPrefix(s.issuer, s.srv.URL)+"/flow/")
	ft := ftRe.FindStringSubmatch(page)[1]
	r, _ := s.b.PostForm(s.issuer+"/flow/"+id+"/start", url.Values{"ft": {ft}, "method": {"smartid"}, "flow": {"qr"}})
	qrPage := body(r)
	if !strings.Contains(qrPage, "qr.png") {
		t.Fatalf("no QR on the page: %.300s", qrPage)
	}
	img, _ := s.b.Get(s.issuer + "/flow/" + id + "/qr.png")
	if img.Header.Get("Content-Type") != "image/png" {
		t.Fatal("QR image")
	}
	img.Body.Close()
	ui, ok := s.app.Web.PendingUI(id)
	if !ok {
		t.Fatal("no pending UI")
	}
	if err := smartid.MockSubmitDeviceLink(context.Background(), "https://sid.demo.sk.ee/mock", "PNOEE-40404040009-MOCK-Q", ui.QRPayload, nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := s.b.Get(s.issuer + "/flow/" + id + "/status")
		var st struct{ State, Next string }
		json.NewDecoder(r.Body).Decode(&st)
		r.Body.Close()
		if st.Next != "" {
			if st.State != "verified" {
				t.Fatalf("live flow ended %s", st.State)
			}
			r, _ := s.nr.Get(s.srv.URL + st.Next)
			r.Body.Close()
			u, _ := url.Parse(r.Header.Get("Location"))
			tok := s.token(u.Query().Get("code"))
			if tok["id_token"] == nil {
				t.Fatalf("token: %v", tok)
			}
			req, _ := http.NewRequest(http.MethodGet, s.issuer+"/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
			ur, _ := s.nr.Do(req)
			var ui map[string]any
			json.NewDecoder(ur.Body).Decode(&ui)
			ur.Body.Close()
			if ui["eid_env"] != "demo" || ui["country"] != "EE" {
				t.Fatalf("userinfo %v", ui)
			}
			t.Logf("live demo OIDC round-trip verified: state=%s acr=demo", st.State)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("live login did not finish")
}

// TestLiveDemoBridgeMobileID runs a full bridge login with Mobile-ID
// against tsp.demo.sk.ee (EIDBRIDGE_LIVE=1), through the login page's
// notification form. Status checking is off for the same demo OCSP reason.
func TestLiveDemoBridgeMobileID(t *testing.T) {
	if os.Getenv("EIDBRIDGE_LIVE") != "1" {
		t.Skip("set EIDBRIDGE_LIVE=1")
	}
	s := newStack(t, map[string]string{"EIDBRIDGE_METHODS": "smartid,mobileid", "EIDBRIDGE_MOBILEID_ENV": "demo", "EIDBRIDGE_MOBILEID_CERT_STATUS": "none"})
	u := s.login("notification", url.Values{"method": {"mobileid"}, "country": {"EE"}, "personal_code": {"51307149560"}, "phone": {"+37269930366"}})
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("live Mobile-ID redirect %s", u)
	}
	tok := s.token(code)
	if tok["id_token"] == nil {
		t.Fatalf("token %v", tok)
	}
	t.Logf("live Mobile-ID login through the bridge: code exchanged, ID token issued")
}
