//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	kcPort   = 18081
	kcOrigin = "http://localhost:18081"
	kcRealm  = "eid"
	// The test application the IdP's "log in with eidbridge" flow ends at. The
	// browser driver stops at the redirect, so nothing has to listen here.
	kcAppRedirect = "http://localhost:18083/cb"
)

// Keycloak majors tested: the two latest majors on quay.io on 2026-11-20.
var keycloakImages = []struct{ name, ref string }{
	{"26.8.2", "quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3"},
	{"25.0.6", "quay.io/keycloak/keycloak:25.0.6@sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2"},
}

func TestKeycloak(t *testing.T) {
	requireDocker(t)
	for _, img := range keycloakImages {
		t.Run(img.name, func(t *testing.T) { testKeycloak(t, img.ref) })
	}
}

type kcUser struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Attributes map[string][]string `json:"attributes"`
}

func testKeycloak(t *testing.T, image string) {
	portFree(t, kcPort)
	broker := kcOrigin + "/realms/" + kcRealm + "/broker/eidbridge/endpoint"
	bc := startBridge(t, "keycloak", "client_secret_basic", broker)
	pull(t, image)
	adminPass := randHex(12)
	runContainer(t, "keycloak", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD="+adminPass,
		"-e", "KEYCLOAK_ADMIN=admin", "-e", "KEYCLOAK_ADMIN_PASSWORD="+adminPass, image,
		"start-dev", "--http-port=18081", "--http-host=127.0.0.1")
	waitHTTP(t, kcOrigin+"/realms/master", 200, 240*time.Second)

	// Admin token.
	resp, body := newBrowser(t).do(http.MethodPost, kcOrigin+"/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {adminPass}})
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal([]byte(body), &tok)
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatalf("admin token: HTTP %d: %s", resp.StatusCode, body)
	}
	api := &jsonAPI{t: t, base: kcOrigin + "/admin/realms", auth: "Bearer " + tok.AccessToken}

	// Realm. The bridge supplies no e-mail, so the user profile must not require
	// one; the stable `sub` and `acr` are stored as managed attributes.
	api.Must("POST", "", map[string]any{"realm": kcRealm, "enabled": true, "sslRequired": "none"}, nil)
	var profile map[string]any
	api.Must("GET", "/"+kcRealm+"/users/profile", nil, &profile)
	attrs, _ := profile["attributes"].([]any)
	for _, a := range attrs {
		m := a.(map[string]any)
		switch m["name"] {
		case "email", "firstName", "lastName":
			delete(m, "required")
		}
	}
	for _, n := range []string{"eid_sub", "eid_acr"} {
		attrs = append(attrs, map[string]any{"name": n, "displayName": n,
			"permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}})
	}
	profile["attributes"] = attrs
	api.Must("PUT", "/"+kcRealm+"/users/profile", profile, nil)

	// First-broker-login flow without any form: create the user if unique.
	api.Must("POST", "/"+kcRealm+"/authentication/flows", map[string]any{
		"alias": "eid first login", "providerId": "basic-flow", "topLevel": true, "builtIn": false}, nil)
	api.Must("POST", "/"+kcRealm+"/authentication/flows/eid%20first%20login/executions/execution",
		map[string]any{"provider": "idp-create-user-if-unique"}, nil)
	var execs []map[string]any
	api.Must("GET", "/"+kcRealm+"/authentication/flows/eid%20first%20login/executions", nil, &execs)
	for _, e := range execs {
		e["requirement"] = "REQUIRED"
		api.Must("PUT", "/"+kcRealm+"/authentication/flows/eid%20first%20login/executions", e, nil)
	}

	// Test application (confidential client).
	appSecret := randHex(16)
	api.Must("POST", "/"+kcRealm+"/clients", map[string]any{"clientId": "testapp", "secret": appSecret, "enabled": true,
		"publicClient": false, "standardFlowEnabled": true, "redirectUris": []string{kcAppRedirect}}, nil)

	// Identity provider: discovery import, then the settings the bridge requires.
	var cfg map[string]string
	api.Must("POST", "/"+kcRealm+"/identity-provider/import-config", map[string]any{
		"fromUrl": bridgeIssuer + "/.well-known/openid-configuration", "providerId": "oidc"}, &cfg)
	for k, v := range map[string]string{
		"clientId": bc.ID, "clientSecret": bc.Secret, "clientAuthMethod": "client_secret_basic",
		"pkceEnabled": "true", "pkceMethod": "S256", "defaultScope": "openid profile",
		"validateSignature": "true", "useJwksUrl": "true", "syncMode": "IMPORT",
	} {
		cfg[k] = v
	}
	if cfg["issuer"] != bridgeIssuer {
		t.Fatalf("discovery issuer = %q, want %q", cfg["issuer"], bridgeIssuer)
	}
	idp := map[string]any{"alias": "eidbridge", "displayName": "eidbridge", "providerId": "oidc", "enabled": true,
		"trustEmail": false, "storeToken": false, "linkOnly": false,
		"firstBrokerLoginFlowAlias": "eid first login", "config": cfg}
	api.Must("POST", "/"+kcRealm+"/identity-provider/instances", idp, nil)
	for _, m := range []struct{ name, claim, attr string }{{"eid-sub", "sub", "eid_sub"}, {"eid-acr", "acr", "eid_acr"}} {
		api.Must("POST", "/"+kcRealm+"/identity-provider/instances/eidbridge/mappers", map[string]any{
			"name": m.name, "identityProviderAlias": "eidbridge", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
			"config": map[string]string{"claim": m.claim, "user.attribute": m.attr, "syncMode": "INHERIT"}}, nil)
	}

	listUsers := func() []kcUser {
		var us []kcUser
		api.Must("GET", "/"+kcRealm+"/users?max=50", nil, &us)
		return us
	}
	authURL := func() string {
		return kcOrigin + "/realms/" + kcRealm + "/protocol/openid-connect/auth?" + url.Values{
			"client_id": {"testapp"}, "redirect_uri": {kcAppRedirect}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s-" + randHex(6)}, "kc_idp_hint": {"eidbridge"}}.Encode()
	}

	// 1. Full login through "log in with eidbridge".
	final := newBrowser(t).Follow(authURL(), kcAppRedirect, nil)
	code := final.Query().Get("code")
	if code == "" {
		t.Fatalf("login did not end with a code: %s", final)
	}
	us := listUsers()
	if len(us) != 1 {
		t.Fatalf("want exactly 1 broker-created user, got %d: %+v", len(us), us)
	}
	u := us[0]
	var fed []struct{ IdentityProvider, UserID, UserName string }
	api.Must("GET", "/"+kcRealm+"/users/"+u.ID+"/federated-identity", nil, &fed)
	if len(fed) != 1 || fed[0].IdentityProvider != "eidbridge" || fed[0].UserID == "" {
		t.Fatalf("federated identity: %+v", fed)
	}
	sub := fed[0].UserID
	if got := u.Attributes["eid_sub"]; len(got) != 1 || got[0] != sub {
		t.Fatalf("eid_sub attribute %v != federated userId %q", got, sub)
	}
	if got := u.Attributes["eid_acr"]; len(got) != 1 || got[0] != "demo" {
		t.Fatalf("eid_acr attribute = %v, want [demo]", got)
	}
	if len(sub) < 16 || strings.ContainsAny(sub, " @") {
		t.Fatalf("bridge sub %q does not look like an opaque pairwise id", sub)
	}
	t.Logf("user %s federated with eidbridge sub %s", u.ID, sub)

	// The code is good: the user is logged in at Keycloak (ID token for that user).
	resp, body = newBrowser(t).do(http.MethodPost, kcOrigin+"/realms/"+kcRealm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {kcAppRedirect},
		"client_id": {"testapp"}, "client_secret": {appSecret}})
	var tr struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal([]byte(body), &tr)
	if resp.StatusCode != 200 || tr.IDToken == "" {
		t.Fatalf("code exchange: HTTP %d: %s", resp.StatusCode, body)
	}
	parts := strings.Split(tr.IDToken, ".")
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(cb, &claims)
	if claims["sub"] != u.ID || claims["iss"] != kcOrigin+"/realms/"+kcRealm {
		t.Fatalf("Keycloak ID token claims %v, want sub=%s", claims, u.ID)
	}

	// 2. A second, fresh browser session logs in as the same user (stable sub).
	newBrowser(t).Follow(authURL(), kcAppRedirect, nil)
	if us2 := listUsers(); len(us2) != 1 || us2[0].ID != u.ID {
		t.Fatalf("second login created/changed users: %+v", us2)
	}

	// 3. Rejecting demo logins: claim filter on acr (documented in docs/idp/keycloak.md).
	api.Must("DELETE", "/"+kcRealm+"/users/"+u.ID, nil, nil)
	cfg["filteredByClaim"], cfg["claimFilterName"], cfg["claimFilterValue"] = "true", "acr", "^(?!demo$).*"
	api.Must("PUT", "/"+kcRealm+"/identity-provider/instances/eidbridge", idp, nil)
	br := newBrowser(t)
	cb2 := br.Follow(authURL(), kcOrigin+"/realms/"+kcRealm+"/broker/eidbridge/endpoint?", nil)
	resp, page := br.do(http.MethodGet, cb2.String(), nil)
	if resp.StatusCode < 400 || !strings.Contains(page, "essential claim") {
		t.Fatalf("demo login was not refused: HTTP %d: %.300s", resp.StatusCode, stripTags(page))
	}
	t.Logf("demo login refused: HTTP %d: %.120s", resp.StatusCode, stripTags(page))
	if us3 := listUsers(); len(us3) != 0 {
		t.Fatalf("refused demo login still created users: %+v", us3)
	}
}
