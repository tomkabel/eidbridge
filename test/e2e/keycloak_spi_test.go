//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Keycloak ports for the SPI test: 18300-18399 only (one per tested image).
const kcSPIPortBase = 18300

var (
	kcSPIJarOnce sync.Once
	kcSPIJar     string
	kcSPIJarErr  error
)

// buildKeycloakSPI builds integrations/keycloak with Maven once and returns a
// world-readable copy of the jar (the Keycloak container runs as another uid).
func buildKeycloakSPI(t *testing.T) string {
	t.Helper()
	kcSPIJarOnce.Do(func() {
		pom := filepath.Join(repoRoot(), "integrations", "keycloak", "pom.xml")
		out, err := exec.Command("mvn", "-q", "-B", "-f", pom, "-DskipTests", "package").CombinedOutput()
		if err != nil {
			kcSPIJarErr = fmt.Errorf("mvn package: %v\n%s", err, tail(string(out), 4000))
			return
		}
		data, err := os.ReadFile(filepath.Join(repoRoot(), "integrations", "keycloak", "target", "eidbridge-keycloak.jar"))
		if err != nil {
			kcSPIJarErr = err
			return
		}
		dir, err := os.MkdirTemp("", "eidbridge-e2e-spi")
		if err != nil {
			kcSPIJarErr = err
			return
		}
		os.Chmod(dir, 0o755)
		kcSPIJar = filepath.Join(dir, "eidbridge-keycloak.jar")
		kcSPIJarErr = os.WriteFile(kcSPIJar, data, 0o644)
	})
	if kcSPIJarErr != nil {
		t.Fatal(kcSPIJarErr)
	}
	return kcSPIJar
}

func TestKeycloakSPI(t *testing.T) {
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("mvn binary not found in PATH, cannot build integrations/keycloak: " + err.Error())
	}
	requireDocker(t)
	jar := buildKeycloakSPI(t)
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(jar)) })
	for i, img := range keycloakImages {
		t.Run(img.name, func(t *testing.T) { testKeycloakSPI(t, img.ref, jar, kcSPIPortBase+i) })
	}
}

func testKeycloakSPI(t *testing.T, image, jar string, port int) {
	origin := fmt.Sprintf("http://localhost:%d", port)
	issuer := origin + "/realms/" + kcRealm
	portFree(t, port)
	broker := issuer + "/broker/eidbridge/endpoint"
	bc := startBridge(t, "keycloak", "client_secret_basic", broker)
	pull(t, image)
	adminPass := randHex(12)
	name := fmt.Sprintf("keycloak-spi-%d", port)
	runContainer(t, name, "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD="+adminPass,
		"-e", "KEYCLOAK_ADMIN=admin", "-e", "KEYCLOAK_ADMIN_PASSWORD="+adminPass,
		"-v", jar+":/opt/keycloak/providers/eidbridge-keycloak.jar:ro", image,
		"start-dev", fmt.Sprintf("--http-port=%d", port), "--http-host=127.0.0.1")
	waitHTTP(t, origin+"/realms/master", 200, 300*time.Second)

	resp, body := newBrowser(t).do(http.MethodPost, origin+"/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {adminPass}})
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal([]byte(body), &tok)
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatalf("admin token: HTTP %d: %s", resp.StatusCode, body)
	}
	auth := "Bearer " + tok.AccessToken
	api := &jsonAPI{t: t, base: origin + "/admin/realms", auth: auth}

	// 1. The provider type is registered.
	root := &jsonAPI{t: t, base: origin + "/admin", auth: auth}
	var info struct {
		IdentityProviders []struct{ ID, Name string } `json:"identityProviders"`
	}
	root.Must("GET", "/serverinfo", nil, &info)
	found := false
	var ids []string
	for _, p := range info.IdentityProviders {
		ids = append(ids, p.ID)
		found = found || p.ID == "eidbridge"
	}
	if !found {
		t.Fatalf("serverinfo identityProviders %v does not contain eidbridge", ids)
	}
	t.Logf("serverinfo identityProviders contains eidbridge (of %d types)", len(ids))

	// Realm, user profile and first-login flow: same shape as docs/idp/keycloak.md.
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
	for _, n := range []string{"eid_sub", "eid_acr", "eid_method", "eid_country"} {
		attrs = append(attrs, map[string]any{"name": n, "displayName": n,
			"permissions": map[string]any{"view": []string{"admin"}, "edit": []string{"admin"}}})
	}
	profile["attributes"] = attrs
	api.Must("PUT", "/"+kcRealm+"/users/profile", profile, nil)

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
	appSecret := randHex(16)
	api.Must("POST", "/"+kcRealm+"/clients", map[string]any{"clientId": "testapp", "secret": appSecret, "enabled": true,
		"publicClient": false, "standardFlowEnabled": true, "redirectUris": []string{kcAppRedirect}}, nil)

	// 2. Create the eidbridge-type identity provider with only issuer, client id and
	// secret (plus allowDemo, which this demo-fixture bridge requires).
	idp := map[string]any{"alias": "eidbridge", "displayName": "eidbridge", "providerId": "eidbridge", "enabled": true,
		"firstBrokerLoginFlowAlias": "eid first login",
		"config":                    map[string]string{"issuer": bridgeIssuer, "clientId": bc.ID, "clientSecret": bc.Secret, "allowDemo": "true"}}
	api.Must("POST", "/"+kcRealm+"/identity-provider/instances", idp, nil)
	// The mapper reads the sub claim from the ID token, independently of the
	// brokered user id, so comparing it to the federated userId is a real check.
	api.Must("POST", "/"+kcRealm+"/identity-provider/instances/eidbridge/mappers", map[string]any{
		"name": "eid-sub", "identityProviderAlias": "eidbridge", "identityProviderMapper": "oidc-user-attribute-idp-mapper",
		"config": map[string]string{"claim": "sub", "user.attribute": "eid_sub", "syncMode": "INHERIT"}}, nil)

	listUsers := func() []kcUser {
		var us []kcUser
		api.Must("GET", "/"+kcRealm+"/users?max=50", nil, &us)
		return us
	}
	authURL := func() string {
		return origin + "/realms/" + kcRealm + "/protocol/openid-connect/auth?" + url.Values{
			"client_id": {"testapp"}, "redirect_uri": {kcAppRedirect}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s-" + randHex(6)}, "kc_idp_hint": {"eidbridge"}}.Encode()
	}

	// 2a. allowDemo=true: full login. First check what Keycloak sends to the bridge.
	br := newBrowser(t)
	bridgeAuth := kcSPIFirstBridgeURL(t, br, authURL())
	q := bridgeAuth.Query()
	if q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" ||
		q.Get("state") == "" || q.Get("response_type") != "code" || !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Fatalf("authorization request to the bridge lacks nonce/PKCE S256/state/openid: %s", bridgeAuth)
	}
	t.Logf("authorization request to bridge: path=%s nonce=%d chars code_challenge_method=%s scope=%q",
		bridgeAuth.Path, len(q.Get("nonce")), q.Get("code_challenge_method"), q.Get("scope"))
	final := br.Follow(bridgeAuth.String(), kcAppRedirect, nil)
	if final.Query().Get("code") == "" {
		t.Fatalf("login did not end with a code: %s", final)
	}
	us := listUsers()
	if len(us) != 1 {
		t.Fatalf("allowDemo=true: want exactly 1 broker-created user, got %d: %+v", len(us), us)
	}
	u := us[0]
	var fed []struct{ IdentityProvider, UserID, UserName string }
	api.Must("GET", "/"+kcRealm+"/users/"+u.ID+"/federated-identity", nil, &fed)
	if len(fed) != 1 || fed[0].IdentityProvider != "eidbridge" || fed[0].UserID == "" {
		t.Fatalf("federated identity: %+v", fed)
	}
	sub := fed[0].UserID
	if got := u.Attributes["eid_sub"]; len(got) != 1 || got[0] != sub {
		t.Fatalf("sub claim (mapped to eid_sub) %v != federated userId %q", got, sub)
	}
	if len(sub) < 16 || strings.ContainsAny(sub, " @") {
		t.Fatalf("bridge sub %q does not look like an opaque pairwise id", sub)
	}
	if got := u.Attributes["eid_acr"]; len(got) != 1 || got[0] != "demo" {
		t.Fatalf("eid_acr attribute = %v, want [demo] (set by the provider)", got)
	}
	if got := u.Attributes["eid_method"]; len(got) != 1 || got[0] == "" {
		t.Fatalf("eid_method attribute = %v, want one value (set by the provider)", got)
	}
	t.Logf("allowDemo=true: user %s federated with sub %s; attributes eid_acr=%v eid_method=%v eid_country=%v",
		u.ID, sub, u.Attributes["eid_acr"], u.Attributes["eid_method"], u.Attributes["eid_country"])

	// 3. allowDemo=false: the same login must fail and create nothing.
	api.Must("DELETE", "/"+kcRealm+"/users/"+u.ID, nil, nil)
	var cur map[string]any
	api.Must("GET", "/"+kcRealm+"/identity-provider/instances/eidbridge", nil, &cur)
	cur["config"].(map[string]any)["allowDemo"] = "false"
	api.Must("PUT", "/"+kcRealm+"/identity-provider/instances/eidbridge", cur, nil)
	br = newBrowser(t)
	cb := br.Follow(authURL(), origin+"/realms/"+kcRealm+"/broker/eidbridge/endpoint?", nil)
	resp, page := br.do(http.MethodGet, cb.String(), nil)
	if resp.StatusCode < 400 {
		t.Fatalf("allowDemo=false: demo login was not refused: HTTP %d: %.300s", resp.StatusCode, stripTags(page))
	}
	if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, kcAppRedirect) {
		t.Fatalf("allowDemo=false: login redirected to the app: %s", loc)
	}
	t.Logf("allowDemo=false: demo login refused: HTTP %d: %.120s", resp.StatusCode, stripTags(page))
	if us := listUsers(); len(us) != 0 {
		t.Fatalf("allowDemo=false: refused login still created users: %+v", us)
	}
	logs, _ := exec.Command("docker", "logs", "eidbridge-e2e-"+name).CombinedOutput()
	if !strings.Contains(string(logs), "eidbridge demo ID token refused") {
		t.Fatalf("Keycloak log does not show the SPI's refusal (the login failed for another reason):\n%s", tail(string(logs), 3000))
	}
	t.Log("Keycloak log shows the SPI refusal: eidbridge demo ID token refused (acr is demo)")
}

// kcSPIFirstBridgeURL follows Keycloak redirects until the first one that leaves
// for the bridge and returns that authorization URL (not fetched).
func kcSPIFirstBridgeURL(t *testing.T, b *browser, start string) *url.URL {
	t.Helper()
	cur := start
	for hop := 0; hop < 20; hop++ {
		u, _ := url.Parse(cur)
		if u.Host == "localhost:18080" {
			return u
		}
		resp, body := b.do(http.MethodGet, cur, nil)
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" {
			t.Fatalf("expected a redirect towards the bridge at %s: HTTP %d: %.400s", cur, resp.StatusCode, stripTags(body))
		}
		n, err := u.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		cur = n.String()
	}
	t.Fatalf("no redirect to the bridge from %s", start)
	return nil
}
