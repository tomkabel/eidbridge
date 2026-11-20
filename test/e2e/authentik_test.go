//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	akHTTP   = 18090
	akOrigin = "http://localhost:18090"
	akPGPort = 18432
	akImage  = "ghcr.io/goauthentik/server:2026.8.6@sha256:da89d8338a3b1889800eb033fd61f8d43f7aa9a1c5a042cb5e03d891b1f0c56c"
	pgImage  = "postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32"
)

func TestAuthentik(t *testing.T) {
	requireDocker(t)
	callback := akOrigin + "/source/oauth/callback/eidbridge/"
	bc := startBridge(t, "authentik", "client_secret_basic", callback)
	dbPass, token := randHex(12), "e2e-"+randHex(20)
	portFree(t, akHTTP)
	portFree(t, akPGPort)
	{
		pull(t, akImage)
		pull(t, pgImage)
		runContainer(t, "authentik-pg", "-e", "POSTGRES_USER=authentik", "-e", "POSTGRES_DB=authentik", "-e", "POSTGRES_PASSWORD="+dbPass,
			pgImage, "postgres", "-p", "18432", "-c", "listen_addresses=127.0.0.1")
		env := []string{"-e", "AUTHENTIK_SECRET_KEY=" + randHex(32), "-e", "AUTHENTIK_POSTGRESQL__HOST=127.0.0.1",
			"-e", "AUTHENTIK_POSTGRESQL__PORT=18432", "-e", "AUTHENTIK_POSTGRESQL__USER=authentik",
			"-e", "AUTHENTIK_POSTGRESQL__NAME=authentik", "-e", "AUTHENTIK_POSTGRESQL__PASSWORD=" + dbPass,
			"-e", "AUTHENTIK_BOOTSTRAP_PASSWORD=" + randHex(12), "-e", "AUTHENTIK_BOOTSTRAP_TOKEN=" + token,
			"-e", "AUTHENTIK_DISABLE_UPDATE_CHECK=true", "-e", "AUTHENTIK_ERROR_REPORTING__ENABLED=false"}
		for i := 0; i < 60; i++ { // wait for postgres
			if exec.Command("docker", "exec", "eidbridge-e2e-authentik-pg", "pg_isready", "-h", "127.0.0.1", "-p", "18432").Run() == nil {
				break
			}
			time.Sleep(time.Second)
		}
		runContainer(t, "authentik-server", append(append([]string{
			"-e", "AUTHENTIK_LISTEN__HTTP=127.0.0.1:18090", "-e", "AUTHENTIK_LISTEN__HTTPS=127.0.0.1:18091",
			"-e", "AUTHENTIK_LISTEN__METRICS=127.0.0.1:18092", "-e", "AUTHENTIK_LISTEN__DEBUG=127.0.0.1:18093"}, env...), akImage, "server")...)
		// The worker applies the blueprints that create the default flows.
		runContainer(t, "authentik-worker", append(append([]string{
			"-e", "AUTHENTIK_LISTEN__HTTP=127.0.0.1:18094", "-e", "AUTHENTIK_LISTEN__HTTPS=127.0.0.1:18095",
			"-e", "AUTHENTIK_LISTEN__METRICS=127.0.0.1:18096", "-e", "AUTHENTIK_LISTEN__DEBUG=127.0.0.1:18097"}, env...), akImage, "worker")...)

	}
	api := &jsonAPI{t: t, base: akOrigin + "/api/v3", auth: "Bearer " + token}
	// Wait for migrations, bootstrap token and the default-source-enrollment blueprint.
	deadline := time.Now().Add(6 * time.Minute)
	for {
		var fl struct{ Results []struct{ Slug, Pk string } }
		quiet := &jsonAPI{t: t, base: api.base, auth: api.auth}
		if st := quiet.doQuiet("GET", "/flows/instances/?page_size=100", &fl); st == 200 {
			have := map[string]bool{}
			for _, f := range fl.Results {
				have[f.Slug] = true
			}
			if have["default-source-enrollment"] && have["default-source-authentication"] {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("authentik did not become ready (default-source-enrollment flow missing) within 6 minutes")
		}
		time.Sleep(5 * time.Second)
	}
	flowPK := func(slug string) string {
		var fl struct{ Results []struct{ Slug, Pk string } }
		api.Must("GET", "/flows/instances/?slug="+slug, nil, &fl)
		if len(fl.Results) != 1 {
			t.Fatalf("flow %s not found", slug)
		}
		return fl.Results[0].Pk
	}

	// The bridge sends no preferred_username/e-mail, so the user name is the stable
	// `sub`. The mapping may also refuse demo logins (eid_env=demo).
	mapping := func(guard bool) string {
		g := ""
		if guard {
			g = "if info.get(\"eid_env\") == \"demo\" or info.get(\"acr\") == \"demo\":\n    raise Exception(\"demo eID logins are not accepted\")\n"
		}
		return g + "return {\"username\": info[\"sub\"], \"name\": info.get(\"name\") or info[\"sub\"]}\n"
	}
	var pm struct{ Pk string }
	api.Must("POST", "/propertymappings/source/oauth/", map[string]any{"name": "eidbridge user", "expression": mapping(false)}, &pm)

	// Enrollment flow without any prompt: write the user, log them in.
	var fl, uw, ul struct{ Pk string }
	api.Must("POST", "/flows/instances/", map[string]any{"name": "eidbridge enrollment", "title": "eidbridge", "slug": "eidbridge-enrollment",
		"designation": "enrollment", "authentication": "none"}, &fl)
	api.Must("POST", "/stages/user_write/", map[string]any{"name": "eidbridge user write", "user_creation_mode": "always_create",
		"user_path_template": "eidbridge"}, &uw)
	api.Must("POST", "/stages/user_login/", map[string]any{"name": "eidbridge user login", "session_duration": "seconds=0"}, &ul)
	for i, st := range []string{uw.Pk, ul.Pk} {
		api.Must("POST", "/flows/bindings/", map[string]any{"target": fl.Pk, "stage": st, "order": (i + 1) * 10}, nil)
	}

	src := map[string]any{"name": "eidbridge", "slug": "eidbridge", "enabled": true, "provider_type": "openidconnect",
		"consumer_key": bc.ID, "consumer_secret": bc.Secret,
		"oidc_well_known_url": bridgeIssuer + "/.well-known/openid-configuration",
		// authentik never sends a nonce; the bridge requires one, so a fixed nonce is
		// put in the authorization URL (authentik merges those query parameters).
		"authorization_url": bridgeIssuer + "/authorize?nonce=authentik-sends-no-nonce", "access_token_url": bridgeIssuer + "/token",
		"profile_url": bridgeIssuer + "/userinfo", "oidc_jwks_url": bridgeIssuer + "/jwks.json",
		"additional_scopes": "*openid profile", "pkce": "S256", "authorization_code_auth_method": "basic_auth",
		"user_matching_mode": "identifier", "user_property_mappings": []string{pm.Pk},
		"authentication_flow": flowPK("default-source-authentication"), "enrollment_flow": fl.Pk}
	api.Must("POST", "/sources/oauth/", src, nil)

	login := func() (*browser, string) {
		b := newBrowser(t)
		cbURL := b.Follow(akOrigin+"/source/oauth/login/eidbridge/", callback+"?", nil)
		resp, body := b.do(http.MethodGet, cbURL.String(), nil)
		loc := resp.Header.Get("Location")
		if resp.StatusCode != 302 || !strings.HasPrefix(loc, "/if/flow/") {
			t.Fatalf("authentik callback: HTTP %d Location=%q: %.300s", resp.StatusCode, loc, stripTags(body))
		}
		return b, akRunFlow(t, b, loc)
	}
	b, final := login()
	if final != "/if/user/" {
		t.Fatalf("authentik flow ended at %q, want /if/user/", final)
	}

	// The browser session is logged in at authentik as the user written from the bridge `sub`.
	var me struct {
		User struct {
			Pk             int
			Username, Path string
		}
	}
	_, mb := b.do(http.MethodGet, akOrigin+"/api/v3/core/users/me/", nil)
	json.Unmarshal([]byte(mb), &me)
	var conns struct {
		Results []struct {
			Identifier string
			User       int
		}
	}
	api.Must("GET", "/sources/user_connections/oauth/?source__slug=eidbridge", nil, &conns)
	if len(conns.Results) != 1 {
		t.Fatalf("want 1 source connection, got %+v", conns.Results)
	}
	sub := conns.Results[0].Identifier
	if me.User.Pk == 0 || me.User.Pk != conns.Results[0].User || me.User.Username != sub || len(sub) < 16 {
		t.Fatalf("session user %+v does not match connection %+v", me.User, conns.Results[0])
	}
	t.Logf("browser logged in as authentik user %d (username == bridge sub %s)", me.User.Pk, sub)

	// A second, fresh browser session signs in as the same user (the source authentication flow).
	b2, final2 := login()
	_, mb2 := b2.do(http.MethodGet, akOrigin+"/api/v3/core/users/me/", nil)
	var me2 struct{ User struct{ Pk int } }
	json.Unmarshal([]byte(mb2), &me2)
	api.Must("GET", "/sources/user_connections/oauth/?source__slug=eidbridge", nil, &conns)
	if me2.User.Pk != me.User.Pk || len(conns.Results) != 1 {
		t.Fatalf("second login (to %s) user %d, connections %+v; want user %d", final2, me2.User.Pk, conns.Results, me.User.Pk)
	}

	// Rejecting demo logins: guarded mapping, then a fresh identity must not be enrolled.
	api.Must("DELETE", "/core/users/"+strconv.Itoa(me.User.Pk)+"/", nil, nil)
	api.Must("PATCH", "/propertymappings/source/oauth/"+pm.Pk+"/", map[string]any{"expression": mapping(true)}, nil)
	b3 := newBrowser(t)
	cb3 := b3.Follow(akOrigin+"/source/oauth/login/eidbridge/", callback+"?", nil)
	resp, body := b3.do(http.MethodGet, cb3.String(), nil)
	t.Logf("demo login: HTTP %d Location=%q %.200s", resp.StatusCode, resp.Header.Get("Location"), stripTags(body))
	_, mb3 := b3.do(http.MethodGet, akOrigin+"/api/v3/core/users/me/", nil)
	if strings.Contains(mb3, `"username"`) && !strings.Contains(mb3, "AnonymousUser") {
		t.Fatalf("demo login was accepted: %.200s", mb3)
	}
	var us struct{ Results []struct{ Pk int } }
	api.Must("GET", "/core/users/?path=eidbridge", nil, &us)
	if len(us.Results) != 0 {
		t.Fatalf("refused demo login still created users: %+v", us.Results)
	}
}

// akRunFlow plays the authentik flow executor like its web UI: it follows the
// challenges of the flow at flowLoc (/if/flow/<slug>/?query) until the executor
// redirects out of the flow, and returns that redirect target.
func akRunFlow(t *testing.T, b *browser, flowLoc string) string {
	t.Helper()
	u, _ := url.Parse(flowLoc)
	slug := strings.Trim(strings.TrimPrefix(u.Path, "/if/flow/"), "/")
	ex := akOrigin + "/api/v3/flows/executor/" + slug + "/?query=" + url.QueryEscape(u.RawQuery)
	cb := b.fetch(ex)
	for i := 0; i < 12; i++ {
		var ch map[string]any
		json.Unmarshal([]byte(cb), &ch)
		t.Logf("challenge %d: %.300s", i, cb)
		comp, _ := ch["component"].(string)
		if comp == "xak-flow-redirect" {
			to, _ := ch["to"].(string)
			return to
		}
		cb = b.postJSON(ex, map[string]any{"component": comp})
	}
	t.Fatalf("authentik flow did not finish: %.400s", cb)
	return ""
}
