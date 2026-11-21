//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	zitPort   = 18100
	zitOrigin = "http://localhost:18100"
	zitPGPort = 18433
	zitImage  = "ghcr.io/zitadel/zitadel:v4.20.5@sha256:cb21fe73badfe44972bb24a66cf0ebce6a8dc63ab8ed24567af6b731bd8bbf45"
	zitApp    = "http://localhost:18083/zitadel-cb"
)

func TestZitadel(t *testing.T) {
	requireDocker(t)
	bc := startBridge(t, "zitadel", "client_secret_basic",
		zitOrigin+"/ui/login/login/externalidp/callback", zitOrigin+"/idps/callback")
	var pat string
	{
		portFree(t, zitPort)
		portFree(t, zitPGPort)
		pull(t, zitImage)
		pull(t, pgImage)
		out := t.TempDir()
		os.Chmod(out, 0o777)
		runContainer(t, "zitadel-pg", "-e", "POSTGRES_PASSWORD=pgpw", pgImage, "postgres", "-p", "18433", "-c", "listen_addresses=127.0.0.1")
		for i := 0; i < 60; i++ {
			if exec.Command("docker", "exec", "eidbridge-e2e-zitadel-pg", "pg_isready", "-h", "127.0.0.1", "-p", "18433").Run() == nil {
				break
			}
			time.Sleep(time.Second)
		}
		runContainer(t, "zitadel", "-v", out+":/zout",
			"-e", "ZITADEL_MASTERKEY=MasterkeyNeedsToHave32Characters",
			// Zitadel refuses to call loopback addresses by default (SSRF guard); the bridge runs on
			// localhost here, so allow everything except the cloud-metadata range.
			"-e", "ZITADEL_HTTPCLIENT_DENYLIST=169.254.0.0/16", "-e", "ZITADEL_HTTPCLIENT_ALLOWHTTPSDOWNGRADE=true",
			"-e", "ZITADEL_PORT=18100", "-e", "ZITADEL_EXTERNALDOMAIN=localhost", "-e", "ZITADEL_EXTERNALPORT=18100",
			"-e", "ZITADEL_EXTERNALSECURE=false", "-e", "ZITADEL_TLS_ENABLED=false",
			"-e", "ZITADEL_DATABASE_POSTGRES_HOST=127.0.0.1", "-e", "ZITADEL_DATABASE_POSTGRES_PORT=18433",
			"-e", "ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel",
			"-e", "ZITADEL_DATABASE_POSTGRES_USER_USERNAME=zitadel", "-e", "ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=zpw",
			"-e", "ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE=disable",
			"-e", "ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=postgres", "-e", "ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=pgpw",
			"-e", "ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE=disable",
			"-e", "ZITADEL_FIRSTINSTANCE_PATPATH=/zout/admin.pat", "-e", "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=e2e-admin",
			"-e", "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME=e2e-admin",
			"-e", "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=2030-01-01T00:00:00Z",
			zitImage, "start-from-init", "--masterkeyFromEnv")
		waitHTTP(t, zitOrigin+"/debug/ready", 200, 5*time.Minute)
		deadline := time.Now().Add(3 * time.Minute)
		for pat == "" {
			if b, err := os.ReadFile(out + "/admin.pat"); err == nil {
				pat = strings.TrimSpace(string(b))
			} else if time.Now().After(deadline) {
				t.Fatal("zitadel did not write the first-instance PAT within 3 minutes")
			} else {
				time.Sleep(time.Second)
			}
		}
	}
	api := &jsonAPI{t: t, base: zitOrigin, auth: "Bearer " + pat}
	for deadline := time.Now().Add(3 * time.Minute); api.doQuiet("GET", "/v2/features/instance", nil) != 200; time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("zitadel API did not become ready within 3 minutes")
		}
	}

	var idp struct{ ID string }
	api.Must("POST", "/admin/v1/idps/oauth", map[string]any{"name": "eidbridge", "clientId": bc.ID, "clientSecret": bc.Secret,
		// Zitadel's generic OIDC provider sends no nonce, which the bridge requires; the OAuth 2.0
		// provider type takes the endpoints verbatim, so a fixed nonce rides in the authorization URL.
		"authorizationEndpoint": bridgeIssuer + "/authorize?nonce=zitadel-sends-no-nonce",
		"tokenEndpoint":         bridgeIssuer + "/token", "userEndpoint": bridgeIssuer + "/userinfo",
		"scopes": []string{"openid", "profile"}, "idAttribute": "sub", "usePkce": true,
		"providerOptions": map[string]any{"isCreationAllowed": true, "isAutoCreation": false, "isLinkingAllowed": false, "isAutoUpdate": false}}, &idp)
	api.Must("POST", "/admin/v1/policies/login/idps", map[string]any{"idpId": idp.ID, "ownerType": "IDP_OWNER_TYPE_SYSTEM"}, nil)

	// intent runs one "log in with eidbridge" round trip: Zitadel returns the
	// bridge authorization URL, the browser logs in at the bridge and comes back
	// through Zitadel's /idps/callback to the success URL.
	intent := func() (id, token, user string, raw map[string]any) {
		var st struct {
			AuthURL string `json:"authUrl"`
		}
		api.Must("POST", "/v2/idp_intents", map[string]any{"idpId": idp.ID,
			"urls": map[string]string{"successUrl": zitApp + "/ok", "failureUrl": zitApp + "/fail"}}, &st)
		t.Logf("authUrl: %s", st.AuthURL)
		final := newBrowser(t).Follow(st.AuthURL, zitApp, nil)
		if !strings.HasPrefix(final.String(), zitApp+"/ok") {
			t.Fatalf("intent did not succeed: %s", final)
		}
		id, token, user = final.Query().Get("id"), final.Query().Get("token"), final.Query().Get("user")
		var res map[string]any
		api.Must("POST", "/v2/idp_intents/"+id, map[string]any{"idpIntentToken": token}, &res)
		return id, token, user, res
	}
	login := func(id, token, userID string) string {
		var sess struct{ SessionID, SessionToken string }
		chk := map[string]any{"idpIntent": map[string]string{"idpIntentId": id, "idpIntentToken": token}}
		chk["user"] = map[string]string{"userId": userID}
		api.Must("POST", "/v2/sessions", map[string]any{"checks": chk}, &sess)
		var got struct {
			Session struct {
				Factors struct {
					User   struct{ ID, LoginName string }
					Intent struct{ VerifiedAt string }
				}
			}
		}
		api.Must("GET", "/v2/sessions/"+sess.SessionID, nil, &got)
		if got.Session.Factors.User.ID != userID || got.Session.Factors.Intent.VerifiedAt == "" {
			t.Fatalf("session is not logged in as %s via the intent: %+v", userID, got)
		}
		return sess.SessionID
	}

	// 1. First login: the identity is unknown, so create the user with an IdP link
	// whose userId is the bridge `sub` (never link by name or e-mail).
	id, token, user, res := intent()
	info, _ := res["idpInformation"].(map[string]any)
	sub, _ := info["userId"].(string)
	if user != "" || len(sub) < 16 || info["idpId"] != idp.ID {
		t.Fatalf("first intent: linked user %q, sub %q, info %v", user, sub, info)
	}
	var nu struct{ UserID string }
	api.Must("POST", "/v2/users/human", map[string]any{
		"username": sub, "profile": map[string]string{"givenName": "eID", "familyName": "user"},
		// Zitadel requires an e-mail; the bridge supplies none, so use a non-routable placeholder.
		"email":    map[string]any{"email": strings.ToLower(sub[:16]) + "@eidbridge.invalid", "isVerified": false},
		"idpLinks": []map[string]string{{"idpId": idp.ID, "userId": sub, "userName": sub}}}, &nu)
	// Demo guard (docs/idp/zitadel.md): Zitadel hands the bridge claims to the login
	// code in rawInformation; a production login service must refuse eid_env=demo.
	ri, _ := info["rawInformation"].(map[string]any)
	raw, _ := ri["RawInfo"].(map[string]any)
	if raw["eid_env"] != "demo" {
		t.Fatalf("rawInformation lacks eid_env=demo: %v", raw)
	}
	login(id, token, nu.UserID)
	t.Logf("logged in at Zitadel as user %s linked to bridge sub %s", nu.UserID, sub)

	// 2. Second login: Zitadel recognises the link and returns the user itself.
	id2, token2, user2, res2 := intent()
	if user2 != nu.UserID {
		t.Fatalf("second intent: linked user %q, want %q (result %v)", user2, nu.UserID, res2)
	}
	login(id2, token2, nu.UserID)

	// The IdP link on the user is the bridge sub.
	var links struct {
		Result []struct{ IdpID, UserID string }
	}
	api.Must("POST", "/v2/users/"+nu.UserID+"/links/_search", map[string]any{}, &links)
	if len(links.Result) != 1 || links.Result[0].UserID != sub || links.Result[0].IdpID != idp.ID {
		t.Fatalf("user links: %+v, want one to sub %s", links.Result, sub)
	}
}
