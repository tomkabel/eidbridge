//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	kratosPublic = "http://localhost:18200"
	kratosAdmin  = "http://localhost:18201"
	// Kratos' UI and return URLs. The browser driver stops at redirects to them,
	// so nothing has to listen here.
	kratosUI    = "http://localhost:18202"
	kratosImage = "oryd/kratos:v26.2.0@sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643"
)

const kratosSchema = `{
  "$id": "https://schemas.ory.sh/presets/kratos/eidbridge.schema.json",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "eID person",
  "type": "object",
  "properties": {
    "traits": {
      "type": "object",
      "properties": {
        "sub": {"type": "string", "title": "eidbridge sub"},
        "name": {"type": "string", "title": "Name"}
      },
      "required": ["sub"],
      "additionalProperties": false
    }
  }
}`

const kratosMapper = `local claims = std.extVar('claims');
{
  identity: {
    traits: {
      sub: claims.sub,
      [if 'given_name' in claims then 'name']: claims.given_name + ' ' + std.get(claims, 'family_name', ''),
    },
  },
}`

// The same mapper, refusing demo logins (docs/idp/ory.md).
const kratosMapperGuard = `local claims = std.extVar('claims');
if std.get(claims, 'eid_env', '') == 'demo' || std.get(claims, 'acr', '') == 'demo' then
  error 'demo eID logins are not accepted'
else
  ` + "{\n  identity: { traits: { sub: claims.sub } },\n}"

func TestOryKratos(t *testing.T) {
	requireDocker(t)
	t.Skip("e2e: NOT RUN - Ory Kratos v26.2.0 (generic OIDC provider) never sends the `nonce` parameter and ignores " +
		"auth_url when issuer_url is set, so there is no configuration that adds one; the bridge requires a nonce and " +
		"answers invalid_request (observed on 2026-11-20). Re-enable by deleting this Skip once the bridge accepts " +
		"authorization requests without nonce or Kratos can add one. The code below is the intended test; it ran only up to " +
		"the bridge's invalid_request redirect.")
	pull(t, kratosImage)
	t.Run("login", func(t *testing.T) { testKratos(t, false) })
	t.Run("reject-demo", func(t *testing.T) { testKratos(t, true) })
}

func testKratos(t *testing.T, guard bool) {
	portFree(t, 18200)
	portFree(t, 18201)
	cb := kratosPublic + "/self-service/methods/oidc/callback"
	bc := startBridge(t, "kratos", "client_secret_basic", cb)

	mapper := kratosMapper
	if guard {
		mapper = kratosMapperGuard
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	cfg := fmt.Sprintf(`dsn: memory
log: {level: debug}
serve:
  public: {host: 127.0.0.1, port: 18200, base_url: %[1]s/}
  admin: {host: 127.0.0.1, port: 18201, base_url: %[2]s/}
secrets:
  cookie: [%[3]s]
  cipher: [%[4]s]
identity:
  default_schema_id: default
  schemas: [{id: default, url: file:///cfg/identity.schema.json}]
selfservice:
  default_browser_return_url: %[5]s/
  allowed_return_urls: [%[5]s/]
  flows:
    login: {ui_url: %[5]s/login}
    registration: {ui_url: %[5]s/registration, enabled: true}
    error: {ui_url: %[5]s/error}
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: eidbridge
            provider: generic
            client_id: %[6]s
            client_secret: %[7]s
            issuer_url: %[8]s
            pkce: force
            scope: [openid, profile]
            mapper_url: base64://%[9]s
`, kratosPublic, kratosAdmin, randHex(16), randHex(16), kratosUI, bc.ID, bc.Secret, bridgeIssuer,
		base64.StdEncoding.EncodeToString([]byte(mapper)))
	for name, content := range map[string]string{"kratos.yml": cfg, "identity.schema.json": kratosSchema} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runContainer(t, "kratos", "-v", dir+":/cfg:ro", kratosImage, "serve", "--dev", "-c", "/cfg/kratos.yml")
	waitHTTP(t, kratosPublic+"/health/ready", 200, 60*time.Second)

	// browserLogin plays the browser: start a login flow, press "eidbridge", log in at
	// the bridge, and come back through Kratos' callback to the return URL.
	browserLogin := func() (*browser, *url.URL, string) {
		b := newBrowser(t)
		resp, _ := b.do(http.MethodGet, kratosPublic+"/self-service/login/browser", nil)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		flowID := loc.Query().Get("flow")
		if resp.StatusCode != 303 || flowID == "" {
			t.Fatalf("login/browser: HTTP %d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
		var fl struct {
			UI struct {
				Action string
				Nodes  []struct {
					Attributes struct{ Name, Value any }
				}
			}
		}
		_, fb := b.do(http.MethodGet, kratosPublic+"/self-service/login/flows?id="+flowID, nil)
		if err := json.Unmarshal([]byte(fb), &fl); err != nil {
			t.Fatalf("flow: %v: %.300s", err, fb)
		}
		form := url.Values{"provider": {"eidbridge"}, "method": {"oidc"}}
		for _, n := range fl.UI.Nodes {
			if n.Attributes.Name == "csrf_token" {
				form.Set("csrf_token", fmt.Sprint(n.Attributes.Value))
			}
		}
		resp, body := b.do(http.MethodPost, fl.UI.Action, form)
		next := resp.Header.Get("Location")
		if resp.StatusCode != 303 || !strings.HasPrefix(next, bridgeIssuer+"/authorize") {
			t.Fatalf("pressing eidbridge: HTTP %d Location=%q: %.300s", resp.StatusCode, next, stripTags(body))
		}
		final := b.Follow(next, kratosUI, nil)
		return b, final, flowID
	}

	if guard {
		// Refused: the mapper errors, Kratos shows its error UI and creates no identity.
		_, final, _ := browserLogin()
		t.Logf("demo login ended at %s", final)
		var ids []map[string]any
		(&jsonAPI{t: t, base: kratosAdmin}).Must("GET", "/admin/identities", nil, &ids)
		if len(ids) != 0 || strings.HasPrefix(final.Path, "/error") == false && !strings.Contains(final.String(), "error") {
			t.Fatalf("demo login was not refused: final %s, identities %d", final, len(ids))
		}
		return
	}

	b, final, _ := browserLogin()
	if final.Path != "/" {
		_, fb := b.do(http.MethodGet, kratosPublic+"/self-service/login/flows?id="+final.Query().Get("flow"), nil)
		t.Fatalf("login ended at %s, want the return URL; flow: %.1500s", final, fb)
	}
	resp, body := b.do(http.MethodGet, kratosPublic+"/sessions/whoami", nil)
	var who struct {
		Active   bool
		Identity struct {
			ID     string
			Traits struct{ Sub, Name string }
		}
	}
	json.Unmarshal([]byte(body), &who)
	if resp.StatusCode != 200 || !who.Active || who.Identity.Traits.Sub == "" {
		t.Fatalf("whoami: HTTP %d: %.300s", resp.StatusCode, body)
	}
	admin := &jsonAPI{t: t, base: kratosAdmin}
	var idn struct {
		ID          string
		Credentials map[string]struct {
			Identifiers []string
		}
	}
	admin.Must("GET", "/admin/identities/"+who.Identity.ID+"?include_credential=oidc", nil, &idn)
	sub := who.Identity.Traits.Sub
	if got := idn.Credentials["oidc"].Identifiers; len(got) != 1 || got[0] != "eidbridge:"+sub {
		t.Fatalf("oidc credential identifiers %v, want [eidbridge:%s]", got, sub)
	}
	t.Logf("logged in at Kratos as identity %s federated with eidbridge:%s (name %q)", who.Identity.ID, sub, who.Identity.Traits.Name)

	// A fresh browser session signs in as the same identity.
	b2, _, _ := browserLogin()
	_, body2 := b2.do(http.MethodGet, kratosPublic+"/sessions/whoami", nil)
	var who2 struct{ Identity struct{ ID string } }
	json.Unmarshal([]byte(body2), &who2)
	var ids []map[string]any
	admin.Must("GET", "/admin/identities", nil, &ids)
	if who2.Identity.ID != who.Identity.ID || len(ids) != 1 {
		t.Fatalf("second login: identity %q (want %q), %d identities", who2.Identity.ID, who.Identity.ID, len(ids))
	}
}
