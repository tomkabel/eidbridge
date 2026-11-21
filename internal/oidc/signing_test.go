package oidc

import (
	"net/http/httptest"
	"testing"
)

func TestAuthenticateSigningClient(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Clients = append(c.Clients, Client{ID: "signer", Secret: secret, AuthMethod: AuthBasic,
			RedirectURIs: []string{"http://localhost:9000/cb"}, SubMode: "pairwise", SectorID: "signer.example", SigningAllowed: true})
	})
	try := func(user, pass string, basic bool) bool {
		r := httptest.NewRequest("POST", "/api/v1/sign", nil)
		if basic {
			r.SetBasicAuth(user, pass)
		}
		_, ok := e.p.AuthenticateSigningClient(r)
		return ok
	}
	if !try("signer", secret, true) {
		t.Fatal("signing client rejected")
	}
	for name, c := range map[string][3]any{
		"no credentials": {"", "", false}, "wrong secret": {"signer", secret + "x", true},
		"client without signing": {"basic", secret, true}, "unknown client": {"nobody", secret, true},
	} {
		if try(c[0].(string), c[1].(string), c[2].(bool)) {
			t.Errorf("%s accepted", name)
		}
	}
	bad := []Client{{ID: "x", Secret: secret, AuthMethod: AuthPost, RedirectURIs: []string{"https://a/cb"}, SubMode: "public", SigningAllowed: true}}
	if validateClients(bad, false) == nil {
		t.Fatal("signing_allowed with client_secret_post accepted")
	}
}
