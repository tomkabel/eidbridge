package oidc

import (
	"slices"
	"testing"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
)

// twoMethods is a production-like configuration (production acr values are
// switched on with prodACR, since New insists on an https issuer) with two methods and
// operator-backed acr values (ADR 0003), plus a client limited to one.
func twoMethods(c *Config) {
	c.Methods = []string{"smartid", "mobileid"}
	c.MethodACR = map[string]string{"smartid": "urn:example:loa:high", "mobileid": "urn:example:loa:substantial"}
	c.Clients = append(c.Clients, Client{ID: "only-mid", Secret: secret, AuthMethod: AuthBasic,
		RedirectURIs: []string{"http://localhost:9000/cb"}, SubMode: "pairwise", AllowedMethods: []string{"mobileid"}})
}

// Story 4.1: acr_values filtering and per-client restriction decide which
// methods the login page may offer; order follows EIDBRIDGE_METHODS.
func TestMethodsFilteredByACRValuesAndClient(t *testing.T) {
	e := newEnv(t, twoMethods)
	prodACR(e)
	mid := authn.Identity{Method: "mobileid", AMR: []string{"mobileid"}, IDType: "PNO", Country: "EE", Code: "40404040009", GivenName: "OK", FamilyName: "TEST"}
	e.front.id = &mid
	for _, tc := range []struct {
		client, acr string
		want        []string
	}{
		{"basic", "", []string{"smartid", "mobileid"}},
		{"basic", "urn:example:loa:substantial", []string{"mobileid"}},
		{"basic", "urn:example:loa:high urn:example:loa:substantial", []string{"smartid", "mobileid"}},
		{"only-mid", "", []string{"mobileid"}},
	} {
		q := e.authParams(tc.client)
		if tc.acr != "" {
			q.Set("acr_values", tc.acr)
		}
		e.front.last = nil
		e.authorize(q)
		if e.front.last == nil || !slices.Equal(e.front.last.Methods, tc.want) {
			t.Errorf("%s acr=%q: methods %v, want %v", tc.client, tc.acr, e.front.last, tc.want)
		}
	}
	q := e.authParams("only-mid")
	q.Set("acr_values", "urn:example:loa:high")
	if u := e.authorize(q); u.Query().Get("error") != "unmet_authentication_requirements" {
		t.Fatalf("restricted client asking for an excluded method's acr: %s", u)
	}
	if acr := e.p.ACRValuesSupported(); !slices.Equal(acr, []string{"urn:example:loa:high", "urn:example:loa:substantial"}) {
		t.Fatalf("acr_values_supported %v", acr)
	}
}

// Story 4.1: amr and acr in the token come from the method that actually
// authenticated, and a result from a method the request did not permit is
// refused (no silent downgrade).
func TestTokenCarriesAMRAndACRFromUsedMethod(t *testing.T) {
	e := newEnv(t, twoMethods)
	prodACR(e)
	mid := authn.Identity{Method: "mobileid", AMR: []string{"mobileid"}, IDType: "PNO", Country: "EE", Code: "40404040009", GivenName: "OK", FamilyName: "TEST"}
	e.front.id = &mid
	tr := e.exchange("basic", e.code("basic"), nil)
	c := claims(t, tr.IDToken)
	if c["acr"] != "urn:example:loa:substantial" || c["eid_method"] != "mobileid" {
		t.Fatalf("claims %v", c)
	}
	if amr, _ := c["amr"].([]any); len(amr) != 1 || amr[0] != "mobileid" {
		t.Fatalf("amr %v", c["amr"])
	}
	res, err := e.p.Reserve(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Release()
	req := &AuthRequest{ClientID: "basic", RedirectURI: "http://localhost:9000/cb", State: "s", Nonce: "n",
		CodeChallenge: challenge(verifier), Scopes: []string{"openid"}, Methods: []string{"smartid"}}
	if _, err := e.p.Complete(req, res, &mid, e.clk.Now()); err == nil {
		t.Fatal("mobileid result accepted for a smartid-only request")
	}
}

// prodACR turns on production acr derivation for the test server, which
// listens on http and so cannot be built in production mode.
func prodACR(e *env) { e.p.cfg.Demo = false }
