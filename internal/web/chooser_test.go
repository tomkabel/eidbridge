package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Story 4.1 [A17]: one enabled method renders no chooser UI.
func TestNoChooserWithSingleMethod(t *testing.T) {
	e := newWeb(t, wopt{remember: true})
	_, page, _ := e.browser().begin(nil)
	if strings.Contains(page, catalogs["en"]["choose.method"]) || strings.Contains(page, `name="remember"`) {
		t.Fatal("chooser or remember offer shown with a single method")
	}
	if !strings.Contains(page, `name="method" value="smartid"`) {
		t.Fatal("single method not offered")
	}
}

func methodsOn(page string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(page, `name="method" value="`)[1:] {
		m := part[:strings.Index(part, `"`)]
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// Story 4.1: two methods show the chooser in EIDBRIDGE_METHODS order;
// login_hint=method:<name> preselects one; an unknown hint is ignored.
func TestChooserAndLoginHint(t *testing.T) {
	e := newWeb(t, wopt{fake: true})
	_, page, _ := e.browser().begin(nil)
	if got := methodsOn(page); len(got) != 2 || got[0] != "smartid" || got[1] != "fake" || !strings.Contains(page, catalogs["en"]["choose.method"]) {
		t.Fatalf("chooser methods %v", got)
	}
	_, page, _ = e.browser().begin(url.Values{"login_hint": {"method:fake"}})
	if got := methodsOn(page); len(got) != 1 || got[0] != "fake" {
		t.Fatalf("login_hint preselect: %v", got)
	}
	_, page, _ = e.browser().begin(url.Values{"login_hint": {"method:nope"}})
	if got := methodsOn(page); len(got) != 2 {
		t.Fatalf("unknown hint changed the choice: %v", got)
	}
}

// Story 4.1: the start form refuses a method the page did not offer.
func TestStartRefusesMethodNotOffered(t *testing.T) {
	e := newWeb(t, wopt{fake: true})
	b := e.browser()
	id, page, _ := b.begin(url.Values{"login_hint": {"method:fake"}})
	// the hint only narrows the page; the request still permits both, so a
	// method outside the request is what must fail:
	r := b.start(id, page, "mobileid", "qr", nil)
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown method: %d", r.StatusCode)
	}
}

// Story 4.1 [E23]: a remembered method that is no longer enabled is ignored
// and the flow proceeds; an enabled remembered method preselects.
func TestRememberCookieIgnoredWhenMethodRemoved(t *testing.T) {
	e := newWeb(t, wopt{fake: true, remember: true})
	for _, tc := range []struct {
		cookie string
		want   []string
	}{{"mobileid", []string{"smartid", "fake"}}, {"fake", []string{"fake"}}, {"", []string{"smartid", "fake"}}} {
		b := e.browser()
		u, _ := url.Parse(e.srv.URL)
		if tc.cookie != "" {
			b.c.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-eidb-method", Value: tc.cookie, Path: "/", Secure: true}})
		}
		_, page, resp := b.begin(nil)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("cookie %q: authorize %d", tc.cookie, resp.StatusCode)
		}
		if got := methodsOn(page); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("cookie %q: methods %v, want %v", tc.cookie, got, tc.want)
		}
	}
}

// Wallet links use custom schemes (openid4vp://). html/template replaces
// unknown schemes with #ZgotmplZ, which broke the same-device wallet link;
// allowed schemes render as is and anything else is dropped.
func TestAppLinkSchemes(t *testing.T) {
	for link, want := range map[string]string{
		"openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fb.example%2Fr": `href="openid4vp://?client_id=x509_hash%3Aabc&amp;request_uri=https%3A%2F%2Fb.example%2Fr"`,
		"haip://?request_uri=https%3A%2F%2Fb.example%2Fr":                                 `href="haip://?request_uri=https%3A%2F%2Fb.example%2Fr"`,
		"https://app.example/x":                                                           `href="https://app.example/x"`,
		"javascript:alert(1)":                                                             ``,
	} {
		e := newWeb(t, wopt{fake: true})
		e.fake.FlowList = []string{"same-device"}
		e.fake.AppLink = link
		b := e.browser()
		id, page, _ := b.begin(nil)
		b.start(id, page, "fake", "same-device", nil).Body.Close()
		r, _ := b.c.Get(e.issuer + "/flow/" + id)
		got := readAll(r)
		if want != "" && !strings.Contains(got, want) {
			t.Errorf("%s: link not rendered: %.200s", link, got[strings.Index(got, "<main"):])
		}
		if want == "" && (strings.Contains(got, "javascript:") || strings.Contains(got, "ZgotmplZ")) {
			t.Errorf("%s rendered", link)
		}
	}
}
