#!/usr/bin/env python3
"""Drive WordPress logins through eidbridge like a browser. Standard library only.

WordPress login page -> bridge /authorize -> bridge login page (/demo/flow/{id})
-> start QR flow -> fixture upstream auto-approves -> status 'next' -> continue
-> 303 to the WordPress callback -> logged in. Then:
  1. the login page link carries PKCE S256, nonce, state, the exact redirect URI;
  2. /wp-admin/profile.php answers 200 for the new user, 302 to the login page
     for an anonymous client;
  3. WP-CLI shows the ID token `sub` stored in user meta;
  4. a second login in a fresh browser maps to the same WordPress user;
  5. with EIDBRIDGE_PRODUCTION=true the demo login is refused and no user is added.
Cookies are kept by hand: Python's cookie jar drops Secure cookies over http,
and the bridge's __Host-eidb-* cookie is Secure.
"""
import html, http.client, json, os, re, subprocess, sys, time, urllib.parse

WP = os.environ.get("WP_URL", "http://localhost:18481")
BRIDGE = os.environ.get("BRIDGE_URL", "http://localhost:18480")
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = ["docker", "compose", "-f", os.path.join(HERE, "docker-compose.yml")]
REDIRECT_URI = WP + "/wp-admin/admin-ajax.php?action=openid-connect-authorize"
SUB_META = "openid-connect-generic-subject-identity"
cookies = {}  # netloc -> {name: value}


def req(method, url, data=None):
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPConnection(u.netloc, timeout=60)
    jar = cookies.setdefault(u.netloc, {})
    h = {"Accept-Language": "en"}
    if jar:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data)
        h["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, u.path + ("?" + u.query if u.query else ""), body, h)
    r = c.getresponse()
    for k, v in r.getheaders():
        if k.lower() == "set-cookie":
            name, _, rest = v.partition("=")
            val = rest.split(";")[0]
            if "Max-Age=0" in v or val in ("", "deleted"):
                jar.pop(name, None)
            else:
                jar[name] = val
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read().decode(errors="replace")


def follow(url, limit=15):
    for _ in range(limit):
        st, h, b = req("GET", url)
        if st in (301, 302, 303, 307) and "location" in h:
            url = urllib.parse.urljoin(url, h["location"])
            continue
        return url, st, b
    raise SystemExit("too many redirects")


def wp(*args):
    """Run WP-CLI in the provisioning image (same volume as WordPress)."""
    p = subprocess.run(COMPOSE + ["run", "--rm", "--no-deps", "-T", "--entrypoint", "wp", "provision", *args],
                       capture_output=True, text=True, cwd=HERE)
    if p.returncode != 0:
        raise SystemExit(f"wp {' '.join(args)} failed ({p.returncode}): {p.stderr.strip()[-800:]}")
    return p.stdout.strip()


def sub_users():
    out = wp("eval", 'echo json_encode(array_values(array_filter(array_map(function($u){return ['
             '"id"=>$u->ID,"login"=>$u->user_login,"sub"=>get_user_option("' + SUB_META + '",$u->ID)];},'
             'get_users()), function($r){return !empty($r["sub"]);})));')
    return json.loads(out)


def authorize_link():
    _, st, page = follow(WP + "/wp-login.php")
    page = html.unescape(page)
    m = re.search(r'href="(' + re.escape(BRIDGE) + r'/demo/authorize\?[^"]+)"', page)
    if not m:
        raise SystemExit(f"no bridge login link on the WordPress login page (HTTP {st})")
    link = m.group(1)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
    one = lambda k: q.get(k, [""])[0]
    assert one("response_type") == "code", q
    assert one("code_challenge_method") == "S256" and len(one("code_challenge")) >= 43, q
    assert one("nonce") and one("state"), q
    assert one("redirect_uri") == REDIRECT_URI, q
    assert one("scope") == "openid profile" and one("client_id") == "wordpress", q
    print(f"  login link: PKCE S256 + nonce + state + exact redirect_uri present (state {one('state')[:8]}...)")
    return link


def bridge_login(link):
    url, st, page = follow(link)
    m = re.search(r'name="ft" value="([^"]+)"', page)
    if not m:
        raise SystemExit(f"no bridge login page at {url} ({st})")
    base, fid = re.match(r"(.*)/flow/([^/?]+)", url).groups()
    st, _, _ = req("POST", f"{base}/flow/{fid}/start", {"ft": m.group(1), "method": "smartid", "flow": "qr"})
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        _, _, b = req("GET", f"{base}/flow/{fid}/status")
        s = json.loads(b)
        if s.get("next"):
            o = urllib.parse.urlsplit(base)
            return follow(f"{o.scheme}://{o.netloc}{s['next']}")
        time.sleep(0.5)
    raise SystemExit("bridge flow did not finish")


def profile_login():
    st, h, b = req("GET", WP + "/wp-admin/profile.php")
    if st != 200:
        return None, st, h.get("location", "")
    m = re.search(r'id="user_login"[^>]*value="([^"]*)"', b) or re.search(r'value="([^"]*)"[^>]*id="user_login"', b)
    return (m.group(1) if m else "?"), st, ""


def one_login(label):
    for d in cookies.values():
        d.clear()  # fresh browser
    t0 = time.monotonic()
    link = authorize_link()
    t1 = time.monotonic()
    url, st, page = bridge_login(link)
    t2 = time.monotonic()
    login, pst, loc = profile_login()
    print(f"  {label}: callback ended at {url} (HTTP {st}); profile.php HTTP {pst}"
          + (f" -> {loc}" if loc else f", user_login {login!r}"))
    print(f"  timings: login page {t1 - t0:.2f}s, bridge flow + callback {t2 - t1:.2f}s, total {time.monotonic() - t0:.2f}s")
    return login, page


def main():
    t_all = time.monotonic()
    # The bridge itself refuses a request without PKCE.
    link = authorize_link()
    nopkce = re.sub(r"&code_challenge(_method)?=[^&]*", "", link)
    st, h, b = req("GET", nopkce)
    loc = urllib.parse.unquote(h.get("location", ""))
    assert st == 400 or "error=" in loc, f"bridge accepted an authorize request without PKCE: {st} {loc}"
    print(f"bridge without PKCE: HTTP {st} {('Location ' + loc[:120]) if loc else b.strip()[:100]!r}")

    print("anonymous /wp-admin/profile.php")
    cookies.clear()
    st, h, _ = req("GET", WP + "/wp-admin/profile.php")
    assert st == 302 and "wp-login.php" in h.get("location", ""), (st, h)
    print(f"  HTTP {st} -> {h['location']}")

    print("login 1 (demo mode)")
    login1, _ = one_login("login 1")
    assert login1, "not logged in after login 1"
    users = sub_users()
    assert len(users) == 1 and users[0]["login"] == login1, users
    sub = users[0]["sub"]
    print(f"  wp user meta {SUB_META} = {sub} (user ID {users[0]['id']}, user_login {login1})")

    print("login 2 (fresh browser, same eID)")
    login2, _ = one_login("login 2")
    users2 = sub_users()
    assert login2 == login1 and users2 == users, (login1, login2, users, users2)
    print(f"  same WordPress user: ID {users2[0]['id']}, one user with that sub")

    print("production guard: EIDBRIDGE_PRODUCTION=true must refuse the demo token")
    wp("config", "set", "EIDBRIDGE_PRODUCTION", "true", "--raw")
    try:
        login3, page3 = one_login("login 3 (production)")
        assert login3 is None, "demo login was accepted with EIDBRIDGE_PRODUCTION=true"
        assert len(sub_users()) == 1, "a user was created by a refused demo login"
        err = re.search(r'id="login_error"[^>]*>(.*?)</div>', page3, re.S)
        print("  refused; login page says: " + (re.sub(r"<[^>]+>|\s+", " ", err.group(1)).strip() if err else "(no message)"))
    finally:
        wp("config", "set", "EIDBRIDGE_PRODUCTION", "false", "--raw")
    login4, _ = one_login("login 4 (demo mode again)")
    assert login4 == login1
    print(f"PASS in {time.monotonic() - t_all:.1f}s")


if __name__ == "__main__":
    main()
