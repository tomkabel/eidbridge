#!/usr/bin/env python3
"""Drive a complete demo login through the compose stack like a browser.

demo-rp /login -> bridge /authorize -> chooser -> start QR flow -> fixture
upstream auto-approves -> status 'next' -> continue -> demo-rp /callback.
Prints the verified claims page. Exit 0 on success. Standard library only.
"""
import html, http.client, json, re, sys, time, urllib.parse

RP = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
EXPECT = sys.argv[2] if len(sys.argv) > 2 else "claims"  # or "refused"
cookies = {}  # host -> {name: value}; Secure cookies are kept on localhost like browsers do


def req(method, url, data=None):
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPConnection(u.netloc, timeout=30)
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
            if "Max-Age=0" in v or val == "":
                jar.pop(name, None)
            else:
                jar[name] = val
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read().decode()


def follow(url):
    for _ in range(10):
        st, h, b = req("GET", url)
        if st in (301, 302, 303, 307) and "location" in h:
            url = urllib.parse.urljoin(url, h["location"])
            continue
        return url, st, b
    raise SystemExit("too many redirects")


t0 = time.monotonic()
url, st, page = follow(RP + "/login")
m = re.search(r'name="ft" value="([^"]+)"', page)
if not m:
    raise SystemExit(f"no chooser page at {url} ({st})")
base, fid = re.match(r"(.*)/flow/([^/?]+)", url).groups()
st, h, _ = req("POST", f"{base}/flow/{fid}/start", {"ft": m.group(1), "method": "smartid", "flow": "qr"})
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    _, _, b = req("GET", f"{base}/flow/{fid}/status")
    s = json.loads(b)
    if s.get("next"):
        o = urllib.parse.urlsplit(base)
        url, st, page = follow(f"{o.scheme}://{o.netloc}{s['next']}")
        break
    time.sleep(0.5)
else:
    raise SystemExit("flow did not finish")
elapsed = time.monotonic() - t0
if EXPECT == "claims":
    page = html.unescape(page)
    if 'id="claims"' not in page or '"acr": "demo"' not in page:
        raise SystemExit(f"no verified claims ({st}) at {url}: {re.sub(r"<style.*?</style>", "", page, flags=re.S)[:600]}")
    print(re.search(r'<pre id="claims">(.*?)</pre>', page, re.S).group(1))
else:
    if st != 403:
        raise SystemExit(f"expected production RP to refuse demo token, got {st}")
    print("refused:", page.strip())
print(f"login completed in {elapsed:.2f}s")
