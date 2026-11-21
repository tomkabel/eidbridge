#!/usr/bin/env python3
"""Exercise static/webeid.js in Chrome against a running bridge (HTTPS,
EIDBRIDGE_METHODS including webeid). A stand-in for the browser extension,
installed as an init script, answers the window.postMessage protocol.

Usage: webeid_browser_check.py <issuer> <client redirect origin>
Checks: no extension -> flow ends (error at the client); extension reports
user cancel -> access_denied at the client; the page posts within limits.
"""
import sys, urllib.parse
from playwright.sync_api import sync_playwright

ISSUER, RP = sys.argv[1], sys.argv[2]
AUTH = ISSUER + "/authorize?" + urllib.parse.urlencode({
    "client_id": "demo-rp", "redirect_uri": RP + "/callback", "response_type": "code", "scope": "openid",
    "state": "s1", "nonce": "n1", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
FAKE_CANCEL = """
window.addEventListener("message", function (ev) {
  if (!ev.data || ev.data.action !== "web-eid:authenticate") return;
  console.log("webeid-request nonce-length=" + String(ev.data.challengeNonce || "").length + " origin=" + location.origin);
  window.postMessage({action: "web-eid:authenticate-ack"}, "*");
  setTimeout(function () {
    window.postMessage({action: "web-eid:authenticate-failure", error: {code: "ERR_WEBEID_USER_CANCELLED"}}, "*");
  }, 200);
});
"""
failed = False


def run(name, init, want):
    global failed
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
        ctx = b.new_context(ignore_https_errors=True)
        if init:
            ctx.add_init_script(init)
        page = ctx.new_page()
        logs = []
        page.on("console", lambda m: logs.append(m.text))
        page.goto(AUTH)
        page.click("input[value=webeid] ~ button")
        page.wait_for_selector("#browser-start", timeout=5000)
        page.focus("#browser-start")
        page.keyboard.press("Enter")
        page.wait_for_url(RP + "/callback**", timeout=15000)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(page.url).query))
        seen = [l for l in logs if l.startswith("webeid-request")]
        ok = q.get("error") == want
        if init:
            ok = ok and seen == ["webeid-request nonce-length=44 origin=" + urllib.parse.urlsplit(ISSUER).scheme + "://" + urllib.parse.urlsplit(ISSUER).netloc]
        print(f"{name}: client got error={q.get('error')} (want {want}) extension request={seen or '-'} -> {'PASS' if ok else 'FAIL'}")
        failed |= not ok
        b.close()


run("no extension", None, "server_error")
run("user cancels in extension", FAKE_CANCEL, "access_denied")
sys.exit(1 if failed else 0)
