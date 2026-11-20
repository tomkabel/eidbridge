#!/usr/bin/env python3
"""axe-core and keyboard-only checks of the login pages (Story 3.4, NFR-010).

Usage: a11y.py <issuer> <axe.min.js>  (the bridge must run in demo mode with
EIDBRIDGE_MOCK_DOCUMENT=manual so the pending page stays up).
Exit 1 on any serious or critical axe violation or a keyboard failure.
"""
import json, sys, urllib.parse
from playwright.sync_api import sync_playwright

ISSUER, AXE = sys.argv[1], open(sys.argv[2]).read()
AUTH = ISSUER + "/authorize?" + urllib.parse.urlencode({
    "client_id": "demo-rp", "redirect_uri": "http://localhost:8081/callback", "response_type": "code",
    "scope": "openid", "state": "a11y-state", "nonce": "a11y-nonce",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
failed = False


def audit(page, name):
    global failed
    page.add_script_tag(content=AXE)
    r = page.evaluate("axe.run(document, {runOnly: ['wcag2a','wcag2aa','wcag21a','wcag21aa','best-practice']})")
    bad = [v for v in r["violations"] if v["impact"] in ("serious", "critical")]
    other = [(v["id"], v["impact"]) for v in r["violations"] if v not in bad]
    print(f"{name}: passes={len(r['passes'])} serious/critical={len(bad)} other={other}")
    for v in bad:
        failed = True
        print("  VIOLATION", v["id"], v["impact"], v["help"], [n["target"] for n in v["nodes"]][:3])


with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    for lang in ("en", "et", "ru"):
        ctx = b.new_context(locale=lang, bypass_csp=True)  # only to inject axe
        page = ctx.new_page()
        page.goto(AUTH + "&ui_locales=" + lang)
        audit(page, f"choose[{lang}]")
        if lang == "en":
            # Keyboard only: Tab reaches the primary action with a visible focus ring; Enter starts the flow.
            page.keyboard.press("Tab")
            seen = []
            for _ in range(12):
                el = page.evaluate("""() => {const e=document.activeElement; const s=getComputedStyle(e);
                    return {tag:e.tagName, text:(e.innerText||e.value||'').trim().slice(0,40), outline:s.outlineStyle+' '+s.outlineWidth, shadow:s.boxShadow}}""")
                seen.append(el)
                if el["tag"] == "BUTTON":
                    break
                page.keyboard.press("Tab")
            btn = seen[-1]
            if btn["tag"] != "BUTTON" or (btn["outline"].startswith("none") and btn["shadow"] == "none"):
                failed = True
                print("  KEYBOARD: no focusable primary button with visible focus", seen)
            else:
                print(f"  keyboard: reached '{btn['text']}' after {len(seen)} Tab(s), focus {btn['outline']}")
            page.keyboard.press("Enter")
            page.wait_for_url("**/flow/**", timeout=5000)
            page.wait_for_selector("img, [data-status]", timeout=5000)
            audit(page, "pending-qr[en]")
            # Cancel by keyboard: focus the cancel button and press Enter.
            flow_url = page.url
            page.focus("form.cancel button")
            page.keyboard.press("Enter")
            page.wait_for_url("**/callback**", timeout=10000)
            err = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(page.url).query)).get("error", "")
            print("  keyboard cancel ->", urllib.parse.urlsplit(page.url).path, "error=" + err)
            if err != "access_denied":
                failed = True
                print("  KEYBOARD: cancel did not reach the client with access_denied")
            page.goto(flow_url)
            audit(page, "outcome-or-restart[en]")
            other = b.new_context(bypass_csp=True).new_page()
            other.goto(flow_url)
            audit(other, "restart-no-cookie[en]")
        ctx.close()
    ctx = b.new_context(bypass_csp=True)
    page = ctx.new_page()
    page.goto(ISSUER + "/authorize?client_id=unknown")
    audit(page, "error[en]")
    b.close()
sys.exit(1 if failed else 0)
