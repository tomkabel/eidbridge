import urllib.parse

import pytest
from conftest_bridge import drive_login
from starlette.testclient import TestClient


@pytest.fixture()
def rp(bridge, monkeypatch):
    monkeypatch.setenv("OIDC_DISCOVERY_URL", bridge["discovery"])
    monkeypatch.setenv("OIDC_CLIENT_ID", bridge["client_id"])
    monkeypatch.setenv("OIDC_CLIENT_SECRET", bridge["client_secret"])
    monkeypatch.setenv("OIDC_REDIRECT_URI", bridge["redirect_uri"])
    monkeypatch.delenv("PRODUCTION", raising=False)
    import fastapi_rp
    # http://testserver base; follow_redirects off so /login yields the bridge URL.
    return TestClient(fastapi_rp.create_app(), follow_redirects=False)


def _login(rp, bridge):
    r = rp.get("/login")
    assert r.status_code == 302
    return r.headers["location"], drive_login(r.headers["location"], bridge["base"])


def test_index_links_to_login(rp):
    r = rp.get("/")
    assert r.status_code == 200 and 'href="/login"' in r.text


def test_me_unauthenticated(rp):
    assert rp.get("/me").status_code == 401


def test_authorize_request_uses_pkce(rp, bridge):
    loc, _ = _login(rp, bridge)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
    assert q["code_challenge_method"] == ["S256"] and q["scope"] == ["openid profile"]


def test_full_login(rp, bridge):
    _, cb = _login(rp, bridge)
    r = rp.get(cb)
    assert r.status_code == 200, r.text
    me = rp.get("/me").json()
    assert me["acr"] == "demo" and me["eid_env"] == "demo" and me["sub"]
    assert "personal_code" not in me
    assert me["sub"] in r.text


def test_production_refuses_demo(rp, bridge, monkeypatch):
    monkeypatch.setenv("PRODUCTION", "1")
    _, cb = _login(rp, bridge)
    r = rp.get(cb)
    assert r.status_code == 403
    assert "demo identities are refused in production" in r.text
    assert rp.get("/me").status_code == 401


def test_state_tampering(rp, bridge):
    _, cb = _login(rp, bridge)
    bad = cb.replace("state=", "state=x")
    assert 400 <= rp.get(bad).status_code < 500
    assert rp.get("/me").status_code == 401


def test_issuer_mixup_refused_before_exchange(rp, bridge):
    # RFC 9207: a callback whose iss is not the bridge is refused, and the
    # code is not spent (the genuine callback still works afterwards).
    _, cb = _login(rp, bridge)
    import urllib.parse as up
    u = up.urlsplit(cb)
    q = dict(up.parse_qsl(u.query))
    q["iss"] = "https://attacker.example"
    assert rp.get(u.path + "?" + up.urlencode(q)).status_code == 400
    q.pop("iss")
    assert rp.get(u.path + "?" + up.urlencode(q)).status_code == 400
    assert rp.get(cb).status_code == 200
