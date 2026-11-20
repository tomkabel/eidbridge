"""Shared test helper: run a real eidbridge process (built-in demo fixture
upstream) and drive its login pages like a browser. Used by both examples."""
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parent.parent
CLIENT_ID = "py-example"
REDIRECT_URI = "http://localhost:8000/callback"  # demo mode only accepts http://localhost:<port>/<path>
_build_dir = None


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build():
    global _build_dir
    if _build_dir is None:
        _build_dir = tempfile.mkdtemp(prefix="eidb-build-")
        env = dict(os.environ, GOTOOLCHAIN="local")
        subprocess.run(["go", "build", "-o", f"{_build_dir}/eidbridge", "./cmd/eidbridge"],
                       cwd=REPO, env=env, check=True)
    return f"{_build_dir}/eidbridge"


@pytest.fixture(scope="session")
def bridge():
    """Start eidbridge in demo mode; yields dict(port, base, issuer, client_id, client_secret, discovery)."""
    binary = _build()
    tmp = tempfile.mkdtemp(prefix="eidb-run-")
    port = _free_port()
    secret = secrets.token_urlsafe(40)
    clients = Path(tmp) / "clients.json"
    clients.write_text(json.dumps([{
        "client_id": CLIENT_ID, "client_secret": secret,
        "token_endpoint_auth_method": "client_secret_basic",
        "redirect_uris": [REDIRECT_URI], "sub_mode": "pairwise"}]))
    clients.chmod(0o600)
    env = dict(os.environ,
               EIDBRIDGE_LISTEN=f"127.0.0.1:{port}",
               EIDBRIDGE_ISSUER=f"http://localhost:{port}",
               EIDBRIDGE_SMARTID_ENV="mock",
               EIDBRIDGE_SMARTID_CERT_STATUS="none",
               EIDBRIDGE_KEY_DIR=f"{tmp}/keys",
               EIDBRIDGE_CLIENTS_FILE=str(clients))
    proc = subprocess.Popen([binary, "serve", "--demo", "--root", str(REPO)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://localhost:{port}"
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if httpx.get(base + "/readyz", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("eidbridge did not become ready")
            time.sleep(0.2)
        yield {"port": port, "base": base, "issuer": base + "/demo",
               "discovery": base + "/demo/.well-known/openid-configuration",
               "client_id": CLIENT_ID, "client_secret": secret, "redirect_uri": REDIRECT_URI}
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


def drive_login(authorize_url, base):
    """Act as the browser on the bridge side. Returns the callback path+query
    (http://testserver/callback?code=...&state=...&iss=...) for the app."""
    jar = {}  # manual cookie jar: httpx drops Secure cookies over http

    def req(method, url, data=None):
        h = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} if jar else {}
        r = httpx.request(method, url, data=data, headers=h, timeout=30, follow_redirects=False)
        for sc in r.headers.get_list("set-cookie"):
            name, _, rest = sc.partition("=")
            val = rest.split(";")[0]
            if "Max-Age=0" in sc or not val:
                jar.pop(name, None)
            else:
                jar[name] = val
        return r

    r = req("GET", authorize_url)
    assert r.status_code == 303, r.text
    flow_url = urllib.parse.urljoin(authorize_url, r.headers["location"])
    page = req("GET", flow_url).text
    ft = re.search(r'name="ft" value="([^"]+)"', page).group(1)
    flow_base = flow_url.split("?")[0].rstrip("/")
    r = req("POST", flow_base + "/start", {"ft": ft, "method": "smartid", "flow": "qr"})
    assert r.status_code == 303, r.text
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        s = req("GET", flow_base + "/status").json()
        if s.get("next"):
            break
        time.sleep(0.2)
    else:
        raise AssertionError("flow did not finish")
    r = req("GET", base + s["next"])
    assert r.status_code == 303, r.text
    cb = urllib.parse.urlsplit(r.headers["location"])
    assert f"{cb.scheme}://{cb.netloc}{cb.path}" == REDIRECT_URI
    return cb.path + "?" + cb.query
