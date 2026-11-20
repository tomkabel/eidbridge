"""HTTP side of the Smart-ID RP API v3: start sessions, build device links,
poll. Standard library only (urllib); never follows redirects."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEMO_BASE_URL = "https://sid.demo.sk.ee/smart-id-rp"
DEMO_RP_UUID = "00000000-0000-4000-8000-000000000000"
DEMO_RP_NAME = "DEMO"
SCHEME_DEMO = "smart-id-demo"


@dataclass
class Session:
    id: str
    flow: str  # QR, Web2App or Notification
    rp_challenge_b64: str
    interactions: str
    rp_name: str
    scheme: str
    secret: bytes = field(repr=False, default=b"")
    token: str = ""
    link_base: str = ""
    initial_callback_url: str = ""
    expected_identity: str = ""
    created: float = field(default_factory=time.monotonic)

    def qr_link(self, lang: str = "eng") -> str:
        """Dynamic QR link with elapsedSeconds and authCode (v3 device link)."""
        el = str(int(time.monotonic() - self.created))
        return self._link("QR", el, lang)

    def web2app_link(self, lang: str = "eng") -> str:
        return self._link("Web2App", "", lang)

    def _link(self, dl_type: str, elapsed: str, lang: str) -> str:
        q = f"deviceLinkType={dl_type}&sessionToken={self.token}&sessionType=auth&version=1.0&lang={lang}"
        if elapsed:
            q = f"deviceLinkType={dl_type}&elapsedSeconds={elapsed}&sessionToken={self.token}&sessionType=auth&version=1.0&lang={lang}"
        unprotected = f"{self.link_base}?{q}"
        payload = "|".join([self.scheme, "ACSP_V2", self.rp_challenge_b64, base64.b64encode(self.rp_name.encode()).decode(), "",
                            self.interactions, self.initial_callback_url, unprotected])
        code = base64.urlsafe_b64encode(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        return f"{unprotected}&authCode={code}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, base_url: str = DEMO_BASE_URL, rp_uuid: str = DEMO_RP_UUID, rp_name: str = DEMO_RP_NAME,
                 scheme: str = SCHEME_DEMO, timeout: float = 130.0):
        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("base_url must be https")
        self.base, self.rp_uuid, self.rp_name, self.scheme, self.timeout = base_url.rstrip("/"), rp_uuid, rp_name, scheme, timeout
        self._open = urllib.request.build_opener(_NoRedirect).open

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        with self._open(req, timeout=self.timeout) as r:
            return json.loads(r.read(64 << 10))

    def _request(self, flow: str, display_text: str, callback: str = "") -> tuple[dict, str, bytes]:
        challenge = base64.b64encode(os.urandom(32)).decode()
        interactions = base64.b64encode(json.dumps([{"type": "displayTextAndPIN", "displayText60": display_text}],
                                                   separators=(",", ":")).encode()).decode()
        body = {"relyingPartyUUID": self.rp_uuid, "relyingPartyName": self.rp_name, "certificateLevel": "QUALIFIED",
                "signatureProtocol": "ACSP_V2", "interactions": interactions,
                "signatureProtocolParameters": {"rpChallenge": challenge, "signatureAlgorithm": "rsassa-pss",
                                                "signatureAlgorithmParameters": {"hashAlgorithm": "SHA-512"}}}
        if callback:
            body["initialCallbackUrl"] = callback
        return body, interactions, challenge

    def start_device_link(self, flow: str = "QR", display_text: str = "Log in", callback: str = "") -> Session:
        """flow QR (no callback) or Web2App (https callback required)."""
        if flow not in ("QR", "Web2App") or (flow == "Web2App") != bool(callback):
            raise ValueError("QR takes no callback; Web2App needs one")
        body, inter, ch = self._request(flow, display_text, callback)
        r = self._post("/v3/authentication/device-link/anonymous", body)
        return Session(r["sessionID"], flow, ch, inter, self.rp_name, self.scheme, base64.b64decode(r["sessionSecret"]),
                       r["sessionToken"], r["deviceLinkBase"], callback)

    def start_notification(self, semantics_id: str, display_text: str = "Log in") -> Session:
        body, inter, ch = self._request("Notification", display_text)
        r = self._post("/v3/authentication/notification/etsi/" + semantics_id, body)
        return Session(r["sessionID"], "Notification", ch, inter, self.rp_name, self.scheme, expected_identity=semantics_id)

    def poll(self, session: Session, timeout_ms: int = 30000) -> dict:
        t = min(max(timeout_ms, 1000), 120000)
        req = urllib.request.Request(f"{self.base}/v3/session/{session.id}?timeoutMs={t}", headers={"Accept": "application/json"})
        with self._open(req, timeout=t / 1000 + 10) as r:
            return json.loads(r.read(64 << 10))
