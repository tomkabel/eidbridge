"""Run the client's verifier against the bridge's live demo captures and the
shared negative vectors (testdata/vectors/smartid-v3-negatives.json)."""

import base64
import copy
import datetime as dt
import json
import pathlib
import urllib.parse

import pytest

from eidbridge_rp import Session, VerificationError, load_trust, verify

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIVE = ROOT / "internal" / "smartid" / "testdata" / "live"
TRUST = load_trust(ROOT / "trust" / "demo" / "smartid-auth-ca")


def load(name):
    d = LIVE / name
    meta = json.loads((d / "meta.json").read_text())
    status, link = None, None
    for f in sorted(d.glob("*-*.json")):
        x = json.loads(f.read_text())
        if x["name"] == "session-status":
            status = x["response"]
        if x["name"] == "mock-device-link":
            link = x["request"]["deviceLink"]
    s = Session(id="x", flow=meta["flow"], rp_challenge_b64=meta["rpChallenge"], interactions=meta["interactions"],
                rp_name="DEMO", scheme="smart-id-demo", secret=base64.b64decode(meta.get("sessionSecret", "")),
                token=meta.get("sessionToken", ""), link_base=meta.get("deviceLinkBase", ""),
                initial_callback_url=meta.get("initialCallbackUrl", ""), expected_identity=meta.get("expectedIdentity", ""))
    cb = None
    if meta.get("callbackUrl"):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(meta["callbackUrl"]).query))
        cb = {"sessionSecretDigest": q.get("sessionSecretDigest", ""), "userChallengeVerifier": q.get("userChallengeVerifier", "")}
    now = dt.datetime.fromisoformat(meta["captured"].replace("Z", "+00:00"))
    return s, status, cb, now, link


@pytest.mark.parametrize("name", ["qr-ok", "web2app-ok", "notification-ok"])
def test_live_ok(name):
    s, st, cb, now, _ = load(name)
    ident = verify(s, st, TRUST, callback=cb, now=now)
    assert ident.country == "EE" and ident.id_type == "PNO" and ident.cert_level == "QUALIFIED" and ident.flow_type == s.flow
    assert ident.given_name and ident.surname


@pytest.mark.parametrize("name", ["qr-ok", "web2app-ok"])
def test_auth_code_known_answer(name):
    """The live demo accepted these links, so rebuilding them is a KAT."""
    s, _, _, _, link = load(name)
    if s.flow == "QR":
        el = link.split("elapsedSeconds=")[1].split("&")[0]
        got = s._link("QR", el, "eng")
    else:
        got = s.web2app_link("eng")
    assert got == link


def _vectors():
    return json.loads((ROOT / "testdata" / "vectors" / "smartid-v3-negatives.json").read_text())["cases"]


@pytest.mark.parametrize("case", _vectors(), ids=lambda c: c["name"])
def test_shared_negative_vectors(case):
    s, st, cb, now, _ = load(case["fixture"])
    st = copy.deepcopy(st)
    if case.get("path"):
        keys = case["path"].split(".")
        obj = st
        for k in keys[:-1]:
            obj = obj[k]
        if case.get("delete"):
            del obj[keys[-1]]
        elif case.get("flip"):
            v = obj[keys[-1]]
            obj[keys[-1]] = ("B" if v[0] == "A" else "A") + v[1:]
        else:
            obj[keys[-1]] = case["set"]
    with pytest.raises(VerificationError) as e:
        verify(s, st, TRUST, callback=cb, now=now)
    assert e.value.reason == case["reason"], e.value


def test_web2app_callback_checks():
    s, st, cb, now, _ = load("web2app-ok")
    for bad in [None, {**cb, "sessionSecretDigest": "x"}, {**cb, "userChallengeVerifier": "y"}]:
        with pytest.raises(VerificationError):
            verify(s, st, TRUST, callback=bad, now=now)


def test_expired_and_untrusted():
    s, st, cb, now, _ = load("qr-ok")
    with pytest.raises(VerificationError):
        verify(s, st, TRUST, now=dt.datetime(2045, 1, 1, tzinfo=dt.timezone.utc))
    with pytest.raises(VerificationError):
        verify(s, st, load_trust(ROOT / "trust" / "demo" / "webeid-ca"), now=now)


def test_identity_mismatch_for_notification():
    s, st, cb, now, _ = load("notification-ok")
    s.expected_identity = "PNOEE-30303039914"
    with pytest.raises(VerificationError) as e:
        verify(s, st, TRUST, now=now)
    assert e.value.reason == "identity_mismatch"
