"""Response verification for Smart-ID RP API v3 (ACSP_V2), failing closed.

Order (mirrors the bridge's Go verifier):
 1. Web2App callback: sessionSecretDigest matches the session secret
 2. state COMPLETE, endResult OK, signatureProtocol ACSP_V2, mandatory fields
    present, flowType equals the offered flow, interaction was offered
 3. Web2App: userChallenge == base64url(SHA-256(userChallengeVerifier))
 4. certificate chains to the configured CAs at the current time, leaf not a CA
 5. required certificate policies present
 6. Smart-ID authentication purpose
 7. certificate level at least the minimum
 8. identity: serialNumber PNO/PAS/IDC; expected identity; documentNumber owner
 9. RSASSA-PSS signature over the rebuilt ACSP_V2 payload
Certificate status (OCSP) is the caller's responsibility (status callback).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEMO_POLICY_OIDS = ["1.3.6.1.4.1.10015.17.2"]
SMART_ID_AUTH_EKU = "1.3.6.1.4.1.62306.5.7.0"
LEVELS = {"ADVANCED": 1, "QUALIFIED": 2}
END_RESULTS = {"OK": None, "USER_REFUSED": "refused", "TIMEOUT": "expired", "DOCUMENT_UNUSABLE": "account_unusable",
               "WRONG_VC": "wrong_code", "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP": "account_unusable",
               "USER_REFUSED_CERT_CHOICE": "refused", "USER_REFUSED_INTERACTION": "refused",
               "PROTOCOL_FAILURE": "upstream_error", "EXPECTED_LINKED_SESSION": "upstream_error",
               "SERVER_ERROR": "upstream_error", "ACCOUNT_UNUSABLE": "account_unusable"}
HASHES = {"SHA-256": hashes.SHA256, "SHA-384": hashes.SHA384, "SHA-512": hashes.SHA512}
_SEMANTICS = re.compile(r"^(PNO|PAS|IDC)([A-Z]{2})-([0-9A-Za-z-]{1,40})$")
_USER_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class VerificationError(Exception):
    """Raised for any refused response. reason matches the bridge's codes."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


def _fail(detail: str, reason: str = "verification_failed"):
    raise VerificationError(reason, detail)


@dataclass(frozen=True)
class Identity:
    id_type: str
    country: str
    code: str
    given_name: str
    surname: str
    document_number: str
    cert_level: str
    flow_type: str


@dataclass(frozen=True)
class Trust:
    roots: list
    intermediates: list


def load_trust(directory: str | Path) -> Trust:
    roots, inters = [], []
    for p in sorted(Path(directory).glob("*.pem")):
        for c in x509.load_pem_x509_certificates(p.read_bytes()):
            (roots if c.issuer == c.subject else inters).append(c)
    if not roots:
        raise ValueError("no root CA in trust directory")
    return Trust(roots, inters)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def acsp_v2_payload(scheme, server_random, rp_challenge, user_challenge, rp_name, brokered, interactions,
                    interaction_used, callback_url, flow_type) -> bytes:
    ih = base64.b64encode(hashlib.sha256(interactions.encode()).digest()).decode()
    return "|".join([scheme, "ACSP_V2", server_random, rp_challenge, user_challenge, _b64(rp_name), _b64(brokered),
                     ih, interaction_used, callback_url, flow_type]).encode()


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _chain(leaf: x509.Certificate, trust: Trust, now: dt.datetime) -> Optional[x509.Certificate]:
    """Returns the leaf's issuer if leaf → [intermediate] → root verifies."""
    def valid(c):
        return c.not_valid_before_utc <= now <= c.not_valid_after_utc

    def is_ca(c):
        try:
            return c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            return False
    if not valid(leaf):
        return None
    for root in trust.roots:
        if valid(root) and _issued_by(leaf, root):
            return root
    for inter in trust.intermediates:
        if valid(inter) and is_ca(inter) and _issued_by(leaf, inter):
            for root in trust.roots:
                if valid(root) and _issued_by(inter, root):
                    return inter
    return None


def _auth_purpose(c: x509.Certificate) -> bool:
    try:
        ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return False
    if not ku.digital_signature:
        return False
    try:
        ekus = [e.dotted_string for e in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        ekus = []
    if SMART_ID_AUTH_EKU in ekus:
        return True
    return ku.key_encipherment and ku.data_encipherment and ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string in ekus


def _policies(c: x509.Certificate) -> set:
    try:
        return {p.policy_identifier.dotted_string for p in c.extensions.get_extension_for_class(x509.CertificatePolicies).value}
    except x509.ExtensionNotFound:
        return set()


def _attr(c: x509.Certificate, oid) -> str:
    v = c.subject.get_attributes_for_oid(oid)
    return v[0].value if v else ""


def _interaction_offered(interactions_b64: str, used: str) -> bool:
    try:
        items = json.loads(base64.b64decode(interactions_b64, validate=True))
    except (ValueError, TypeError):
        return False
    return any(isinstance(i, dict) and i.get("type") == used for i in items)


def verify(session, status: dict, trust: Trust, *, min_level: str = "QUALIFIED", policy_oids=DEMO_POLICY_OIDS,
           callback: Optional[dict] = None, now: Optional[dt.datetime] = None,
           status_check: Optional[Callable[[x509.Certificate, x509.Certificate], None]] = None) -> Identity:
    """Verify a session-status response for session; raise VerificationError."""
    now = now or dt.datetime.now(dt.timezone.utc)
    # 1
    if session.flow == "Web2App":
        if not callback:
            _fail("web2app result without callback")
        digest = base64.urlsafe_b64encode(hashlib.sha256(session.secret).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(digest, callback.get("sessionSecretDigest", "")):
            _fail("sessionSecretDigest mismatch")
    # 2
    if status.get("state") != "COMPLETE":
        _fail("session not complete", "upstream_error")
    end = (status.get("result") or {}).get("endResult")
    if end not in END_RESULTS:
        _fail("unknown endResult", "unknown_end_result")
    if END_RESULTS[end]:
        _fail("endResult " + end, END_RESULTS[end])
    if status.get("signatureProtocol") != "ACSP_V2":
        _fail("signatureProtocol is not ACSP_V2")
    cert, sig, doc = status.get("cert"), status.get("signature"), (status.get("result") or {}).get("documentNumber")
    if not isinstance(cert, dict) or not cert.get("value") or not isinstance(sig, dict) or not doc:
        _fail("missing cert, signature or documentNumber")
    if sig.get("flowType") != session.flow:
        _fail("flowType differs from the offered flow")
    uc, sr = sig.get("userChallenge", ""), sig.get("serverRandom", "")
    if not isinstance(uc, str) or not _USER_CHALLENGE.match(uc):
        _fail("malformed userChallenge")
    if not isinstance(sr, str) or len(sr) < 24 or not _B64.match(sr):
        _fail("malformed serverRandom")
    if not _interaction_offered(session.interactions, status.get("interactionTypeUsed", "")):
        _fail("interactionTypeUsed was not offered")
    # 3
    if session.flow == "Web2App":
        v = callback.get("userChallengeVerifier", "")
        want = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
        if not v or not hmac.compare_digest(want, uc):
            _fail("userChallengeVerifier mismatch")
    # 4
    try:
        leaf = x509.load_der_x509_certificate(base64.b64decode(cert["value"], validate=True))
    except (ValueError, TypeError):
        _fail("cert does not parse")
    issuer = _chain(leaf, trust, now)
    if issuer is None:
        _fail("certificate chain does not verify to a configured CA")
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            _fail("end-entity certificate is a CA")
    except x509.ExtensionNotFound:
        pass
    # 5
    if not set(policy_oids) <= _policies(leaf):
        _fail("required certificate policy missing")
    # 6
    if not _auth_purpose(leaf):
        _fail("certificate is not an authentication certificate")
    # 7
    lvl = cert.get("certificateLevel")
    if LEVELS.get(lvl, 0) == 0 or LEVELS[lvl] < LEVELS[min_level]:
        _fail("certificate level below the required minimum")
    # 8
    m = _SEMANTICS.match(_attr(leaf, NameOID.SERIAL_NUMBER))
    if not m:
        _fail("subject serialNumber is not PNO/PAS/IDC")
    id_type, country, code = m.groups()
    subject = f"{id_type}{country}-{code}"
    if session.expected_identity and not hmac.compare_digest(subject, session.expected_identity):
        _fail("certificate identity differs from requested identity", "identity_mismatch")
    if not doc.startswith(subject + "-"):
        _fail("documentNumber does not belong to the certificate subject", "identity_mismatch")
    # 9
    if sig.get("signatureAlgorithm") != "rsassa-pss":
        _fail("signatureAlgorithm is not rsassa-pss")
    p = sig.get("signatureAlgorithmParameters") or {}
    h = HASHES.get(p.get("hashAlgorithm"))
    mgf = p.get("maskGenAlgorithm") or {}
    if h is None:
        _fail("unsupported hash algorithm")
    if mgf.get("algorithm") != "id-mgf1" or (mgf.get("parameters") or {}).get("hashAlgorithm") != p.get("hashAlgorithm"):
        _fail("MGF1 must use the signature hash")
    if p.get("saltLength") != h.digest_size:
        _fail("salt length must equal hash length")
    if p.get("trailerField", "0xbc") != "0xbc":
        _fail("unsupported trailer field")
    pub = leaf.public_key()
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2048:
        _fail("certificate key is not RSA-2048 or stronger")
    msg = acsp_v2_payload(session.scheme, sr, session.rp_challenge_b64, uc, session.rp_name, "", session.interactions,
                          status.get("interactionTypeUsed", ""), session.initial_callback_url, sig["flowType"])
    try:
        value = base64.b64decode(sig.get("value", ""), validate=True)
        pub.verify(value, msg, padding.PSS(mgf=padding.MGF1(h()), salt_length=h.digest_size), h())
    except (ValueError, TypeError, InvalidSignature):
        _fail("signature does not verify")
    if status_check is not None:
        status_check(leaf, issuer)
    return Identity(id_type, country, code, _attr(leaf, NameOID.GIVEN_NAME), _attr(leaf, NameOID.SURNAME), doc, lvl, sig["flowType"])
