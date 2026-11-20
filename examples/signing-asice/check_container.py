#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Structural check of an ASiC-E / XAdES container without DSS.

Checks, using only the zip module plus lxml and cryptography:
  1. first zip entry is `mimetype`, stored (not compressed), with the ASiC-E media type;
  2. META-INF/manifest.xml and META-INF/signatures*.xml exist;
  3. each ds:Reference over a data object: recompute SHA-256/384/512 of the entry and
     compare with DigestValue; the SignedProperties reference is recomputed over the
     canonicalised element;
  4. the RSASSA-PSS SignatureValue over the canonicalised SignedInfo, verified with the
     key of the embedded signing certificate (MGF1 with the same hash, salt = hash length).

This is a consistency check by a second, independent implementation of the pieces it covers.
It is NOT a full XAdES validator: no certificate chain, validity period, key usage,
policy or signed-properties semantics are evaluated.

Usage: check_container.py FILE.asice        exit 0 = all checks passed, 1 = a check failed
"""
import base64
import hashlib
import sys
import urllib.parse
import zipfile

from lxml import etree

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:  # pragma: no cover
    x509 = None

DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
HASHES = {
    "http://www.w3.org/2001/04/xmlenc#sha256": ("sha256", hashes.SHA256 if x509 else None),
    "http://www.w3.org/2001/04/xmldsig-more#sha384": ("sha384", hashes.SHA384 if x509 else None),
    "http://www.w3.org/2001/04/xmlenc#sha512": ("sha512", hashes.SHA512 if x509 else None),
}
C14N = {
    "http://www.w3.org/2001/10/xml-exc-c14n#": dict(exclusive=True, with_comments=False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": dict(exclusive=True, with_comments=True),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": dict(exclusive=False, with_comments=False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": dict(exclusive=False, with_comments=True),
}
ASICE_TYPE = b"application/vnd.etsi.asic-e+zip"

failures = []


def ok(msg):
    print("ok   " + msg)


def bad(msg):
    print("FAIL " + msg)
    failures.append(msg)


def c14n(el, alg):
    kw = C14N.get(alg)
    if kw is None:
        raise ValueError("unsupported canonicalisation " + alg)
    return etree.tostring(el, method="c14n", **kw)


def main(path):
    zf = zipfile.ZipFile(path)
    infos = zf.infolist()

    # 1. mimetype first and stored
    if infos and infos[0].filename == "mimetype":
        ok("first entry is mimetype")
    else:
        bad("first entry is not mimetype: %r" % (infos[0].filename if infos else None))
    if "mimetype" in zf.namelist():
        mi = zf.getinfo("mimetype")
        if mi.compress_type == zipfile.ZIP_STORED:
            ok("mimetype is stored uncompressed")
        else:
            bad("mimetype is compressed (method %d)" % mi.compress_type)
        if zf.read("mimetype") == ASICE_TYPE:
            ok("mimetype content is application/vnd.etsi.asic-e+zip")
        else:
            bad("mimetype content is %r" % zf.read("mimetype"))

    # 2. required META-INF parts
    names = zf.namelist()
    if "META-INF/manifest.xml" in names:
        ok("META-INF/manifest.xml present")
    else:
        bad("META-INF/manifest.xml missing")
    sigs = [n for n in names if n.startswith("META-INF/signatures") and n.endswith(".xml")]
    if sigs:
        ok("signature files: " + ", ".join(sigs))
    else:
        bad("no META-INF/signatures*.xml")

    for sname in sigs:
        check_signature(zf, sname)

    if failures:
        print("RESULT: %d check(s) failed" % len(failures))
        return 1
    print("RESULT: all checks passed")
    return 0


def check_signature(zf, sname):
    root = etree.fromstring(zf.read(sname))
    for sig in root.iter("{%s}Signature" % DS):
        signed_info = sig.find("{%s}SignedInfo" % DS)
        c_alg = signed_info.find("{%s}CanonicalizationMethod" % DS).get("Algorithm")
        sm_alg = signed_info.find("{%s}SignatureMethod" % DS).get("Algorithm")
        print("     %s: canonicalisation %s, signature method %s" % (sname, c_alg, sm_alg))

        # 3. reference digests
        for ref in signed_info.findall("{%s}Reference" % DS):
            uri = ref.get("URI") or ""
            dm = ref.find("{%s}DigestMethod" % DS).get("Algorithm")
            want = base64.b64decode(ref.find("{%s}DigestValue" % DS).text)
            hname = HASHES.get(dm, (None, None))[0]
            if hname is None:
                bad("reference %s: unsupported digest %s" % (uri, dm))
                continue
            if uri.startswith("#"):
                target = sig.xpath("//*[@Id=$i]", i=uri[1:])
                if not target:
                    bad("reference %s: target element not found" % uri)
                    continue
                # Local fragment: apply the declared transforms (canonicalisation only).
                alg = c_alg
                for t in ref.findall("{%s}Transforms/{%s}Transform" % (DS, DS)):
                    if t.get("Algorithm") in C14N:
                        alg = t.get("Algorithm")
                data = c14n(target[0], alg)
                label = "signed properties %s" % uri
            else:
                entry = urllib.parse.unquote(uri)
                if entry not in zf.namelist():
                    bad("reference %s: no such zip entry" % entry)
                    continue
                data = zf.read(entry)
                label = "data object %s" % entry
            got = hashlib.new(hname, data).digest()
            if got == want:
                ok("%s digest matches DigestValue (%s)" % (label, hname))
            else:
                bad("%s digest differs: recomputed %s, in XAdES %s" % (label, got.hex(), want.hex()))

        # 4. signature value
        verify_signature_value(sig, signed_info, c_alg, sm_alg)


def verify_signature_value(sig, signed_info, c_alg, sm_alg):
    if x509 is None:
        print("skip SignatureValue check: `cryptography` package not available")
        return
    if "mgf1" not in sm_alg.lower() and "rsa-pss" not in sm_alg.lower():
        print("skip SignatureValue check: signature method %s is not RSASSA-PSS" % sm_alg)
        return
    cert_el = sig.find(".//{%s}X509Certificate" % DS)
    sv = sig.find("{%s}SignatureValue" % DS)
    if cert_el is None or sv is None:
        bad("no X509Certificate or SignatureValue in the signature")
        return
    cert = x509.load_der_x509_certificate(base64.b64decode("".join(cert_el.text.split())))
    sig_bytes = base64.b64decode("".join(sv.text.split()))
    dm = signed_info.find("{%s}SignatureMethod/{*}DigestMethod" % DS)
    hash_cls = hashes.SHA256
    if dm is not None and dm.get("Algorithm") in HASHES:
        hash_cls = HASHES[dm.get("Algorithm")][1]
    elif "sha384" in sm_alg:
        hash_cls = hashes.SHA384
    elif "sha512" in sm_alg:
        hash_cls = hashes.SHA512
    h = hash_cls()
    try:
        cert.public_key().verify(
            sig_bytes,
            c14n(signed_info, c_alg),
            padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=h.digest_size),
            hash_cls(),
        )
        ok("RSASSA-PSS SignatureValue verifies over canonical SignedInfo (%s, salt %d)" % (h.name, h.digest_size))
    except InvalidSignature:
        bad("RSASSA-PSS SignatureValue does NOT verify over canonical SignedInfo")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
