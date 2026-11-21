# eidbridge-rp

A minimal, unofficial Smart-ID RP API v3 authentication client for Python, from the [eidbridge](https://github.com/tomkabel/eidbridge) project. Not affiliated with, endorsed by or certified by SK ID Solutions.

    from eidbridge_rp import Client, verify, load_trust
    c = Client()                                   # public demo by default
    s = c.start_device_link("QR")
    print(s.qr_link())                             # render as a QR code; refresh every second
    st = c.poll(s)
    ident = verify(s, st, load_trust("trust/demo/smartid-auth-ca"))

`verify` fails closed in the same order as the bridge and raises `VerificationError` with the bridge's reason codes. Certificate status (OCSP) is left to the caller through `status_check`. If you only need login, running the bridge and an OIDC client is simpler.
