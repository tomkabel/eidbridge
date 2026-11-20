"""Minimal, unofficial Smart-ID RP API v3 authentication client.

Not affiliated with, endorsed by or certified by SK ID Solutions. It
implements the published RP API v3 (ACSP_V2) and fails closed on every
verification step. See verify.verify() for the order.
"""

from .client import Client, Session, DEMO_BASE_URL, DEMO_RP_UUID, DEMO_RP_NAME, SCHEME_DEMO
from .verify import Identity, VerificationError, verify, load_trust, DEMO_POLICY_OIDS

__all__ = ["Client", "Session", "Identity", "VerificationError", "verify", "load_trust",
           "DEMO_BASE_URL", "DEMO_RP_UUID", "DEMO_RP_NAME", "SCHEME_DEMO", "DEMO_POLICY_OIDS"]
__version__ = "0.1.0"
