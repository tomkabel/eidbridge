# Moving from Smart-ID RP API v2 to v3

The bridge supports both. Integrators see no difference: the same issuer, the same `sub` (it is derived from the person's identity, not the API version), the same claims. Only `eid_method` changes from `smartid-v2` to `smartid`.

1. Ask SK for v3 access for your relying party; v3 uses the same RP UUID in most agreements, but confirm it.
2. Run both: `EIDBRIDGE_METHODS=smartid,smartid-v2`. The login page offers both; v3 adds QR and same-device login, v2 only the notification flow.
3. Watch `eid_method` in your logs until no client depends on `smartid-v2`, then remove it from `EIDBRIDGE_METHODS` and unset `EIDBRIDGE_SMARTID_V2_*`.

What changes for users: v3 lets people log in by scanning a QR code or tapping a button on the same phone, without typing their personal code. v2 always asks for the personal code.

What v2 lacks compared with v3: device-link flows, the dynamic-link binding that stops QR relay, and the ACSP_V2 signature protocol that covers the relying-party name and interactions. Keep v2 only as long as you must.

## Authentication certificate level

Go authentication for both API versions derives the level from the certificate's
policy pair, checks that it matches `cert.certificateLevel`, and compares the
derived level with `EIDBRIDGE_SMARTID_CERT_LEVEL`. The authentication pairs in
[SK Certificate and OCSP Profile v4.8 §2.2.3](https://www.skidsolutions.eu/wp-content/uploads/2025/03/SK-CPR-SMART-ID-EN-v4_8.pdf)
are:

| Level | Required certificate policies |
|---|---|
| ADVANCED (non-qualified) | `1.3.6.1.4.1.10015.17.1` and `0.4.0.2042.1.1` |
| QUALIFIED | `1.3.6.1.4.1.10015.17.2` and `0.4.0.2042.1.2` |

Incomplete or conflicting pairs are rejected. These checks are separate from
`EIDBRIDGE_SMARTID_POLICY_OIDS`, whose entries are **all** required. Its demo
default, `1.3.6.1.4.1.10015.17.2`, rejects ADVANCED certificates even when the
minimum is ADVANCED. For a non-mock deployment, choose the separately required
policies according to your SK agreement and the certificates you intend to
accept; setting both level-specific scheme OIDs requires both and does not
provide an either/or choice. Production requires a non-empty policy list. Mock
mode overrides the list with `DemoPolicyOIDs` and issues qualified synthetic
certificates. v2 shares these settings with v3.

This policy-derived level check covers Go authentication only. Smart-ID
signing and the Python sibling paths require separate assessment.
