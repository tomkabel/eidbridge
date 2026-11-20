# Moving from Smart-ID RP API v2 to v3

The bridge supports both. Integrators see no difference: the same issuer, the same `sub` (it is derived from the person's identity, not the API version), the same claims. Only `eid_method` changes from `smartid-v2` to `smartid`.

1. Ask SK for v3 access for your relying party; v3 uses the same RP UUID in most agreements, but confirm it.
2. Run both: `EIDBRIDGE_METHODS=smartid,smartid-v2`. The login page offers both; v3 adds QR and same-device login, v2 only the notification flow.
3. Watch `eid_method` in your logs until no client depends on `smartid-v2`, then remove it from `EIDBRIDGE_METHODS` and unset `EIDBRIDGE_SMARTID_V2_*`.

What changes for users: v3 lets people log in by scanning a QR code or tapping a button on the same phone, without typing their personal code. v2 always asks for the personal code.

What v2 lacks compared with v3: device-link flows, the dynamic-link binding that stops QR relay, and the ACSP_V2 signature protocol that covers the relying-party name and interactions. Keep v2 only as long as you must.
