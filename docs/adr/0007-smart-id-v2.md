# ADR 0007: Legacy Smart-ID RP API v2

- Status: accepted (owner override 2026-11-20; the original gate was a named relying party that cannot move to v3)
- Date: 2026-11-20
- Story: 7.5; FR-029

## Specification pin

SK-EID/smart-id-documentation, branch `v2`, commit `eef0a77dafadc8128b97e46b129218c82d85d2b6` (2020-11-24), `README.md` sha256 `14c907bbccea1635ecd945c7d49b6cab17ff145b3ab38a4605d62c79d2fb55c7`, read 2026-11-20. Sections 2.3.9 (authentication), 2.3.11 (session status), 2.3.12 (protocol usage, verification code, response verification).

## Decisions

- Method name `smartid-v2`, notification flow only (v2 has no device link). It is a separate method behind the same issuer so a deployment can run v2 and v3 side by side while clients migrate.
- Hash: SHA-512 of 64 random bytes; the bridge always requests SHA-512 and accepts only `sha512WithRSAEncryption`.
- The verification order follows §2.3.12.3 and adds the v3 package's purpose and policy checks and a document-number ownership check.
- Host, pins, trust, status and certificate level come from the Smart-ID settings; only the relying party is separate (`EIDBRIDGE_SMARTID_V2_RP_UUID`, `_RP_NAME`). The bridge logs a legacy warning at startup.

## Evidence and gaps

- Live 2026-11-20 against `sid.demo.sk.ee/smart-id-rp/v2`: OK and USER_REFUSED, captured as replay fixtures.
- No production v2 run; the original gate (a named relying party that needs v2) is unmet.
