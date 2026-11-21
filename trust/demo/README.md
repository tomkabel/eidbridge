# Demo trust (sid.demo.sk.ee, tsp.demo.sk.ee, test ID-cards)

Public demo environment only. Production mode refuses every file here.

| File | Subject | Source | sha256 (DER) | Retrieved |
|---|---|---|---|---|
| `smartid-auth-ca/TEST_SK_ROOT_G1_2021E.pem` | TEST of SK ID Solutions ROOT G1E | http://c.sk.ee/TEST_SK_ROOT_G1_2021E.der.crt | 84242dd8e1a1878f76ff2b5ca0c8ef22c8a8863cf072e56a9f0dc28add96b143 | 2026-11-20 |
| `smartid-auth-ca/TEST_EID-Q_2024E.pem` | TEST of SK ID Solutions EID-Q 2024E | http://c.sk.ee/TEST_EID-Q_2024E.der.crt | 063a4e908785a2b45fba27a22d45d9f2bbaa9a382e5b103e1d1036832cee6ac2 | 2026-11-20 |
| `mobileid-auth-ca/TEST_SK_ROOT_G1_2021E.pem` | TEST of SK ID Solutions ROOT G1E (copy) | http://c.sk.ee/TEST_SK_ROOT_G1_2021E.der.crt | 84242dd8e1a1878f76ff2b5ca0c8ef22c8a8863cf072e56a9f0dc28add96b143 | 2026-11-20 |
| `webeid-ca/TEST_of_EE-GovCA2018.pem` | TEST of EE-GovCA2018 | https://www.skidsolutions.eu/upload/files/TEST_of_EE-GovCA2018.der.crt | e4c92e1146e0123cab3c8f69d0831ecac89869b40d6a59d4107f5bbc916f09e2 | 2026-11-20 |
| `webeid-ca/TEST_of_ESTEID2018.pem` | TEST of ESTEID2018 (test ID-cards) | https://www.skidsolutions.eu/upload/files/TEST_of_ESTEID2018.der.crt | 2291c167b5275152b53f1efa2c1805c9a15ec8def7120e56a3726a2959b31049 | 2026-11-20 |
| `mobileid-auth-ca/TEST_EID-Q_2021E.pem` | TEST of SK ID Solutions EID-Q 2021E | http://c.sk.ee/TEST_EID-Q_2021E.der.crt (AIA of the demo Mobile-ID certificate) | 994477a5a63d1087bbcfa0d6721c401c8e1a778987503b0e202777b3c3cb1ff6 | 2026-11-20 |

`smartid-host.txt` names the RP API host. Mobile-ID demo numbers on the older "TEST of EID-SK 2016" chain are not trusted here. `smartid-tls-pins.txt` is intentionally absent until a pin is observed from a network without TLS interception (see `docs/adr/0001-spike-outcome.md`); demo mode then runs with `EIDBRIDGE_SMARTID_TLS_PINS=disabled` and a warning.
