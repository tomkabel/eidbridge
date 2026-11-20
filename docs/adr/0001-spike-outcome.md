# ADR 0001: Smart-ID v3 demo spike outcome

- Status: accepted (observed result)
- Date: 2026-11-20
- Story: 1.4 (FR-002), PACKET-SPIKE; architecture ADR-001
- Time used: about 25 minutes of the six-hour cap

## Decision

Device-link stays the primary method. No fallback was needed. The public demo environment works without a contract or payment, and it has a scriptable test endpoint usable in CI.

## What was run

`go run ./cmd/sidspike -mock-document PNOEE-40404040009-MOCK-Q` against `https://sid.demo.sk.ee/smart-id-rp` with the public demo relying party (`00000000-0000-4000-8000-000000000000`, `DEMO`). It exits 0 and prints:

```
AUTHENTICATED country=EE certificateLevel=QUALIFIED flowType=QR subject=[personal] chain=verified signature=verified
```

The phone step was **simulated** by SK's automated testing interface (`https://sid.demo.sk.ee/mock`, OpenAPI "Smart-ID Automated Testing Interface" 1.1.0, file `autosigner.yml`, sha256 `b832c1ae0c5f146feae114c8678d1c817fd9913d7740f9533ab01233e38e8f76` on 2026-11-20). It accepts the device link the RP built and resolves the session with a result fixed by a published test document number. No human scanned a QR with the demo app. A human demo-app run is **NOT RUN**; it is not needed for the protocol evidence, because the signature is produced by SK's demo backend over the bridge's own challenge.

`EIDBRIDGE_LIVE=1 EIDBRIDGE_CAPTURE=1 go test ./internal/smartid/ -run TestLiveCaptureFixtures -v` captured these scenarios on 2026-11-20 (fixtures in `internal/smartid/testdata/live/`):

| Scenario | Test account | Live result |
|---|---|---|
| QR, OK | `PNOEE-40404040009-MOCK-Q` | Verified: chain, purpose, level, identity, RSASSA-PSS SHA-512 signature |
| QR, refused | `PNOEE-30403039917-MOCK-Q` | `USER_REFUSED` → `refused` |
| Web2App, OK | `PNOEE-40404040009-MOCK-Q` | Verified, including `sessionSecretDigest` and `userChallengeVerifier` from the callback URL |
| Notification, OK | `PNOEE-40504040001` | Verified, including the identity match against the requested person |
| Notification, refused | `PNOEE-30403039917` | `USER_REFUSED` → `refused` |
| Notification, wrong code | `PNOEE-30403039972` | `WRONG_VC` → `failed(wrong_code)` |

## Observations (answers to the ADR-001 questions)

| Question | Observed |
|---|---|
| Protocol and profile | RP API v3, `ACSP_V2`, `rsassa-pss` with SHA-512, MGF1 SHA-512, salt 64. Docs site 3.2.8. |
| Scheme name in signed payloads | `smart-id-demo` in both the ACSP_V2 payload and the authCode payload (the signature only verifies with it). |
| QR `initialCallbackUrl` | The docs say "empty"; the live API rejects a blank value with HTTP 400 (`must not be blank`). The field must be **omitted** for QR. |
| Demo registration | None needed with the automated testing interface. Self-registering a demo-app account was not tried. |
| Scriptable CI endpoint | Yes: the automated testing interface plus SK's published test accounts. The nightly workflow can use it. |
| Certificate chain | Leaf issued by `TEST of SK ID Solutions EID-Q 2024E` (ECDSA P-384), under `TEST of SK ID Solutions ROOT G1E`. Both fetched from `http://c.sk.ee/` via AIA; stored in `trust/demo/smartid-auth-ca/` with their hashes in `trust/demo/README.md`. |
| Certificate content | RSA 6144-bit key; key usage digitalSignature only; EKU `1.3.6.1.4.1.62306.5.7.0`; policies `1.3.6.1.4.1.10015.17.2` and `0.4.0.2042.1.2`; no qcStatements extension; Subject carries `GN`, `SN` and `serialNumber=PNOEE-…`. OCSP `http://aia.demo.sk.ee/eidq2024e`; CRL `http://c.sk.ee/test_eid-q_2024e.crl`. |
| Level check | A first draft required qcStatements for `QUALIFIED`; the live demo certificate has none, so that check was removed. Level comes from `cert.certificateLevel`; it never sets `acr` above evidence (ADR-008). |
| TLS pinning | The workspace egress goes through a TLS-intercepting proxy, so the real SPKI of `sid.demo.sk.ee` could not be observed here. Pins in `trust/demo/` are therefore **unverified**; `scripts/pin-check.sh` must be run from a normal network. |
| Poll quota, session lifetime, `TIMEOUT` duration, callback replay handling | **NOT MEASURED.** The `TIMEOUT` test account was not run (it waits for the user timeout). |

## Consequences

- `internal/smartid` omits `initialCallbackUrl` for QR and uses the configured scheme name in both payloads.
- The demo policy OID `1.3.6.1.4.1.10015.17.2` is configured as the demo scheme check. It is the observed value, not SK's designated list (Q-02 stays open for production).
- Offline tests replay the captured exchanges. The fixtures contain only SK's published demo test identity and the spent secrets of completed demo sessions.
