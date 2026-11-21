# Offline mock RP API (`eidbridge-mock`)

A Smart-ID RP API v3 stand-in for tests and demos with no network. Responses are signed by a test CA generated at start. Identities are SK's published demo test codes (`PNOEE-40404040009-MOCK-Q` and friends): test data, never real people.

    go run ./cmd/eidbridge-mock --listen 127.0.0.1:8090 --ca-out /tmp/mock-ca/ca.pem

Then point the bridge at it (demo mode only):

    EIDBRIDGE_SMARTID_ENV=mock \
    EIDBRIDGE_SMARTID_BASE_URL=http://127.0.0.1:8090/smart-id-rp \
    EIDBRIDGE_SMARTID_AUTH_CA_DIR=/tmp/mock-ca \
    eidbridge serve --demo

Without `EIDBRIDGE_SMARTID_BASE_URL` on a loopback http address, `EIDBRIDGE_SMARTID_ENV=mock` runs the same server inside the bridge (used by the compose demo and the test suites).

## Control API

| Request | Effect |
|---|---|
| `GET /_mock/sessions` | `{"pending": [ids]}` of sessions not yet resolved |
| `POST /_mock/sessions/{id}/complete[?document=…]` | approve (any scenario document whose result is `OK`) |
| `POST /_mock/sessions/{id}/refuse` | `USER_REFUSED` |
| `POST /_mock/sessions/{id}/timeout` | `TIMEOUT` |
| `POST /_mock/sessions/{id}/wrong-vc` | `WRONG_VC` |

SK's automated testing interface (`/smart-id-rp/v3/mock/device-link`) is also served, so scripts written for the public demo work.

## Options

| Flag | Meaning |
|---|---|
| `--listen` | Address; non-loopback addresses are refused unless `--allow-remote` |
| `--ca-out` | Write the test root and issuing CA (PEM) |
| `--scenario` | YAML map `document → endResult` added to the defaults |
| `--auto` | Resolve device-link sessions with this document on first poll |
