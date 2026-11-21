# Security policy

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/tomkabel/eidbridge/security/advisories/new). Do not open a public issue or post credentials, session data or personal data.

## Supported versions

Pre-release: no version is released yet. After the first release, fixes ship in the latest minor release, and TLS pin and CA fixes are backported one minor release if it is maintained (subject to maintainer capacity; there is no paid SLA).

## Response targets

Best effort by a volunteer maintainer: acknowledgement within 5 working days, an assessment within 15 working days. These are targets, not commitments.

## Scope

The bridge code, its container image and its documentation. The eID services themselves, wallets and client IdPs are out of scope; report issues there to their operators.

Details of the security design, logging and key procedures: [docs/security.md](docs/security.md). Personal data handling: [docs/data-flow.md](docs/data-flow.md).
