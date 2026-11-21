# Legal stance, trademarks and clean-room rules

This page states what eidbridge is and is not. It is project policy, not legal advice. Material questions belong with qualified counsel in the integrator's own jurisdiction.

## Unofficial project

eidbridge is unofficial, community-maintained software. It is not affiliated with, endorsed by or certified by the operators of Smart-ID, Mobile-ID, the Estonian ID-card, Web eID or any EUDI Wallet. The same notice appears in the README, in the footer of every login page and in the container image label `org.opencontainers.image.description`.

## Names and marks

- Scheme names are used only to describe compatibility, for example "compatible with Smart-ID RP API v3".
- No scheme logos, brand colors or user interface imitating a scheme app.
- Scheme names never appear in package, image or module names. The project names are `eidbridge` and `eidbridge-rp`.
- If a trademark holder objects, the project complies first (rename or rewording) and discusses afterwards.

## What the bridge is

- Toward an eID scheme, the bridge is an ordinary relying party. Toward the integrator's applications, it is an OpenID Connect provider. It is not a scheme-certified identity provider, a qualified trust service or a signature-creation device.
- Production use needs the integrator's own relying-party agreement with the scheme operator. The project ships no production credentials and does not broker, resell or meter transactions.
- The bridge does not confer eIDAS, EUDI Wallet or any other regulatory compliance on the integrator's service. Method names and certificate levels are not presented as legally established assurance levels.
- Demo mode uses public demo environments and test accounts. A demo login proves nothing about a real person.
- Signing sessions (when enabled) relay a digest and verify the returned signature. The bridge makes no claim of qualified electronic signature status.

## Data protection roles

The integrator running the bridge decides why and how logins are processed. The project authors receive no data: there is no telemetry and no default persistence (see [data flow](data-flow.md) and [security](security.md)). Anyone hosting the bridge for third parties takes on their own data-protection role and obligations. The project issues no completed legal assessment or universal role determination.

## Clean-room implementation

- Implement from published protocol specifications and RFCs.
- Do not copy code from LGPL-licensed demo applications or from documentation repositories without a license. Link to them; do not vendor them.
- Code samples printed in vendor documentation are not reused. Published example values may be used as known-answer test vectors, with the source URL recorded.
- MIT- or Apache-licensed official client code may be reused only with its notice preserved in [NOTICE](../NOTICE).
- `docs/spec-pins/` stores URL, version, retrieval date, hash and license metadata only, never harvested specification text. CI enforces this with `scripts/check_spec_pins.py`.
- Every dependency must have a permissive license compatible with MIT/Apache-2.0 distribution; CI runs a license check. The WordPress example plugin, if shipped, is GPL-2.0-or-later as WordPress requires and lives in its own directory.

These guardrails reduce risk. They are not legal clearance.

## Contributions

Contributions require a Developer Certificate of Origin sign-off (`git commit -s`). See [CONTRIBUTING](../CONTRIBUTING.md).
