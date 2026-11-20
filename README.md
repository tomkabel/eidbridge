# eidbridge

[![CI](https://github.com/tomkabel/eidbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/tomkabel/eidbridge/actions/workflows/ci.yml)

Self-hosted Go bridge from the Smart-ID RP API v3 to OpenID Connect. Unofficial and operator-controlled. No telemetry and no persistent personal authentication state by default.

> **Unofficial, community-maintained software. Not affiliated with, endorsed by or certified by the operators of Smart-ID, Mobile-ID, the Estonian ID-card or any EUDI Wallet.** Scheme names describe compatibility only and imply no endorsement, certification, assurance level or qualified trust-service status. Production use needs your own relying-party agreement with the scheme operator. See [legal stance](docs/legal.md).

**Status: pre-release.** Code exists on the `feat/full-build` branch; nothing is released or published. No external security review has been done. See the [project overview](docs/project-overview.md) and the [planning index](_bmad-output/planning-artifacts/README.md).

## Documentation

- [Legal stance and clean-room rules](docs/legal.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)
- [Security design and logging](docs/security.md) · [Personal data flow (for DPIAs)](docs/data-flow.md)
- [Configuration reference](docs/configuration.md) · [Maintenance runbook](docs/api-tracking.md) · [Changelog](CHANGELOG.md)
- IdP guides: [Keycloak](docs/idp/keycloak.md)
- [Implementation architecture](docs/architecture.md) · [Decision records](docs/adr/)

Security issues: see [SECURITY.md](SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. See [NOTICE](NOTICE).
