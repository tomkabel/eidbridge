# Keycloak: the eidbridge identity provider SPI

`eidbridge-keycloak` is a small Keycloak provider jar that adds an **eidbridge** identity provider type. It is the generic OpenID Connect provider with the bridge's settings preconfigured, plus one safety check enforced in code: demo-mode ID tokens are refused unless you allow them. Source: `integrations/keycloak/`. License: MIT OR Apache-2.0, like the rest of the repository. It calls only Keycloak's public classes and contains no code from Keycloak or any LGPL project.

e2e: PASSED on 2026-11-20 against both images below (`GOTOOLCHAIN=local go test -tags e2e -count=1 -run TestKeycloakSPI -v ./test/e2e/...`, source in `test/e2e/keycloak_spi_test.go`).

## What it does

* Registers the provider type `eidbridge` (it appears in the admin console's identity provider list and in `GET /admin/serverinfo` under `identityProviders`).
* **Discovery.** You give it the bridge `issuer`; it reads `<issuer>/.well-known/openid-configuration` and fills in the authorization, token, userinfo, JWKS and logout endpoints (cached for 10 minutes). Endpoints you set explicitly win.
* **Defaults.** Forced because the bridge requires or assumes them: PKCE on with `S256`, `validateSignature=true`, `useJwksUrl=true`. Defaults you may override: `syncMode=IMPORT`, `clientAuthMethod=client_secret_basic`, `defaultScope=openid profile`, `backchannelSupported=false`. The values are applied when the provider is instantiated, so a provider created through the admin API with only `issuer`, `clientId` and `clientSecret` works; the stored configuration shows only what you entered.
* **Authorization request.** Keycloak's OIDC code sends `state`, `nonce`, `response_type=code`, the scope and the PKCE challenge. The e2e test reads the redirect to the bridge and checks `nonce`, `code_challenge`, `code_challenge_method=S256`, `state` and `scope=openid profile`.
* **Identity.** The brokered user id (the federated identity `userId`) is the ID token `sub`, as in plain OIDC. Link by `sub` only, never by e-mail or name.
* **Attributes.** The provider copies three claims to *brokered user attributes* (set on the `BrokeredIdentityContext`, so the first-login flow stores them on the new user): `eid_method` to `eid_method`, `acr` to `eid_acr`, `country` to `eid_country`. Keycloak 24+ drops user attributes that the realm user profile does not declare, so declare `eid_method`, `eid_acr` and `eid_country` (and `eid_sub` if you map `sub`) in the realm's user profile. The claims are also still available to the standard *Attribute Importer* mapper (`oidc-user-attribute-idp-mapper`, claim `sub`, `acr`, `country`, ...), which you can add as usual; the e2e test uses one for `sub`.

## Install

1. Build: `mvn -q -f integrations/keycloak/pom.xml verify` (Java 17+, Maven 3.9+). The jar is `integrations/keycloak/target/eidbridge-keycloak.jar`; it targets Java 17 bytecode and is built against Keycloak 26.8.2 with all Keycloak dependencies `provided`.
2. Copy it to `/opt/keycloak/providers/` (or `$KC_HOME/providers/`).
3. Run `kc.sh build` (the official container image: build a derived image that runs it, or use `start-dev`, which builds on start), then start Keycloak.

In a container: `-v ./eidbridge-keycloak.jar:/opt/keycloak/providers/eidbridge-keycloak.jar:ro` with `start-dev` is what the e2e test does.

## Configure

Register Keycloak at the bridge exactly as in [keycloak.md](keycloak.md), step 1 (redirect URI `https://KEYCLOAK/realms/REALM/broker/eidbridge/endpoint`, `client_secret_basic`). Then, in the admin console choose Identity providers, **eidbridge**, alias `eidbridge`, and enter the issuer, client ID and client secret. Or the admin REST API:

```
POST /admin/realms/REALM/identity-provider/instances
{"alias": "eidbridge", "providerId": "eidbridge", "enabled": true,
 "firstBrokerLoginFlowAlias": "eid first login",
 "config": {"issuer": "https://id.example.com",
            "clientId": "keycloak", "clientSecret": "<secret>"}}
```

| Config key | Meaning |
|---|---|
| `issuer` | The bridge `EIDBRIDGE_ISSUER`. Used for discovery and to validate `iss`. |
| `clientId`, `clientSecret` | The client registered at the bridge. |
| `allowDemo` | `false` (default) or `true`. See below. |

The first-login flow without a form, the user profile that does not require e-mail, and linking by `sub` are the same as in [keycloak.md](keycloak.md), steps 3 and 4.

## The `allowDemo` option

Demo-mode bridges issue tokens with `acr=demo`, `eid_env=demo` and an issuer ending in `/demo`. With `allowDemo=false` (the default) the provider refuses an ID token that has **any** of these, after signature, issuer, audience and expiry checks and before Keycloak creates or links a user. The login ends on a Keycloak error page (HTTP 502, "Unexpected error when authenticating with identity provider") and the log shows `eidbridge demo ID token refused (acr is demo)` (or `eid_env is demo` / `issuer ends with /demo`). Set `allowDemo=true` only in a demo realm that talks to a demo bridge.

The rule is `DemoTokenPolicy.reject(claims, issuer, allowDemo)`, a pure function with unit tests (`mvn -q -f integrations/keycloak/pom.xml verify`: 8 tests).

The e2e test runs a full browser-style login with `allowDemo=true` (user created, federated identity `userId` equals the bridge `sub`, attributes set) and the same login with `allowDemo=false` (refused, no user created).

## Tested versions

Tested on 2026-11-20 with one jar (built against 26.8.2) loaded unchanged into both images:

| Keycloak | Image (tag and digest tested) |
|---|---|
| 26.8.2 (latest 26.x) | `quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3` |
| 25.0.6 (latest 25.x, no longer maintained upstream) | `quay.io/keycloak/keycloak:25.0.6@sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2` |

Keycloak's identity provider classes are not a stable public API; rebuild against your Keycloak version (`-Dkeycloak.version=...`) and re-run the checks when you upgrade.

## When the plain OIDC guide is enough

Most operators should use the plain OpenID Connect provider as described in [keycloak.md](keycloak.md), with the claim filter (`filteredByClaim`, `claimFilterName=acr`, `claimFilterValue=^(?!demo$).*`) to reject demo tokens. That needs no jar, no `kc.sh build` and no custom code in your Keycloak.

Use the SPI when you want:

* fewer settings to get right (PKCE `S256`, signature validation and client authentication cannot be forgotten, and discovery is automatic), or
* demo rejection enforced in code, covering `acr`, `eid_env` and the issuer suffix together, instead of a claim filter on one claim, or
* the eID claims stored as user attributes without adding mappers.

The cost is that you run a custom provider jar that must be rebuilt for Keycloak upgrades.
