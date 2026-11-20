# Keycloak: add eidbridge as an OpenID Connect identity provider

Configuration only; no plugin, no custom provider. Users click "eidbridge" on the Keycloak login page (or you skip the chooser with `kc_idp_hint=eidbridge`), log in with their eID at the bridge, and come back to Keycloak as a brokered user.

e2e: PASSED on 2026-11-20 against both images below (`GOTOOLCHAIN=local go test -tags e2e -count=1 -v -run TestKeycloak ./test/e2e/...`, source in `test/e2e/keycloak_test.go`).

| Keycloak | Image (tag and digest tested) |
|---|---|
| 26.8.2 (latest 26.x) | `quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3` |
| 25.0.6 (latest 25.x, no longer maintained upstream) | `quay.io/keycloak/keycloak:25.0.6@sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2` |

On 2026-11-20 there is no 27.x tag on quay.io, so 26 and 25 are the two latest majors. The same configuration worked unchanged on both.

## What the bridge needs from the relying party

PKCE with `S256` is mandatory (a request without `code_challenge` gets `invalid_request`), `state` and `nonce` are mandatory, only `response_type=code` and the scopes `openid` and `profile` are accepted, ID tokens are RS256, discovery is supported. Keycloak sends all of this when configured as below; nothing else is needed.

## 1. Register Keycloak at the bridge

Add a client to the bridge's clients file (`EIDBRIDGE_CLIENTS_FILE`):

```json
[{"client_id": "keycloak",
  "client_secret": "<40+ random characters>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://KEYCLOAK/realms/REALM/broker/eidbridge/endpoint"],
  "sub_mode": "pairwise"}]
```

The redirect URI is Keycloak's broker endpoint for the identity provider alias `eidbridge`. The bridge compares it exactly.

## 2. Create the identity provider

Admin console: Identity providers, OpenID Connect v1.0, alias `eidbridge`. Or the admin REST API, which is what the test does:

1. `POST /admin/realms/REALM/identity-provider/import-config` with `{"fromUrl": "<issuer>/.well-known/openid-configuration", "providerId": "oidc"}`. Keycloak returns `issuer`, `authorizationUrl`, `tokenUrl`, `userInfoUrl` and `jwksUrl` from discovery. `<issuer>` is the bridge's `EIDBRIDGE_ISSUER` (in the test: `http://localhost:18080/demo`).
2. `POST /admin/realms/REALM/identity-provider/instances` with `alias: eidbridge`, `providerId: oidc`, and `config` = the imported values plus:

| Setting | Value |
|---|---|
| `clientId` / `clientSecret` | the client from step 1 |
| `clientAuthMethod` | `client_secret_basic` (must match `token_endpoint_auth_method` at the bridge) |
| `pkceEnabled` / `pkceMethod` | `true` / `S256`. Mandatory. |
| `defaultScope` | `openid profile` |
| `validateSignature` / `useJwksUrl` | `true` / `true` |
| `syncMode` | `IMPORT` |
| `trustEmail` | `false` (the bridge sends no e-mail) |

Keycloak stores the federated identity as (identity provider `eidbridge`, `userId` = the `sub` claim). That is the stable link. The test checks `GET /admin/realms/REALM/users/{id}/federated-identity` returns `userId` equal to the `sub` the bridge issued (also mapped into a user attribute) and that a second login in a fresh browser session lands on the same Keycloak user.

## 3. No form on first login

The bridge supplies no e-mail address, so Keycloak's default first-broker-login flow would stop at "Update Account Information". Avoid that:

* Create a flow `eid first login` (basic-flow) containing only the execution `idp-create-user-if-unique` (`REQUIRED`), and set `firstBrokerLoginFlowAlias` of the identity provider to it. Do not add "Automatically set existing user" or "Verify existing account": they would link by e-mail or user name.
* Make the realm's user profile (`PUT /admin/realms/REALM/users/profile`) not require `email`, `firstName` and `lastName`. Declare any attribute you map (the test uses `eid_sub` and `eid_acr`) in the user profile, otherwise Keycloak 24+ drops it.
* Optional mappers on the identity provider (`oidc-user-attribute-idp-mapper`): claim `sub` to user attribute `eid_sub`, claim `acr` to `eid_acr`.

## 4. Link by `sub` only

Never link accounts by name or e-mail: the bridge does not assert an e-mail address and names are not unique. The federated identity (`eidbridge`, `sub`) is the only key. With the bridge's default `sub_mode: pairwise`, the `sub` is different per client, so a person has one Keycloak user per realm that uses a given bridge client.

## 5. Use it

Browser: `https://KEYCLOAK/realms/REALM/protocol/openid-connect/auth?client_id=APP&redirect_uri=...&response_type=code&scope=openid&kc_idp_hint=eidbridge` skips the login chooser. The e2e test drives exactly this: Keycloak, bridge login page (Smart-ID QR, auto-approved by the fixture upstream in `EIDBRIDGE_SMARTID_ENV=mock`), Keycloak broker endpoint, back to the test application with a code, code exchanged, Keycloak ID token whose `sub` is the brokered user.

## Reject demo logins in production realms

Demo-mode ID tokens carry `acr=demo` and `eid_env=demo` and come from an issuer ending in `/demo`. A production realm must never accept them:

1. Configure the identity provider with the production issuer only (no `/demo` path). Keycloak validates `iss` against the configured issuer, so demo tokens fail.
2. Add a second guard: in the identity provider's **Mappers**, map the `acr` claim to a user attribute, and in a **post login flow** add a *Conditional* step that denies access when the attribute equals `demo` (or, with the Keycloak admin REST API, set `"config": {"claimFilterName": "acr", "claimFilterValue": "^(?!demo$).*", "filteredByClaim": "true"}` on the identity provider so only tokens whose `acr` is not `demo` are accepted).
3. Link accounts by the stable `sub`, never by name or e-mail.

Tested (both images): with `filteredByClaim=true`, `claimFilterName=acr`, `claimFilterValue=^(?!demo$).*` on the identity provider, a demo login ends on a Keycloak error page (HTTP 502, "The ID token issued by the identity provider does not match the configured essential claim") and no user is created.
