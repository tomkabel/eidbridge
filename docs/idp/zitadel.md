# Zitadel: add eidbridge as an identity provider

Configuration only. In Zitadel the bridge is a **generic OAuth 2.0 identity provider**, not the generic OIDC one (see below).

e2e: PASSED on 2026-11-20 (`GOTOOLCHAIN=local go test -tags e2e -count=1 -v -run TestZitadel ./test/e2e/...`, source in `test/e2e/zitadel_test.go`).

Images tested:

* `ghcr.io/zitadel/zitadel:v4.20.5@sha256:cb21fe73badfe44972bb24a66cf0ebce6a8dc63ab8ed24567af6b731bd8bbf45` (the `latest` tag on 2026-11-20).
* `postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32`.

## What was and was not tested

The test drives the **IdP intent API and the Session API** (`/v2/idp_intents`, `/v2/sessions`): Zitadel returns the bridge authorization URL, the browser (test driver) logs in at the bridge and returns through Zitadel's `/idps/callback`, and a Zitadel session is created from the intent. These are the calls the Zitadel login UI (login v2) makes, so the broker path is the real one. It is not a click-through of Zitadel's hosted login pages:

* Login v2 is a separate container (`zitadel-login`) driven by Next.js server actions; it is not part of this test.
* Login v1 on this version failed in the sandbox (`/ui/login/login` returned Zitadel's "An internal error occurred (RECOVER)" page with `loginV2` set to not required), so it was not used.

## Known interoperability points

1. **No nonce from the OIDC provider type.** Zitadel's generic OIDC provider sends no `nonce` (observed: authorization request with `prompt=select_account`, PKCE and `state`, no `nonce`, answered by the bridge with `error=invalid_request`). The OAuth 2.0 provider type takes the endpoints verbatim, so a fixed nonce goes into the authorization endpoint URL: `https://BRIDGE/authorize?nonce=zitadel-sends-no-nonce`. The nonce then gives no replay protection for this client; `state` and PKCE S256 still apply. Zitadel does not read the ID token in this mode; it takes the identity from `/userinfo`.
2. **Zitadel refuses to call loopback addresses by default** (`ZITADEL_HTTPCLIENT_DENYLIST` includes `127.0.0.0/8`, `localhost`, private ranges). In the test the bridge runs on localhost, so the container is started with `ZITADEL_HTTPCLIENT_DENYLIST=169.254.0.0/16` and `ZITADEL_HTTPCLIENT_ALLOWHTTPSDOWNGRADE=true`. In production the bridge is a public HTTPS host and the default list stays.
3. Zitadel needs an e-mail address to create a human user; the bridge sends none. The test uses a non-routable placeholder (`<16 chars of sub>@eidbridge.invalid`, unverified). Do not use that address for anything.

## 1. Register Zitadel at the bridge

```json
[{"client_id": "zitadel",
  "client_secret": "<40+ random characters>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://ZITADEL/idps/callback"],
  "sub_mode": "pairwise"}]
```

The redirect URI Zitadel 4.20.5 sent was `<external origin>/idps/callback`. The token exchange succeeded with the client registered as `client_secret_basic`.

## 2. Create the identity provider

`POST /admin/v1/idps/oauth` (instance level; `Authorization: Bearer <PAT>`), then activate it with `POST /admin/v1/policies/login/idps` (`ownerType: IDP_OWNER_TYPE_SYSTEM`):

| Field | Value |
|---|---|
| `name` | `eidbridge` |
| `clientId` / `clientSecret` | the client from step 1 |
| `authorizationEndpoint` | `<issuer>/authorize?nonce=zitadel-sends-no-nonce` |
| `tokenEndpoint` | `<issuer>/token` |
| `userEndpoint` | `<issuer>/userinfo` |
| `scopes` | `["openid", "profile"]` |
| `idAttribute` | `sub`. The stable user id. |
| `usePkce` | `true`. Mandatory (Zitadel uses S256). |
| `providerOptions.isLinkingAllowed` | `false` |
| `providerOptions.isCreationAllowed` | `true` |
| `providerOptions.isAutoCreation` | `false` (create users deliberately, see step 3) |
| `providerOptions.isAutoUpdate` | `false` |
| `providerOptions.autoLinking` | leave unset. Never link by e-mail or user name. |

`<issuer>` is the bridge's `EIDBRIDGE_ISSUER` (in the test: `http://localhost:18080/demo`).

## 3. Log in and link by `sub`

1. `POST /v2/idp_intents` with `{"idpId": ..., "urls": {"successUrl": ..., "failureUrl": ...}}` returns `authUrl` (the bridge authorize URL). Send the browser there.
2. After the bridge login Zitadel redirects to `successUrl?id=...&token=...` and, if the identity is already linked, `&user=<zitadel user id>`.
3. `POST /v2/idp_intents/{id}` with `{"idpIntentToken": ...}` returns `idpInformation.userId` (the bridge `sub`) and `idpInformation.rawInformation.RawInfo` (the userinfo claims).
4. First login (no `user` in the redirect): `POST /v2/users/human` with `idpLinks: [{"idpId": ..., "userId": "<sub>", "userName": "<sub>"}]`. The link key is the `sub`.
5. Create the session: `POST /v2/sessions` with `checks.user.userId` and `checks.idpIntent.{idpIntentId, idpIntentToken}`.

Tested: the session's `factors.user.id` is the created user and `factors.intent.verifiedAt` is set; a second login returns `user=<same id>` in the redirect and signs in without creating a user; `POST /v2/users/{id}/links/_search` shows exactly one link whose `userId` is the bridge `sub`.

## Reject demo logins in production

Demo-mode tokens carry `acr=demo` and `eid_env=demo` and come from an issuer ending in `/demo`.

1. Configure the production issuer only: no `/demo` URLs in the provider.
2. Zitadel has no per-provider claim filter, so enforce it where the intent is consumed: refuse to create the user or session when `idpInformation.rawInformation.RawInfo.eid_env == "demo"` (or `acr == "demo"`). The test asserts that the demo bridge's claims carry `eid_env=demo`, which is what such a check keys on. This guard is not enforced by Zitadel itself in this setup; it belongs in your login service.
