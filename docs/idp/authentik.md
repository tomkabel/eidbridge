# authentik: add eidbridge as an OAuth/OpenID Connect source

Configuration only. In authentik the bridge is an **OAuth Source** of type OpenID Connect; users click "eidbridge" on the login page or open `/source/oauth/login/eidbridge/`.

e2e: PASSED on 2026-11-20 (`GOTOOLCHAIN=local go test -tags e2e -count=1 -v -run TestAuthentik ./test/e2e/...`, source in `test/e2e/authentik_test.go`; about 160 s because of the cold start).

Images tested:

* `ghcr.io/goauthentik/server:2026.8.6@sha256:da89d8338a3b1889800eb033fd61f8d43f7aa9a1c5a042cb5e03d891b1f0c56c` (latest 2026.8.x on ghcr.io on 2026-11-20), run twice: `server` and `worker`. The worker is required: it applies the blueprints that create the default flows, and without it the API has no `default-source-*` flows.
* `postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32` (authentik 2026.8 needs no Redis).

## Known interoperability point: authentik sends no `nonce`

The bridge requires `nonce`. authentik's OpenID Connect source never sends one (observed: the authorization request had `client_id`, `redirect_uri`, `response_type`, `state`, `code_challenge`, `code_challenge_method`, `scope` and the bridge answered `error=invalid_request`). authentik merges query parameters of the configured authorization URL into the request, so the working configuration puts a fixed nonce there:

```
authorization_url = https://BRIDGE/authorize?nonce=authentik-sends-no-nonce
```

Consequence: the nonce gives no replay protection for this client (authentik does not check it either). CSRF and code-injection protection still come from `state` and PKCE S256, which authentik does send. Remove the workaround if a later authentik version sends a nonce.

authentik adds the scope `email` by default, which the bridge rejects. Set `additional_scopes` to `*openid profile`: the leading `*` replaces the defaults instead of adding to them.

## 1. Register authentik at the bridge

```json
[{"client_id": "authentik",
  "client_secret": "<40+ random characters>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://AUTHENTIK/source/oauth/callback/eidbridge/"],
  "sub_mode": "pairwise"}]
```

## 2. Create the source (API, as the test does)

All calls use `Authorization: Bearer <API token>` against `https://AUTHENTIK/api/v3`.

1. A source property mapping, `POST /propertymappings/source/oauth/`. The bridge sends no `preferred_username` and no e-mail, so the user name must come from `sub`:

   ```python
   return {"username": info["sub"], "name": info.get("name") or info["sub"]}
   ```

   (`info` is the bridge's `/userinfo` response.)
2. An enrollment flow without prompts (the stock `default-source-enrollment` asks the person to pick a user name): `POST /flows/instances/` (`slug: eidbridge-enrollment`, `designation: enrollment`), a User Write stage (`user_creation_mode: always_create`) and a User Login stage, bound to the flow at orders 10 and 20 with `POST /flows/bindings/`.
3. The source, `POST /sources/oauth/`:

| Field | Value |
|---|---|
| `slug` / `name` | `eidbridge` (the slug is part of the callback URL) |
| `provider_type` | `openidconnect` |
| `consumer_key` / `consumer_secret` | the client from step 1 |
| `oidc_well_known_url` | `<issuer>/.well-known/openid-configuration` |
| `authorization_url` | `<issuer>/authorize?nonce=authentik-sends-no-nonce` (see above) |
| `access_token_url`, `profile_url`, `oidc_jwks_url` | `<issuer>/token`, `<issuer>/userinfo`, `<issuer>/jwks.json` |
| `additional_scopes` | `*openid profile` |
| `pkce` | `S256`. Mandatory. |
| `authorization_code_auth_method` | `basic_auth` (client_secret_basic) |
| `user_matching_mode` | `identifier` |
| `user_property_mappings` | the mapping from step 1 |
| `authentication_flow` | `default-source-authentication` |
| `enrollment_flow` | `eidbridge-enrollment` |

`<issuer>` is the bridge's `EIDBRIDGE_ISSUER` (in the test: `http://localhost:18080/demo`).

## 3. Link by `sub` only

`user_matching_mode: identifier` is the only safe choice: authentik links the login to the user connection whose identifier is the `sub`, and otherwise enrolls a new user. Never use `email_link`, `email_deny`, `username_link` or `username_deny`: the bridge sends no e-mail and names are not unique.

Tested: after the first login `GET /sources/user_connections/oauth/?source__slug=eidbridge` has exactly one connection whose `identifier` equals the user name (the bridge `sub`), the browser session's `GET /api/v3/core/users/me/` returns that user, and a second login in a fresh browser session signs in as the same user without creating another.

## Reject demo logins in production

Demo-mode tokens carry `acr=demo` and `eid_env=demo` and come from an issuer ending in `/demo`.

1. Configure the production issuer only: no `/demo` URLs in the source. The production bridge does not serve `/demo`.
2. Add a guard to the property mapping so that a demo identity is never enrolled or signed in. The bridge's userinfo carries `eid_env=demo` in demo mode:

   ```python
   if info.get("eid_env") == "demo" or info.get("acr") == "demo":
       raise Exception("demo eID logins are not accepted")
   return {"username": info["sub"], "name": info.get("name") or info["sub"]}
   ```

Tested: with the guarded mapping a demo login is refused (authentik shows its generic "Server Error" page, HTTP 500) and no user is created. The refusal is an exception, not a friendly message.

## Limits of this test

The test drives authentik's flow executor API the way the web UI does (challenge, answer, redirect) instead of running a JavaScript browser. The final redirect is `/if/user/`.
