# Ory (Kratos and Hydra): eidbridge as an upstream login

e2e: NOT RUN - Ory Kratos v26.2.0 never sends the `nonce` parameter for a generic OIDC provider and ignores `auth_url` when `issuer_url` is set, so no Kratos configuration can add one. The bridge requires a nonce and answers `invalid_request` (observed 2026-11-20). The test in `test/e2e/ory_test.go` is skipped with that reason. Everything below the "Composition" section was therefore **not verified end to end**; the facts that were observed are marked "observed".

Images pulled on 2026-11-20 (digests are for the record; only Kratos was started, and only up to the bridge's refusal):

* `oryd/kratos:v26.2.0@sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643`
* `oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9` (not started)

## Composition: who talks to the bridge

**Hydra alone has no login UI and cannot log anybody in with the bridge.** Hydra is an OAuth 2.0 / OpenID Connect *server*: it redirects the browser to a login and consent app of yours (`urls.login`, `urls.consent`) and trusts what that app accepts. It has no concept of an upstream identity provider.

The supported composition is therefore:

* **Kratos is the relying party of the bridge.** Kratos' `oidc` method has the bridge as a provider; Kratos owns the user, the session and the federated credential.
* **Hydra is the OAuth2 server for your applications, with Kratos as its login/consent provider.** Hydra redirects the browser to your login UI with a `login_challenge`; that UI checks the Kratos session (`/sessions/whoami`), starts a Kratos login flow (with "Sign in with eidbridge") when there is none, and then accepts the Hydra login request with `subject` = the Kratos identity id.

Only the Kratos half is described as configuration below, because Kratos is what talks to the bridge. Hydra needs no bridge-specific setting.

Reachability (observed in the test setup, all containers on `--network host`): the browser must reach the Kratos public API (`http://localhost:18200`) and the bridge (`http://localhost:18080`); the Kratos container must reach the bridge issuer URL itself, for discovery, JWKS and the token request; the bridge only sees the browser's redirect back to Kratos. The issuer URL in Kratos' config must be exactly the bridge's `EIDBRIDGE_ISSUER`.

## 1. Register Kratos at the bridge

```json
[{"client_id": "kratos",
  "client_secret": "<40+ random characters>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://KRATOS_PUBLIC/self-service/methods/oidc/callback"],
  "sub_mode": "pairwise"}]
```

Observed: Kratos v26.2.0 sends `redirect_uri=<public base URL>/self-service/methods/oidc/callback` (no provider id in the path). Kratos' generic provider has no `auth_type` setting (the config schema rejects it), so it is not possible to pick `client_secret_post` or `client_secret_basic` explicitly; the token request style was not reached.

## 2. Kratos provider configuration (intended)

```yaml
selfservice:
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: eidbridge
            provider: generic
            client_id: kratos
            client_secret: <the client secret>
            issuer_url: https://BRIDGE            # = EIDBRIDGE_ISSUER; discovery at /.well-known/openid-configuration
            pkce: force                           # S256 is mandatory at the bridge
            scope: [openid, profile]
            mapper_url: base64://<jsonnet below>
  flows:
    registration: {enabled: true}                 # first login registers the identity
```

Identity schema: a trait `sub` (string, required) and optionally `name`; no e-mail trait, because the bridge sends no e-mail. Jsonnet mapper:

```jsonnet
local claims = std.extVar('claims');
{ identity: { traits: { sub: claims.sub } } }
```

What was observed with this configuration: Kratos starts, shows "Sign in with eidbridge" in the login flow, and on submitting redirects the browser to the bridge's `/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope=openid profile`, `state`, `code_challenge` and `code_challenge_method=S256`, and **no `nonce`**. The bridge redirects back with `error=invalid_request` and Kratos reports "the OpenID Provider returned error invalid_request". Setting `auth_url` next to `issuer_url` did not change the URL; with `auth_url` and `token_url` but no `issuer_url`, Kratos refuses to start the provider ("Get /.well-known/openid-configuration: unsupported protocol scheme").

The pieces after that point (credential identifier format, identity creation from the mapper, second login finding the same identity) are the intended behaviour and are **untested**. Kratos links the login to an OIDC credential keyed by provider id and subject; keep it that way and never add a mapper or flow that matches an existing identity by name or e-mail.

## Unblocking

Either of these makes the skipped test runnable (delete the `t.Skip` in `test/e2e/ory_test.go`):

* the bridge accepts authorization requests without `nonce` for configured clients (a bridge change, outside this story), or
* Kratos gains a way to add authorization parameters to the generic provider.

## Reject demo logins in production (intended, untested)

Demo-mode tokens carry `acr=demo` and `eid_env=demo` and come from an issuer ending in `/demo`.

1. Configure the production issuer only: no `/demo` issuer in `issuer_url`.
2. Make the Jsonnet mapper refuse demo identities, so Kratos aborts the login and creates no identity:

   ```jsonnet
   local claims = std.extVar('claims');
   if std.get(claims, 'eid_env', '') == 'demo' || std.get(claims, 'acr', '') == 'demo' then
     error 'demo eID logins are not accepted'
   else
     { identity: { traits: { sub: claims.sub } } }
   ```

   The test (`reject-demo` subtest) contains this mapper; it has not run.
