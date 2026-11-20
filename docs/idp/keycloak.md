# Keycloak: add eidbridge as an OpenID Connect identity provider

Configuration only; no plugin. The full tested guide with versions is completed by Story 3.5.

## Reject demo logins in production realms

Demo-mode ID tokens carry `acr=demo` and `eid_env=demo` and come from an issuer ending in `/demo`. A production realm must never accept them:

1. Configure the identity provider with the production issuer only (no `/demo` path). Keycloak validates `iss` against the configured issuer, so demo tokens fail.
2. Add a second guard: in the identity provider's **Mappers**, map the `acr` claim to a user attribute, and in a **post login flow** add a *Conditional* step that denies access when the attribute equals `demo` (or, with the Keycloak admin REST API, set `"config": {"claimFilterName": "acr", "claimFilterValue": "^(?!demo$).*", "filteredByClaim": "true"}` on the identity provider so only tokens whose `acr` is not `demo` are accepted).
3. Link accounts by the stable `sub`, never by name or e-mail.
