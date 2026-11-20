# Relying-party examples (Python)

Two minimal apps that log users in through eidbridge with a standard OIDC
client library (Authlib) and nothing else: no eID protocol code. Only
configuration: discovery URL, client id/secret, scopes (`openid profile`),
redirect URI, and PKCE S256 (the bridge rejects requests without PKCE).

- `django/django_rp.py` – Django (`authlib.integrations.django_client`)
- `fastapi/fastapi_rp.py` – FastAPI (`authlib.integrations.starlette_client`)

Routes: `/` (link), `/login`, `/callback`, `/me` (claims JSON or 401).
Accounts are keyed by `sub` only; the session never holds a personal code.
With `PRODUCTION=1` an ID token with `acr=demo`, `eid_env=demo` or an `iss`
ending in `/demo` is refused with HTTP 403.

Environment: `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
optional `OIDC_REDIRECT_URI`, `SESSION_SECRET` (FastAPI), `PRODUCTION`.

Tests build and start a real bridge with its built-in fixture upstream
(needs Go):

    pip install -r examples/django/requirements.txt -r examples/fastapi/requirements.txt
    python3 -m pytest -q examples/
