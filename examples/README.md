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

For the Django example, create a virtual environment, install its requirements,
and configure a unique secret and the bridge credentials. From the repository
root, for example:

    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r examples/django/requirements.txt
    cd examples/django
    export DJANGO_SETTINGS_MODULE=django_settings
    export DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
    export OIDC_DISCOVERY_URL="http://localhost:8080/.well-known/openid-configuration"
    export OIDC_CLIENT_ID="your-client-id"
    export OIDC_CLIENT_SECRET="your-client-secret"
    export OIDC_REDIRECT_URI="http://localhost:8000/callback"
    python -m django migrate
    python -m django runserver

Set the OIDC values to match your bridge and registered client. Django stores
sessions server-side in `examples/django/sessions.sqlite3` by default; set
`DJANGO_SESSION_DB` to choose another SQLite file before running migrations.
Keep the secret stable across restarts so existing sessions remain valid, and
keep both the secret and session database private. The generated key above is
for local use; provide a securely managed, unique deployment key in production.
This minimal example is not production configuration: use an appropriate
shared production database for multiple instances, HTTPS and secure cookies,
restrict allowed hosts, and configure session expiry and cleanup (including
periodic `python -m django clearsessions`).

From the repository root, tests build and start a real bridge with its built-in
fixture upstream (needs Go):

    pip install -r examples/django/requirements.txt -r examples/fastapi/requirements.txt
    python3 -m pytest -q examples/
