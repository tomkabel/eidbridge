"""Minimal FastAPI relying party for eidbridge. Plain OIDC via Authlib: no eID code.

Run: OIDC_DISCOVERY_URL=... OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... \
     uvicorn --factory fastapi_rp:create_app
"""
import html
import os

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

REFUSAL = "demo identities are refused in production"


def is_demo(claims):
    return (claims.get("acr") == "demo" or claims.get("eid_env") == "demo"
            or str(claims.get("iss", "")).endswith("/demo"))


def create_app():
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", os.urandom(32).hex()))
    oauth = OAuth()
    oauth.register(
        "bridge",
        server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        client_kwargs={"scope": "openid profile", "code_challenge_method": "S256",
                       "token_endpoint_auth_method": "client_secret_basic"},
    )

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return '<a href="/login">Log in with eID</a>'

    @app.get("/login")
    async def login(request: Request):
        redirect_uri = os.environ.get("OIDC_REDIRECT_URI") or str(request.url_for("callback"))
        return await oauth.bridge.authorize_redirect(request, redirect_uri)

    @app.get("/callback")
    async def callback(request: Request):
        # RFC 9207: check the issuer before sending the code anywhere (mix-up defence).
        meta = await oauth.bridge.load_server_metadata()
        if request.query_params.get("iss") != meta["issuer"]:
            return HTMLResponse("issuer mismatch", status_code=400)
        try:
            token = await oauth.bridge.authorize_access_token(request)  # verifies state, PKCE, ID token
        except OAuthError as e:
            return HTMLResponse(f"login failed: {html.escape(str(e))}", status_code=400)
        claims = dict(token["userinfo"])
        if os.environ.get("PRODUCTION") == "1" and is_demo(claims):
            return HTMLResponse(REFUSAL, status_code=403)
        request.session.clear()
        request.session["sub"] = claims["sub"]  # account key: sub only
        request.session["claims"] = claims
        return HTMLResponse(f"<p>Logged in. Account key (sub): <code>{html.escape(claims['sub'])}</code></p>"
                            f"<pre>{html.escape(str(claims))}</pre>")

    @app.get("/me")
    async def me(request: Request):
        if "sub" not in request.session:
            return JSONResponse({"error": "not logged in"}, status_code=401)
        return request.session["claims"]

    return app
