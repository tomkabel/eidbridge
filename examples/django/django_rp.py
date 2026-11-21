"""Minimal Django relying party for eidbridge. Plain OIDC via Authlib: no eID code.

See examples/README.md for local setup, migrations and startup.
(this module is the URLconf; call configure() once, or import it after the env is set)
"""
import html
import os

from authlib.integrations.django_client import OAuth, OAuthError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.urls import path

REFUSAL = "demo identities are refused in production"
oauth = OAuth()


def configure():
    oauth.register(
        "bridge",
        server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        client_kwargs={"scope": "openid profile", "code_challenge_method": "S256",
                       "token_endpoint_auth_method": "client_secret_basic"},
        overwrite=True,
    )


if os.environ.get("OIDC_DISCOVERY_URL"):
    configure()


def is_demo(claims):
    return (claims.get("acr") == "demo" or claims.get("eid_env") == "demo"
            or str(claims.get("iss", "")).endswith("/demo"))


def index(request):
    return HttpResponse('<a href="/login">Log in with eID</a>')


def login(request):
    redirect_uri = os.environ.get("OIDC_REDIRECT_URI") or request.build_absolute_uri("/callback")
    return oauth.bridge.authorize_redirect(request, redirect_uri)


def callback(request):
    # RFC 9207: check the issuer before sending the code anywhere (mix-up defence).
    issuer = oauth.bridge.load_server_metadata()["issuer"]
    if request.GET.get("iss") != issuer:
        return HttpResponse("issuer mismatch", status=400)
    try:
        token = oauth.bridge.authorize_access_token(request)  # verifies state, PKCE, ID token
    except OAuthError as e:
        return HttpResponse(f"login failed: {html.escape(str(e))}", status=400)
    claims = dict(token["userinfo"])
    if os.environ.get("PRODUCTION") == "1" and is_demo(claims):
        return HttpResponse(REFUSAL, status=403)
    request.session.flush()
    request.session["sub"] = claims["sub"]  # account key: sub only
    request.session["claims"] = claims
    return HttpResponse(f"<p>Logged in. Account key (sub): <code>{html.escape(claims['sub'])}</code></p>"
                        f"<pre>{html.escape(str(claims))}</pre>")


def me(request):
    if "sub" not in request.session:
        return JsonResponse({"error": "not logged in"}, status=401)
    return JsonResponse(request.session["claims"])


urlpatterns = [path("", index), path("login", login), path("callback", callback), path("me", me)]
