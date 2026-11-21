import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY.strip() or SECRET_KEY.strip() == "example-only-not-a-secret":
    raise ImproperlyConfigured("Set DJANGO_SECRET_KEY to a unique, secret value")
DEBUG = False
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "django_rp"
INSTALLED_APPS = ["django.contrib.sessions"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("DJANGO_SESSION_DB") or Path(__file__).resolve().parent / "sessions.sqlite3",
    }
}
SESSION_ENGINE = "django.contrib.sessions.backends.db"
USE_TZ = True
