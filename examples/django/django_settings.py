SECRET_KEY = "example-only-not-a-secret"
DEBUG = False
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "django_rp"
INSTALLED_APPS = ["django.contrib.sessions"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
USE_TZ = True
