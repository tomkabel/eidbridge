import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("value", [None, "", "   ", "example-only-not-a-secret"])
def test_pr31_requires_explicit_deployment_secret(value):
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "django_settings"}
    env.pop("DJANGO_SECRET_KEY", None)
    if value is not None:
        env["DJANGO_SECRET_KEY"] = value
    result = subprocess.run(
        [sys.executable, "-c", "from django.conf import settings; print(settings.SECRET_KEY)"],
        env=env, cwd=Path(__file__).parent, capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "ImproperlyConfigured" in result.stderr
    assert "DJANGO_SECRET_KEY" in result.stderr


def test_pr31_session_requires_server_side_record(tmp_path):
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "django_settings",
        "DJANGO_SECRET_KEY": "pr31-fixture-" * 8,
        "DJANGO_SESSION_DB": str(tmp_path / "sessions.sqlite3"),
    }
    script = """
import django
django.setup()
from django.conf import settings
from django.test import Client
assert settings.SECRET_KEY == 'pr31-fixture-' * 8
assert settings.SESSION_ENGINE == 'django.contrib.sessions.backends.db'
from django.core.management import call_command
call_command('migrate', verbosity=0)
from django.contrib.sessions.backends.db import SessionStore
client = Client(HTTP_HOST='localhost')
assert client.get('/me').status_code == 401
session = SessionStore()
session['sub'] = 'fixture-user'
session['claims'] = {'sub': 'fixture-user'}
session.save()
client.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
assert client.get('/me').json()['sub'] == 'fixture-user'
session.delete()
assert client.get('/me').status_code == 401
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env, cwd=Path(__file__).parent, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
