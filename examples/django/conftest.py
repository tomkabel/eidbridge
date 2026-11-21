import secrets
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent))
from conftest_bridge import bridge  # noqa: E402,F401


@pytest.fixture(scope="session")
def django_session_db(tmp_path_factory):
    """Initialize Django with a disposable secret and session database."""
    with pytest.MonkeyPatch.context() as env:
        env.setenv("DJANGO_SETTINGS_MODULE", "django_settings")
        env.setenv("DJANGO_SECRET_KEY", secrets.token_urlsafe(48))
        env.setenv("DJANGO_SESSION_DB", str(tmp_path_factory.mktemp("django") / "sessions.sqlite3"))
        import django
        django.setup()
        from django.core.management import call_command
        call_command("migrate", verbosity=0, interactive=False)
        yield
        from django.db import connections
        connections.close_all()
