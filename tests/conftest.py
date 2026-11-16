import os
import re
import sys
import tempfile

import pytest

TMP = tempfile.mkdtemp(prefix="certwatch-test-")
os.environ["DATA_DIR"] = TMP
os.environ["ACME_STORAGE"] = os.path.join(TMP, "acme")
os.environ["SCHEDULER_ENABLED"] = "false"
os.environ["ADMIN_PASSWORD"] = "admin-test-password-1"
os.environ["ALERT_TEST_MODE"] = "true"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402
from app.extensions import db as _db  # noqa: E402
from app.models import User  # noqa: E402


@pytest.fixture()
def app():
    application = create_app()
    from app import _bootstrap_admin
    with application.app_context():
        _db.drop_all()
        _db.create_all()
        _bootstrap_admin(application, User)
        yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(client, url="/login"):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture()
def admin_client(app, client):
    token = csrf_from(client)
    client.post("/login", data={"username": "admin",
                                "password": "admin-test-password-1",
                                "csrf_token": token})
    return client


@pytest.fixture()
def analyst_client(app, client):
    with app.app_context():
        User.create("analyst", "analyst-password-1", "Analyst")
    token = csrf_from(client)
    client.post("/login", data={"username": "analyst",
                                "password": "analyst-password-1",
                                "csrf_token": token})
    return client


@pytest.fixture()
def admin_token(admin_client):
    return csrf_from(admin_client, "/dashboard/")


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    from app import security
    security._login_attempts.clear()
    yield
