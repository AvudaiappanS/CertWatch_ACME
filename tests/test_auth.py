"""Authentication, CSRF, rate limiting and role enforcement tests."""
from app.models import AuditLog, User


def test_login_success_redirects_to_dashboard(app, client):
    from tests.conftest import csrf_from
    token = csrf_from(client)
    resp = client.post("/login", data={
        "username": "admin", "password": "admin-test-password-1",
        "csrf_token": token})
    assert resp.status_code == 302 and "/dashboard/" in resp.headers["Location"]
    with app.app_context():
        entry = AuditLog.query.filter_by(action="login", outcome="SUCCESS").first()
        assert entry is not None and entry.username == "admin"


def test_login_failure_is_audited(app, client):
    from tests.conftest import csrf_from
    token = csrf_from(client)
    resp = client.post("/login", data={
        "username": "admin", "password": "wrong-password", "csrf_token": token})
    assert b"Invalid username or password" in resp.data
    with app.app_context():
        assert AuditLog.query.filter_by(action="login", outcome="FAILED").count() >= 1


def test_csrf_token_required_for_post(client):
    resp = client.post("/login", data={"username": "admin", "password": "x"})
    assert resp.status_code == 400


def test_login_rate_limit_blocks_after_max_attempts(app, client):
    from tests.conftest import csrf_from
    token = csrf_from(client)
    for _ in range(app.config["MAX_LOGIN_ATTEMPTS"]):
        client.post("/login", data={"username": "admin", "password": "bad",
                                    "csrf_token": token})
    resp = client.post("/login", data={"username": "admin",
                                       "password": "admin-test-password-1",
                                       "csrf_token": token})
    assert b"Too many failed attempts" in resp.data
    with app.app_context():
        assert AuditLog.query.filter_by(outcome="DENIED").count() >= 1


def test_analyst_cannot_reach_admin_pages(analyst_client):
    from tests.conftest import csrf_from
    resp = analyst_client.get("/dashboard/audit")
    assert resp.status_code == 302  # redirected back to dashboard
    resp = analyst_client.get("/dashboard/settings")
    assert resp.status_code == 302
    token = csrf_from(analyst_client, "/dashboard/")
    resp = analyst_client.post("/renewal/trigger",
                               data={"domain": "certwatchlab.in", "csrf_token": token})
    assert resp.status_code == 302  # denied + redirected, renewal never ran


def test_passwords_are_stored_hashed(app):
    with app.app_context():
        user = User.create("hashcheck", "some-long-password", "Analyst")
        assert user.password_hash != "some-long-password"
        assert "some-long-password" not in user.password_hash
        assert user.check_password("some-long-password")
        assert not user.check_password("other-password")


def test_pages_require_login(client):
    for url in ("/dashboard/", "/alerts/", "/renewal/history", "/ct/findings",
                "/reports/certificates.pdf"):
        resp = client.get(url)
        assert resp.status_code == 302 and "/login" in resp.headers["Location"], url
