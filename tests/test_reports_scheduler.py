"""Reports, scheduler job bookkeeping and watchlist tests."""
from app.extensions import db
from app.models import Certificate, JobStatus, Watchlist
from app.scheduler import _record_job, scan_all_watchlist


def test_pdf_reports(admin_client):
    for url in ("/reports/certificates.pdf", "/reports/ct.pdf", "/reports/renewals.pdf"):
        resp = admin_client.get(url)
        assert resp.status_code == 200, url
        assert resp.headers["Content-Type"] == "application/pdf"
        assert resp.data.startswith(b"%PDF")


def test_csv_export(app, admin_client):
    with app.app_context():
        db.session.add(Certificate(domain="csv.example", days_remaining=5,
                                   status="Expiring Soon"))
        db.session.commit()
    resp = admin_client.get("/reports/certificates.csv")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "domain,issuer" in body and "csv.example" in body


def test_scheduler_disabled_in_tests(app):
    assert "scheduler" not in app.extensions


def test_job_status_records_runs(app):
    with app.app_context():
        _record_job(app, "scan_all_watchlist", "Success")
        _record_job(app, "scan_all_watchlist", "Failed", "boom")
        job = JobStatus.query.filter_by(job_name="scan_all_watchlist").one()
        assert job.run_count == 2 and job.last_status == "Failed"
        assert job.last_error == "boom"


def test_watchlist_scan_job_uses_watchlist(app, monkeypatch):
    scanned = []
    monkeypatch.setattr("app.scheduler.scan_certificate", lambda d: scanned.append(d))
    with app.app_context():
        db.session.add(Watchlist(domain="watch1.example"))
        db.session.commit()
    scan_all_watchlist(app)
    # primary domain is always included, watchlist domain added
    assert scanned == ["certwatchlab.in", "watch1.example"]
    with app.app_context():
        job = JobStatus.query.filter_by(job_name="scan_all_watchlist").one()
        assert job.last_status == "Success" and job.run_count == 1


def test_watchlist_admin_add_remove(admin_client, admin_token, app):
    resp = admin_client.post("/watchlist/add", follow_redirects=True,
                             data={"domain": "Example.COM/x", "csrf_token": admin_token})
    assert b"example.com added" in resp.data
    with app.app_context():
        entry = Watchlist.query.filter_by(domain="example.com").one()
    resp = admin_client.post(f"/watchlist/remove/{entry.id}", follow_redirects=True,
                             data={"csrf_token": admin_token})
    assert b"removed" in resp.data
    with app.app_context():
        assert Watchlist.query.filter_by(domain="example.com").first() is None


def test_watchlist_requires_admin(analyst_client):
    from tests.conftest import csrf_from
    token = csrf_from(analyst_client, "/dashboard/")
    resp = analyst_client.post("/watchlist/add",
                               data={"domain": "example.com", "csrf_token": token})
    assert resp.status_code == 302


def test_scan_job_runs_without_caller_app_context(app, monkeypatch):
    """Regression: the scheduler thread has no Flask context, so the job must
    push its own. scan_certificate needs the db, so it must run inside one."""
    from flask import has_app_context
    seen = []
    def fake_scan(domain):
        assert has_app_context(), "scan_certificate ran outside app context"
        seen.append(domain)
    monkeypatch.setattr("app.scheduler.scan_certificate", fake_scan)
    scan_all_watchlist(app)  # called with NO app context, like APScheduler does
    assert seen == ["certwatchlab.in"]
    with app.app_context():
        job = JobStatus.query.filter_by(job_name="scan_all_watchlist").one()
        assert job.last_status == "Success"
