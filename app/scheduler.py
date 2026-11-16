"""Background jobs (APScheduler).

Three jobs run on configurable intervals:
  scan_all_watchlist  - TLS scan of every active watchlist domain + PRIMARY_DOMAIN
  ct_scan_watchlist   - CT look-alike scan of the same domains
  renewal_and_alerts  - expiry alert check + auto-renewal of due certificates

Duplicate prevention: the scheduler only starts when SCHEDULER_ENABLED=true.
In Docker, the web container runs with SCHEDULER_ENABLED=false and a separate
"scheduler" container runs with it true, so jobs never run twice.
Each job records its runs in the JobStatus table for the dashboard.
"""
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

from .alerts.notifier import send_alert
from .alerts.routes import check_expiry_alerts
from .audit import audit
from .ct_monitor.ct_scanner import scan_ct
from .extensions import db
from .models import JobStatus, Watchlist
from .renewal.core import check_and_renew_due
from .scanner.core import scan_certificate


def _monitored_domains(app):
    with app.app_context():
        domains = [w.domain for w in Watchlist.query.filter_by(active=True)]
        primary = app.config["PRIMARY_DOMAIN"]
        if primary and primary not in domains:
            domains.insert(0, primary)
        return domains


def _record_job(app, name, status, error=None):
    with app.app_context():
        job = JobStatus.query.filter_by(job_name=name).first()
        if not job:
            job = JobStatus(job_name=name)
            db.session.add(job)
        job.last_run = datetime.utcnow()
        job.last_status = status
        job.last_error = (error or "")[:290] or None
        job.run_count = (job.run_count or 0) + 1
        db.session.commit()


def scan_all_watchlist(app):
    try:
        with app.app_context():
            for domain in _monitored_domains(app):
                scan_certificate(domain)
        _record_job(app, "scan_all_watchlist", "Success")
    except Exception as exc:
        _record_job(app, "scan_all_watchlist", "Failed", str(exc))


def ct_scan_watchlist(app):
    try:
        with app.app_context():
            for domain in _monitored_domains(app):
                scan_ct(domain, alert_callback=send_alert)
        _record_job(app, "ct_scan_watchlist", "Success")
    except Exception as exc:
        _record_job(app, "ct_scan_watchlist", "Failed", str(exc))


def renewal_and_alerts(app):
    try:
        with app.app_context():
            check_expiry_alerts(app)
            check_and_renew_due(app, alert_callback=send_alert)
        _record_job(app, "renewal_and_alerts", "Success")
    except Exception as exc:
        _record_job(app, "renewal_and_alerts", "Failed", str(exc))


def start_scheduler(app):
    scheduler = BackgroundScheduler(daemon=True)
    jobs = [
        ("scan_all_watchlist", scan_all_watchlist, app.config["SCAN_INTERVAL_HOURS"]),
        ("ct_scan_watchlist", ct_scan_watchlist, app.config["CT_INTERVAL_HOURS"]),
        ("renewal_and_alerts", renewal_and_alerts, app.config["RENEWAL_CHECK_INTERVAL_HOURS"]),
    ]
    for name, func, hours in jobs:
        scheduler.add_job(func, "interval", hours=hours, args=[app],
                          id=name, name=name, max_instances=1,
                          next_run_time=datetime.now() + timedelta(seconds=30))
    scheduler.start()
    app.extensions["scheduler"] = scheduler
    return scheduler
