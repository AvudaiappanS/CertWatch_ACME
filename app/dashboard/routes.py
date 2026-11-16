"""Dashboard: system overview, audit log and runtime settings view."""
from datetime import datetime

from flask import Blueprint, current_app, render_template

from ..auth.routes import login_required, role_required
from ..models import (Alert, AuditLog, Certificate, CTFinding, JobStatus,
                      Renewal, ScanResult, Watchlist)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/")
@login_required
def dashboard():
    certs = Certificate.query.order_by(Certificate.days_remaining.asc().nullslast()).all()
    stats = {
        "certificates": len(certs),
        "valid": sum(1 for c in certs if c.status == "Valid"),
        "expiring": sum(1 for c in certs if c.status == "Expiring Soon"),
        "expired": sum(1 for c in certs if c.status == "Expired"),
        "watchlist": Watchlist.query.filter_by(active=True).count(),
        "findings": CTFinding.query.count(),
        "critical_findings": CTFinding.query.filter(
            CTFinding.risk_level.in_(["Critical", "High"])).count(),
        "unhandled_alerts": Alert.query.count(),
        "renewals_ok": Renewal.query.filter_by(status="SUCCESS").count(),
        "renewals_failed": Renewal.query.filter_by(status="FAILED").count(),
    }
    recent_scans = (ScanResult.query.order_by(ScanResult.scan_time.desc())
                    .limit(5).all())
    recent_renewals = (Renewal.query.order_by(Renewal.created_at.desc())
                       .limit(5).all())
    return render_template("dashboard.html", certs=certs, stats=stats,
                           recent_scans=recent_scans,
                           recent_renewals=recent_renewals,
                           acme_mode=current_app.config["ACME_MODE"],
                           now=datetime.utcnow())


@dashboard_bp.route("/audit")
@role_required("Administrator")
def audit_log():
    rows = AuditLog.query.order_by(AuditLog.ts.desc()).limit(300).all()
    return render_template("audit.html", entries=rows)


@dashboard_bp.route("/settings")
@role_required("Administrator")
def settings():
    """Read-only view of the effective runtime configuration.

    Secret values (SMTP password, SECRET_KEY) are never displayed.
    """
    cfg = current_app.config
    visible = {
        "PRIMARY_DOMAIN": cfg["PRIMARY_DOMAIN"],
        "ALLOWED_RENEWAL_DOMAINS": ", ".join(cfg["ALLOWED_RENEWAL_DOMAINS"]),
        "ACME_MODE": cfg["ACME_MODE"],
        "ALLOW_PRODUCTION_ACME": cfg["ALLOW_PRODUCTION_ACME"],
        "ACME_EMAIL": cfg["ACME_EMAIL"] or "(not set)",
        "ALERT_TEST_MODE": cfg["ALERT_TEST_MODE"],
        "ALERT_EMAIL_TO": cfg["ALERT_EMAIL_TO"] or "(not set)",
        "SMTP_HOST": cfg["SMTP_HOST"] or "(not set)",
        "SMTP_PASSWORD": "(hidden)",
        "WEBHOOK_URL": cfg["WEBHOOK_URL"] or "(not set)",
        "SCAN_INTERVAL_HOURS": cfg["SCAN_INTERVAL_HOURS"],
        "CT_INTERVAL_HOURS": cfg["CT_INTERVAL_HOURS"],
        "RENEWAL_CHECK_INTERVAL_HOURS": cfg["RENEWAL_CHECK_INTERVAL_HOURS"],
        "RENEW_BEFORE_DAYS": cfg["RENEW_BEFORE_DAYS"],
        "SCHEDULER_ENABLED": cfg["SCHEDULER_ENABLED"],
        "SESSION_COOKIE_SECURE": cfg["SESSION_COOKIE_SECURE"],
        "SCAN_ALLOW_PRIVATE": cfg["SCAN_ALLOW_PRIVATE"],
    }
    return render_template("settings.html", settings=visible)
