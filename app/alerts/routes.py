"""Alert feed UI and the expiry-threshold check used by the scheduler."""
from flask import Blueprint, render_template

from ..auth.routes import login_required
from ..models import Alert, Certificate
from .notifier import send_alert

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/")
@login_required
def index():
    from datetime import datetime, timedelta

    from flask import current_app

    cfg = current_app.config
    rows = Alert.query.order_by(Alert.created_at.desc()).limit(200).all()
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent = [a for a in rows if a.created_at >= week_ago]
    summary = {
        "total": len(recent),
        "email": sum(1 for a in recent
                     if "email" in (a.channel or "") and "failed" not in (a.delivery_status or "")),
        "webhook": sum(1 for a in recent
                       if "webhook" in (a.channel or "") and "failed" not in (a.delivery_status or "")),
    }
    if cfg["ALERT_TEST_MODE"]:
        email_state = "Test mode - recorded only"
        webhook_state = "Test mode - recorded only"
    else:
        email_state = (f"Enabled - {cfg['ALERT_EMAIL_TO']}"
                       if cfg["ALERT_EMAIL_TO"] and cfg["SMTP_HOST"] else "Disabled")
        webhook_state = "Enabled - Slack / Teams URL" if cfg["WEBHOOK_URL"] else "Disabled"
    return render_template("alerts.html", alerts=rows, summary=summary,
                           email_state=email_state, webhook_state=webhook_state,
                           test_mode=cfg["ALERT_TEST_MODE"])


def check_expiry_alerts(app) -> int:
    """Raise expiry alerts for certificates crossing 30/14/7-day thresholds.

    Returns the number of alerts created. Deduplication inside send_alert
    keeps one alert per domain per threshold.
    """
    created = 0
    with app.app_context():
        for cert in Certificate.query.all():
            days = cert.days_remaining
            if days is None:
                continue
            if days < 0:
                alert = send_alert("expired", "Critical", cert.domain,
                                   f"The certificate for {cert.domain} EXPIRED "
                                   f"{-days} day(s) ago.")
                created += 1 if alert else 0
                continue
            # Check the tightest threshold first so a certificate 3 days out
            # raises the 7-day alert, not the 30-day one.
            for threshold in sorted(app.config["ALERT_THRESHOLDS_DAYS"]):
                if days <= threshold:
                    alert = send_alert(
                        "expiry",
                        "Warning" if threshold > 7 else "Critical",
                        cert.domain,
                        f"The certificate for {cert.domain} expires in "
                        f"{days} day(s) (threshold: {threshold} days).",
                        threshold_days=threshold)
                    created += 1 if alert else 0
                    break
    return created
