"""Alert delivery: email (SMTP) and webhook, with a safe test mode.

ALERT_TEST_MODE=true (the default) records every alert in the database
without sending anything, so a fresh install can never send unintended mail.
"""
import json
import smtplib
from email.message import EmailMessage

import requests
from flask import current_app

from ..extensions import db
from ..models import Alert


def _already_sent(alert_type, domain, threshold_days) -> bool:
    """Deduplication: one alert per (domain, threshold) for expiry alerts and
    one per domain for expired alerts - they repeat on every scan otherwise."""
    if alert_type == "expiry":
        return (Alert.query.filter_by(alert_type=alert_type, domain=domain,
                                      threshold_days=threshold_days).first()
                is not None)
    if alert_type == "expired":
        return Alert.query.filter_by(alert_type=alert_type, domain=domain).first() is not None
    return False


def send_alert(alert_type: str, severity: str, domain: str, message: str,
               threshold_days: int = None) -> Alert:
    """Record and (outside test mode) deliver one alert. Returns the row."""
    if _already_sent(alert_type, domain, threshold_days):
        return None
    cfg = current_app.config
    channels, status = [], []

    if cfg["ALERT_TEST_MODE"]:
        channels.append("test-mode")
        status.append("recorded only (ALERT_TEST_MODE=true)")
    else:
        if cfg["ALERT_EMAIL_TO"] and cfg["SMTP_HOST"]:
            try:
                _send_email(cfg, alert_type, severity, domain, message)
                channels.append("email")
                status.append("email sent")
            except Exception as exc:
                channels.append("email")
                status.append(f"email failed: {exc}")
        if cfg["WEBHOOK_URL"]:
            try:
                _send_webhook(cfg, alert_type, severity, domain, message)
                channels.append("webhook")
                status.append("webhook delivered")
            except Exception as exc:
                channels.append("webhook")
                status.append(f"webhook failed: {exc}")
        if not channels:
            status.append("no alert channel configured")

    alert = Alert(alert_type=alert_type, severity=severity, domain=domain,
                  threshold_days=threshold_days, message=message[:900],
                  channel="+".join(channels) or "none",
                  delivery_status="; ".join(status)[:190])
    db.session.add(alert)
    db.session.commit()
    return alert


def _send_email(cfg, alert_type, severity, domain, message):
    msg = EmailMessage()
    msg["Subject"] = f"[CertWatch] {severity}: {alert_type} - {domain}"
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = cfg["ALERT_EMAIL_TO"]
    msg.set_content(message)
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as smtp:
        smtp.starttls()
        if cfg["SMTP_USER"]:
            smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        smtp.send_message(msg)


def _send_webhook(cfg, alert_type, severity, domain, message):
    payload = {"source": "certwatch-lab", "type": alert_type,
               "severity": severity, "domain": domain, "message": message}
    resp = requests.post(cfg["WEBHOOK_URL"], json=payload, timeout=10)
    resp.raise_for_status()
