"""Alert recording, test mode, expiry thresholds and deduplication."""
from datetime import datetime, timedelta

from app.alerts.notifier import send_alert
from app.alerts.routes import check_expiry_alerts
from app.models import Alert, Certificate


def test_test_mode_records_without_sending(app, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("SMTP must not be used in test mode")
    monkeypatch.setattr("app.alerts.notifier._send_email", boom)
    with app.app_context():
        alert = send_alert("lookalike", "High", "example.com", "test message")
        assert alert is not None
        assert alert.channel == "test-mode"
        assert "ALERT_TEST_MODE" in alert.delivery_status


def test_expiry_thresholds_and_deduplication(app):
    with app.app_context():
        now = datetime.utcnow()
        for domain, days in (("soon10.example", 10), ("soon3.example", 3),
                             ("expired.example", -2), ("fine.example", 100)):
            from app.extensions import db
            db.session.add(Certificate(domain=domain, days_remaining=days,
                                       expiry_date=now + timedelta(days=days),
                                       status="x"))
        from app.extensions import db
        db.session.commit()
        created = check_expiry_alerts(app)
        assert created == 3  # 14-day, 7-day and expired alerts; fine.example gets none
        rows = {(a.domain, a.alert_type, a.threshold_days) for a in Alert.query.all()}
        assert ("soon10.example", "expiry", 14) in rows
        assert ("soon3.example", "expiry", 7) in rows
        assert ("expired.example", "expired", None) in rows
        # second run creates nothing new
        assert check_expiry_alerts(app) == 0
