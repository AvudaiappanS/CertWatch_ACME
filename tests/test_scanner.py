"""TLS scanner: risk scoring rules and persistence (network mocked), plus one
genuinely live scan against example.com."""
from datetime import datetime, timedelta

import pytest

from app.models import Certificate, ScanResult
from app.scanner.core import certificate_status, risk_level, risk_score, scan_certificate


def _fake_cert(days):
    now = datetime.utcnow()
    return {
        "subject": "commonName=example.test", "common_name": "example.test",
        "issuer": "commonName=Test CA", "serial_number": "AB12",
        "issue_date": now - timedelta(days=30),
        "expiry_date": now + timedelta(days=days),
        "san": "example.test", "tls_version": "TLSv1.3",
        "verified": True, "verify_error": None,
    }


@pytest.mark.parametrize("days,verified,expected", [
    (-1, True, 100), (5, True, 70), (5, False, 90), (10, True, 60),
    (25, True, 40), (60, True, 20), (200, True, 0), (200, False, 20),
])
def test_risk_scoring_rules(days, verified, expected):
    score, _ = risk_score(days, verified)
    assert score == expected


def test_status_and_level_labels():
    assert certificate_status(-1) == "Expired"
    assert certificate_status(10) == "Expiring Soon"
    assert certificate_status(90) == "Valid"
    assert risk_level(95) == "Critical" and risk_level(60) == "High"
    assert risk_level(40) == "Medium" and risk_level(10) == "Low"


def test_scan_persists_certificate_and_result(app, monkeypatch):
    monkeypatch.setattr("app.scanner.core._fetch_certificate", lambda d: _fake_cert(42))
    with app.app_context():
        result = scan_certificate("example.test")
        assert result.status == "Success" and result.risk_score == 20  # 40-20
        cert = Certificate.query.filter_by(domain="example.test").one()
        assert cert.status == "Valid" and cert.days_remaining in (41, 42)
        assert cert.issuer == "commonName=Test CA"
        assert ScanResult.query.filter_by(certificate_id=cert.id).count() == 1


def test_scan_failure_is_recorded(app, monkeypatch):
    def boom(domain):
        raise OSError("connection refused")
    monkeypatch.setattr("app.scanner.core._fetch_certificate", boom)
    with app.app_context():
        result = scan_certificate("down.example")
        assert result.status == "Failed" and "connection refused" in result.error


def test_live_tls_scan_example_com(app):
    """REAL network scan (not mocked). Skipped if outbound 443 is unavailable."""
    import socket
    try:
        socket.create_connection(("example.com", 443), timeout=5).close()
    except OSError:
        pytest.skip("no outbound network access in this environment")
    with app.app_context():
        result = scan_certificate("example.com")
        assert result.status == "Success", result.error
        assert result.days_remaining and result.days_remaining > 0
        cert = Certificate.query.filter_by(domain="example.com").one()
        assert cert.issuer and cert.expiry_date
