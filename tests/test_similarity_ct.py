"""Look-alike detection rules and the CT scan pipeline (crt.sh mocked)."""
from app.ct_monitor.similarity import analyze_similarity
from app.ct_monitor.ct_scanner import scan_ct
from app.models import Alert, CTFinding


def test_exact_match_and_subdomain_ignored():
    assert analyze_similarity("certwatchlab.in", "certwatchlab.in")[0] == 0
    assert analyze_similarity("certwatchlab.in", "mail.certwatchlab.in")[0] == 0


def test_homoglyph_is_critical():
    score, level, _ = analyze_similarity("certwatchlab.in", "certwatch1ab.in")
    assert score == 100 and level == "Critical"


def test_prefix_variation_floored_at_high():
    score, level, _ = analyze_similarity("certwatchlab.in", "certwatchlab-login.com")
    assert score == 80 and level == "High"


def test_unrelated_domain_is_low():
    score, level, _ = analyze_similarity("certwatchlab.in", "google.com")
    assert score < 55 and level == "Low"


FAKE_CT = [
    {"name_value": "certwatchlab.in\nwww.certwatchlab.in", "issuer_name": "CN=LE"},
    {"name_value": "certwatch1ab.in", "issuer_name": "CN=Evil CA"},
    {"name_value": "certwatchlab-secure.com", "issuer_name": "CN=Evil CA"},
    {"name_value": "totally-unrelated.org", "issuer_name": "CN=Other"},
]


def test_ct_scan_records_findings_and_alerts(app, monkeypatch):
    monkeypatch.setattr("app.ct_monitor.ct_scanner.query_crtsh", lambda d: FAKE_CT)
    alerts = []
    with app.app_context():
        summary = scan_ct("certwatchlab.in", alert_callback=lambda *a, **k: alerts.append(a))
        # two look-alikes found (homoglyph + prefix), unrelated name ignored,
        # exact match and legitimate subdomain ignored
        assert summary["findings"] == 2 and summary["new_findings"] == 2
        names = {f.detected_domain for f in CTFinding.query.all()}
        assert names == {"certwatch1ab.in", "certwatchlab-secure.com"}
        assert len(alerts) == 2
        # second run: findings deduplicated, no new alerts
        summary2 = scan_ct("certwatchlab.in", alert_callback=lambda *a, **k: alerts.append(a))
        assert summary2["new_findings"] == 0 and len(alerts) == 2
