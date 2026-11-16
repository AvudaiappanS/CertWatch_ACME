"""Domain validation, SSRF guard, headers and health endpoint."""
import pytest

from app.security import (DomainValidationError, clean_domain, ssrf_guard,
                          validate_domain)


def test_domain_normalization():
    assert clean_domain("  HTTPS://Example.COM/path?x=1 ") == "example.com"
    assert clean_domain("*.example.com") == "example.com"
    assert clean_domain("example.com.") == "example.com"
    assert clean_domain("example.com:8443") == "example.com"


def test_domain_validation_rejects_bad_input():
    for bad in ("", "not a domain", "localhost", "-bad-.com", "a" * 260 + ".com",
                "example..com"):
        with pytest.raises(DomainValidationError):
            validate_domain(bad)


def test_ssrf_guard_blocks_private_addresses(app, monkeypatch):
    import socket
    fake = [(socket.AF_INET, None, None, None, ("127.0.0.1", 443))]
    monkeypatch.setattr("app.security.socket.getaddrinfo", lambda *a, **k: fake)
    with app.test_request_context():
        with pytest.raises(DomainValidationError):
            ssrf_guard("internal.example")


def test_ssrf_guard_allows_public_addresses(app, monkeypatch):
    import socket
    fake = [(socket.AF_INET, None, None, None, ("93.184.216.34", 443))]
    monkeypatch.setattr("app.security.socket.getaddrinfo", lambda *a, **k: fake)
    with app.test_request_context():
        ssrf_guard("example.com")  # must not raise


def test_scan_route_rejects_private_target(admin_client, admin_token):
    resp = admin_client.post("/scanner/scan", follow_redirects=True,
                             data={"domain": "localhost", "csrf_token": admin_token})
    assert b"valid public domain" in resp.data


def test_security_headers_present(admin_client):
    resp = admin_client.get("/dashboard/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200 and resp.get_json() == {"status": "ok"}
