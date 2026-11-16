"""ACME client flow (fully mocked CA) and renewal policy tests."""
import datetime as dt
import json
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.models import Certificate, Renewal
from app.renewal.acme_client import ACMEClient, ACMEError, client_from_config
from app.renewal.core import RenewalNotAllowed, renew_certificate


# ------------------------------------------------------------ fake CA -----

class FakeResp:
    def __init__(self, status_code=200, payload=None, headers=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text if text is not None else (
            json.dumps(payload) if payload is not None else "")
        self.content = self.text.encode() if self.text else b""

    def json(self):
        return self._payload


def _self_signed_pem(domain):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Test CA")]))
            .public_key(key.public_key())
            .serial_number(123456789)
            .not_valid_before(dt.datetime.utcnow())
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class FakeCASession:
    """Implements the small part of requests.Session the client uses."""

    def __init__(self):
        self.cert_pem = _self_signed_pem("certwatchlab.in")
        self.challenge_posted = False

    def get(self, url, **kw):
        return FakeResp(payload={"newNonce": "https://ca.test/nonce",
                                 "newAccount": "https://ca.test/new-account",
                                 "newOrder": "https://ca.test/new-order"})

    def head(self, url, **kw):
        return FakeResp(headers={"Replay-Nonce": "nonce-123"})

    def post(self, url, json=None, **kw):
        if url == "https://ca.test/new-account":
            return FakeResp(201, payload={"status": "valid"},
                            headers={"Location": "https://ca.test/acct/1"})
        if url == "https://ca.test/new-order":
            return FakeResp(201, payload={
                "status": "pending",
                "authorizations": ["https://ca.test/authz/1"],
                "finalize": "https://ca.test/order/1/finalize"},
                headers={"Location": "https://ca.test/order/1"})
        if url == "https://ca.test/authz/1":
            status = "valid" if self.challenge_posted else "pending"
            return FakeResp(payload={
                "status": status,
                "challenges": [{"type": "http-01",
                                "url": "https://ca.test/chall/1",
                                "token": "tokentokentoken1"}]})
        if url == "https://ca.test/chall/1":
            self.challenge_posted = True
            return FakeResp(payload={"status": "processing"})
        if url == "https://ca.test/order/1/finalize":
            return FakeResp(payload={"status": "processing"})
        if url == "https://ca.test/order/1":
            return FakeResp(payload={"status": "valid",
                                     "certificate": "https://ca.test/cert/1"})
        if url == "https://ca.test/cert/1":
            return FakeResp(text=self.cert_pem)
        raise AssertionError(f"unexpected URL {url}")


# ------------------------------------------------------------ tests -------

def test_full_acme_flow_against_mocked_ca(tmp_path):
    client = ACMEClient("https://ca.test/dir", str(tmp_path),
                        email="admin@example.com", session=FakeCASession())
    result = client.issue_certificate("certwatchlab.in")
    assert result["issuer"].startswith("CN=Fake Test CA")
    assert os.path.exists(result["certificate_path"])
    assert os.path.exists(result["private_key_path"])
    # the challenge file must be cleaned up after the run
    assert os.listdir(os.path.join(str(tmp_path), "challenges")) == []


def test_production_mode_requires_explicit_opt_in(app):
    app.config["ACME_MODE"] = "production"
    app.config["ALLOW_PRODUCTION_ACME"] = False
    with app.app_context():
        with pytest.raises(ACMEError):
            client_from_config(app.config)


def test_renewal_refuses_domains_not_in_allowlist(app):
    with app.app_context():
        with pytest.raises(RenewalNotAllowed):
            renew_certificate(app, "evil.example")


def test_renewal_records_success(app, monkeypatch):
    def fake_fetch(domain):
        now = dt.datetime.utcnow()
        return {"subject": f"commonName={domain}", "common_name": domain,
                "issuer": "CN=Fake Test CA", "serial_number": "FF01",
                "issue_date": now, "expiry_date": now + dt.timedelta(days=90),
                "san": domain, "tls_version": "TLSv1.3",
                "verified": False, "verify_error": "self-signed test CA"}
    monkeypatch.setattr("app.renewal.core.scan_certificate",
                        lambda d: _scan_with(app, d, fake_fetch))
    class StubClient:
        def issue_certificate(self, domain):
            return {"certificate_path": "/tmp/x.crt", "private_key_path": "/tmp/x.key",
                    "issuer": "CN=Fake Test CA", "serial_number": "FF01",
                    "not_before": dt.datetime.utcnow(),
                    "not_after": dt.datetime.utcnow() + dt.timedelta(days=90)}
    monkeypatch.setattr("app.renewal.core.client_from_config", lambda config: StubClient())
    with app.app_context():
        from app.extensions import db
        db.session.add(Certificate(domain="certwatchlab.in", days_remaining=20))
        db.session.commit()
        renewal = renew_certificate(app, "certwatchlab.in")
        assert renewal.status == "SUCCESS" and renewal.new_expiry is not None
        assert Renewal.query.count() == 1


def _scan_with(app, domain, fetch):
    from app.scanner import core
    original = core._fetch_certificate
    core._fetch_certificate = fetch
    try:
        return core.scan_certificate(domain)
    finally:
        core._fetch_certificate = original


def test_challenge_file_is_served(app, client):
    path = os.path.join(app.config["ACME_STORAGE"], "challenges", "tokentokentoken2")
    with open(path, "w") as fh:
        fh.write("tokentokentoken2.thumbprintvalue")
    resp = client.get("/.well-known/acme-challenge/tokentokentoken2")
    assert resp.status_code == 200
    assert resp.get_data(as_text=True) == "tokentokentoken2.thumbprintvalue"


def test_challenge_route_rejects_bad_token(client):
    assert client.get("/.well-known/acme-challenge/bad/token").status_code == 404
    assert client.get("/.well-known/acme-challenge/x").status_code == 400
