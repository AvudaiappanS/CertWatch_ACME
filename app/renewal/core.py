"""Renewal workflow: request a fresh certificate through ACME and record it.

Only domains listed in ALLOWED_RENEWAL_DOMAINS may be renewed - the app must
never try to prove control over a domain it does not own.
"""
from datetime import datetime

from ..extensions import db
from ..models import Certificate, Renewal
from ..scanner.core import scan_certificate
from .acme_client import client_from_config


class RenewalNotAllowed(Exception):
    pass


def renew_certificate(app, domain: str, alert_callback=None) -> Renewal:
    """Run one ACME issuance for the domain and store a Renewal record."""
    config = app.config
    domain = domain.lower().strip()
    if domain not in config["ALLOWED_RENEWAL_DOMAINS"]:
        raise RenewalNotAllowed(
            f"Renewal for '{domain}' is not allowed. Add it to "
            "ALLOWED_RENEWAL_DOMAINS only if you control the domain.")

    cert_row = Certificate.query.filter_by(domain=domain).first()
    old_expiry = cert_row.expiry_date if cert_row else None

    if True:
        try:
            client = client_from_config(config)
            result = client.issue_certificate(domain)
            # Rescan so the database reflects the newly issued certificate.
            scan_certificate(domain)
            cert_row = Certificate.query.filter_by(domain=domain).first()
            renewal = Renewal(certificate_id=cert_row.id if cert_row else None,
                              acme_mode=config["ACME_MODE"], challenge_type="HTTP-01",
                              old_expiry=old_expiry,
                              new_expiry=result["not_after"],
                              issuer=result["issuer"],
                              serial_number=result["serial_number"],
                              status="SUCCESS")
        except Exception as exc:
            renewal = Renewal(certificate_id=cert_row.id if cert_row else None,
                              acme_mode=config["ACME_MODE"], challenge_type="HTTP-01",
                              old_expiry=old_expiry, status="FAILED",
                              error=str(exc)[:900])
        db.session.add(renewal)
        db.session.commit()
        db.session.refresh(renewal)  # keep attributes readable for the caller

        if alert_callback:
            if renewal.status == "SUCCESS":
                alert_callback("renewal_success", "Info", domain,
                               f"Certificate for {domain} renewed via ACME "
                               f"({config['ACME_MODE']}). New expiry: {renewal.new_expiry}.")
            else:
                alert_callback("renewal_failed", "High", domain,
                               f"Automatic renewal for {domain} failed: {renewal.error}")
        return renewal


def check_and_renew_due(app, alert_callback=None) -> list:
    """Scheduler job: renew configured certificates nearing expiry."""
    renew_before = app.config["RENEW_BEFORE_DAYS"]
    results = []
    for domain in app.config["ALLOWED_RENEWAL_DOMAINS"]:
        cert = Certificate.query.filter_by(domain=domain).first()
        if not cert:
            continue
        if cert.days_remaining is not None and cert.days_remaining <= renew_before:
            results.append(renew_certificate(app, domain, alert_callback=alert_callback))
    return results
