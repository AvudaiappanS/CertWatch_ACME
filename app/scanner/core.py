"""TLS certificate scanning.

Opens a TLS connection to a domain, reads the presented certificate chain
and stores the leaf certificate's metadata. Risk scoring follows the rules
defined in the project report (Table 3.1):

    expired              -> 100
    days <= 7            -> 90
    days <= 14           -> 80
    days <= 30           -> 60
    days <= 90           -> 40
    otherwise            -> 20
    minus 20 when the certificate chain/hostname verifies cleanly
    (score is clamped to 0..100; a negative value is reported as 0/Low)
"""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from ..extensions import db
from ..models import Certificate, ScanResult


def _name_to_str(name: x509.Name) -> str:
    parts = []
    for attr in name:
        oid_name = attr.oid._name or attr.oid.dotted_string
        parts.append(f"{oid_name}={attr.value}")
    return ", ".join(parts)


def _fetch_certificate(domain: str, port: int = 443, timeout: int = 10):
    """Return (cert_dict, verified, verify_error).

    First the certificate is fetched with a verifying SSL context; if chain
    or hostname verification fails (common for staging/self-signed certs) the
    certificate is fetched again without verification so its details can
    still be shown, and the failure is recorded.
    """
    der = None
    verified, verify_error = True, None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, str(exc.verify_message or exc)
    if der is None:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
    else:
        tls_version = None
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                tls_version = ssock.version()

    cert = x509.load_der_x509_certificate(der, default_backend())
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject": _name_to_str(cert.subject),
        "common_name": next((a.value for a in cert.subject
                             if a.oid == NameOID.COMMON_NAME), ""),
        "issuer": _name_to_str(cert.issuer),
        "serial_number": format(cert.serial_number, "X"),
        "issue_date": cert.not_valid_before_utc.replace(tzinfo=None),
        "expiry_date": cert.not_valid_after_utc.replace(tzinfo=None),
        "san": ", ".join(sans),
        "tls_version": tls_version or "unknown",
        "verified": verified,
        "verify_error": verify_error,
    }


def risk_score(days_remaining, verified=True):
    """Risk score (0-100) plus human-readable reasons. See module docstring."""
    if days_remaining < 0:
        score, reasons = 100, ["Certificate has expired"]
    elif days_remaining <= 7:
        score, reasons = 90, ["Certificate expires within 7 days"]
    elif days_remaining <= 14:
        score, reasons = 80, ["Certificate expires within 14 days"]
    elif days_remaining <= 30:
        score, reasons = 60, ["Certificate expires within 30 days"]
    elif days_remaining <= 90:
        score, reasons = 40, ["Certificate expires within 90 days"]
    else:
        score, reasons = 20, ["Certificate has more than 90 days remaining"]
    if verified and days_remaining >= 0:
        score -= 20
        reasons.append("Certificate chain and hostname verified (-20)")
    else:
        reasons.append("Certificate failed chain/hostname verification")
    return max(0, min(100, score)), "; ".join(reasons)


def risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def certificate_status(days_remaining):
    if days_remaining < 0:
        return "Expired"
    if days_remaining <= 30:
        return "Expiring Soon"
    return "Valid"


def scan_certificate(domain: str) -> ScanResult:
    """Scan one domain and persist the result. Returns the ScanResult row."""
    try:
        data = _fetch_certificate(domain)
        expiry = data["expiry_date"]
        days = (expiry - datetime.utcnow()).days
        score, reasons = risk_score(days, data["verified"])

        cert_row = Certificate.query.filter_by(domain=domain).first()
        if not cert_row:
            cert_row = Certificate(domain=domain)
            db.session.add(cert_row)
        cert_row.subject = data["subject"]
        cert_row.san = data["san"]
        cert_row.issuer = data["issuer"]
        cert_row.serial_number = data["serial_number"]
        cert_row.issue_date = data["issue_date"]
        cert_row.expiry_date = expiry
        cert_row.tls_version = data["tls_version"]
        cert_row.verified = data["verified"]
        cert_row.verify_error = data["verify_error"]
        cert_row.days_remaining = days
        cert_row.status = certificate_status(days)
        cert_row.last_scanned = datetime.utcnow()

        result = ScanResult(certificate=cert_row, days_remaining=days,
                            risk_score=score, risk_reasons=reasons,
                            status="Success")
    except Exception as exc:
        result = ScanResult(days_remaining=None, risk_score=None,
                            status="Failed", error=str(exc)[:290])
        cert_row = Certificate.query.filter_by(domain=domain).first()
        if cert_row:
            result.certificate = cert_row
    db.session.add(result)
    db.session.commit()
    return result
