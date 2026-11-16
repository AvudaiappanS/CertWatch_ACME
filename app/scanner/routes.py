"""Scanner UI: run a scan on demand and view certificate details."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..audit import audit
from ..auth.routes import login_required
from ..extensions import db
from ..models import Certificate, ScanResult
from ..security import DomainValidationError, ssrf_guard, validate_domain
from .core import risk_level, scan_certificate

scanner_bp = Blueprint("scanner", __name__, url_prefix="/scanner")


@scanner_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    try:
        domain = validate_domain(request.form.get("domain", ""))
        ssrf_guard(domain)
    except DomainValidationError as exc:
        audit("scan", request.form.get("domain", ""), "FAILED", str(exc))
        flash(str(exc), "error")
        return redirect(url_for("dashboard.dashboard"))

    result = scan_certificate(domain)
    if result.status == "Success":
        audit("scan", domain, "SUCCESS",
              f"Risk score {result.risk_score}, {result.days_remaining} days remaining")
        flash(f"Scanned {domain}: {result.days_remaining} days remaining, "
              f"risk {result.risk_score}/100 ({risk_level(result.risk_score)}).", "success")
    else:
        audit("scan", domain, "FAILED", result.error or "scan failed")
        flash(f"Scan failed for {domain}: {result.error}", "error")
    return redirect(url_for("scanner.certificate_detail", domain=domain)) \
        if result.certificate_id else redirect(url_for("dashboard.dashboard"))


@scanner_bp.route("/search")
@login_required
def search_page():
    """Standalone search page (nav: Search Domain)."""
    return render_template("search.html")


@scanner_bp.route("/certificate/<domain>")
@login_required
def certificate_detail(domain):
    cert = Certificate.query.filter_by(domain=domain).first_or_404()
    scans = (ScanResult.query.filter_by(certificate_id=cert.id)
             .order_by(ScanResult.scan_time.desc()).limit(30).all())
    latest = scans[0] if scans else None
    return render_template("certificate.html", cert=cert, scans=scans,
                           latest=latest, risk_level=risk_level)
