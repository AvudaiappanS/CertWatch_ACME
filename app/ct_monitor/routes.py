"""CT monitoring UI: run a scan on demand and browse look-alike findings."""
from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from ..alerts.notifier import send_alert
from ..audit import audit
from ..auth.routes import login_required
from ..models import CTFinding
from ..security import DomainValidationError, validate_domain
from .ct_scanner import scan_ct

ct_bp = Blueprint("ct", __name__, url_prefix="/ct")


@ct_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    try:
        domain = validate_domain(request.form.get("domain", ""))
    except DomainValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard.dashboard"))
    try:
        summary = scan_ct(domain, alert_callback=send_alert)
        audit("ct_scan", domain, "SUCCESS",
              f"{summary['ct_entries']} CT entries, {summary['new_findings']} new look-alikes")
        flash(f"CT scan of {domain}: {summary['ct_entries']} log entries checked, "
              f"{summary['findings']} look-alike finding(s), "
              f"{summary['new_findings']} new.", "success")
    except Exception as exc:
        audit("ct_scan", domain, "FAILED", str(exc)[:200])
        flash(f"CT scan failed for {domain}: {exc}", "error")
    return redirect(url_for("ct.findings", domain=domain))


@ct_bp.route("/findings")
@login_required
def findings():
    domain = request.args.get("domain", "")
    query = CTFinding.query
    if domain:
        query = query.filter_by(protected_domain=domain)
    rows = query.order_by(CTFinding.similarity_score.desc()).all()
    return render_template("ct_findings.html", findings=rows, domain=domain)
