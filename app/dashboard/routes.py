from flask import Blueprint, render_template, session, redirect, url_for
from ..models import Certificate, ScanResult, Vulnerability, Renewal
dashboard_bp=Blueprint("dashboard",__name__)
@dashboard_bp.route("/")
def index():
    if "user_id" not in session: return redirect(url_for("auth.login"))
    return render_template("dashboard.html",
        certificates=Certificate.query.order_by(Certificate.last_scanned.desc()).all(),
        scans=ScanResult.query.order_by(ScanResult.scan_time.desc()).limit(10).all(),
        vulnerabilities=Vulnerability.query.order_by(Vulnerability.detection_time.desc()).limit(10).all(),
        renewals=Renewal.query.order_by(Renewal.renewal_time.desc()).limit(10).all())
