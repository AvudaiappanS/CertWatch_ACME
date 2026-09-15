from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from .scanner import scan_domain, calculate_risk
from ..extensions import db
from ..models import Certificate, ScanResult, Vulnerability
scanner_bp=Blueprint("scanner",__name__,url_prefix="/scanner")
@scanner_bp.route("/scan",methods=["GET","POST"])
def scan():
    if "user_id" not in session: return redirect(url_for("auth.login"))
    if request.method=="POST":
        domain=request.form["domain"].strip()
        try:
            data=scan_domain(domain); score,findings=calculate_risk(data)
            cert=Certificate.query.filter_by(domain=domain).first()
            if not cert: cert=Certificate(domain=domain); db.session.add(cert)
            for k in ["issuer","serial_number","issue_date","expiry_date","tls_version","signature_algorithm","key_length"]:
                setattr(cert,k,data.get(k))
            cert.status="Expired" if data["days_remaining"]<0 else ("Expiring Soon" if data["days_remaining"]<=30 else "Valid")
            cert.last_scanned=datetime.utcnow(); db.session.commit()
            db.session.add(ScanResult(certificate_id=cert.id,days_remaining=data["days_remaining"],risk_score=score,scan_status="Success"))
            for n,se,d in findings: db.session.add(Vulnerability(certificate_id=cert.id,name=n,severity=se,description=d))
            db.session.commit()
            return render_template("scan_result.html",data=data,score=score,findings=findings)
        except Exception as e: flash(f"Scan failed: {e}")
    return render_template("scan.html")
