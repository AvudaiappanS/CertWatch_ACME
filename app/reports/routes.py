from flask import Blueprint, Response, session, redirect, url_for
from ..models import Certificate, ScanResult
reports_bp=Blueprint("reports",__name__,url_prefix="/reports")
@reports_bp.route("/csv")
def csv_report():
    if "user_id" not in session: return redirect(url_for("auth.login"))
    rows=["Domain,Status,Expiry,Days Remaining,Risk Score"]
    for c in Certificate.query.all():
        s=ScanResult.query.filter_by(certificate_id=c.id).order_by(ScanResult.scan_time.desc()).first()
        rows.append(f'"{c.domain}","{c.status}","{c.expiry_date}","{s.days_remaining if s else ""}","{s.risk_score if s else ""}"')
    return Response("\n".join(rows),mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=certwatch_report.csv"})
