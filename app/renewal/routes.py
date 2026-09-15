from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, session, current_app, flash
from ..models import Certificate, Renewal
from ..extensions import db
from .acme import PebbleACME

renewal_bp = Blueprint("renewal", __name__, url_prefix="/renewal")


@renewal_bp.route("/<int:certificate_id>", methods=["POST"])
def renew(certificate_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    cert = Certificate.query.get_or_404(certificate_id)
    old = cert.expiry_date
    stages = []
    try:
        stages.append("Certificate identified")
        stages.append("ACME renewal requested")
        acme = PebbleACME(
            current_app.config["ACME_DIRECTORY_URL"],
            current_app.config["ACME_CA_CERT"],
            current_app.config["ACME_STORAGE"],
            current_app.config["ACME_EMAIL"],
        )
        stages.append("ACME account ready")
        stages.append("ACME order created")
        result = acme.issue_certificate(cert.domain)
        stages.append("HTTP-01 challenge accepted by Pebble test CA")
        stages.append("New certificate obtained")
        cert.expiry_date = result["new_expiry"]
        cert.status = "Valid (Pebble ACME)"
        cert.issuer = result["issuer"]
        cert.serial_number = result["serial_number"]
        cert.last_scanned = datetime.utcnow()
        renewal = Renewal(
            certificate_id=cert.id,
            old_expiry_date=old,
            new_expiry_date=result["new_expiry"],
            renewal_method="ACME-PEBBLE",
            status="SUCCESS",
        )
        db.session.add(renewal)
        db.session.commit()
        stages.append("Certificate stored and verified")
        return render_template("renewal_result.html", cert=cert, old=old, new=result["new_expiry"], stages=stages, result=result)
    except Exception as exc:
        db.session.rollback()
        db.session.add(Renewal(certificate_id=cert.id, old_expiry_date=old,
                               new_expiry_date=old, renewal_method="ACME-PEBBLE",
                               status="FAILED"))
        db.session.commit()
        flash(f"ACME renewal failed: {exc}")
        return redirect(url_for("dashboard.index"))
