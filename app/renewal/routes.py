"""Renewal UI: manual renewal (Administrator only), history and challenge serving."""
from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, send_from_directory, url_for)

from ..alerts.notifier import send_alert
from ..audit import audit
from ..auth.routes import login_required, role_required
from ..models import Renewal
from ..security import DomainValidationError, validate_domain
from .core import RenewalNotAllowed, renew_certificate

renewal_bp = Blueprint("renewal", __name__, url_prefix="/renewal")


@renewal_bp.route("/trigger", methods=["POST"])
@role_required("Administrator")
def trigger():
    try:
        domain = validate_domain(__import__("flask").request.form.get("domain", ""))
        renewal = renew_certificate(current_app._get_current_object(), domain,
                                    alert_callback=send_alert)
    except (DomainValidationError, RenewalNotAllowed) as exc:
        audit("renewal", "", "DENIED", str(exc))
        flash(str(exc), "error")
        return redirect(url_for("renewal.history"))
    if renewal.status == "SUCCESS":
        audit("renewal", domain, "SUCCESS",
              f"Issued via {renewal.acme_mode}, new expiry {renewal.new_expiry}")
    else:
        audit("renewal", domain, "FAILED", (renewal.error or "")[:200])
    ca = {
        "pebble": ("local Pebble test CA", "Pebble",
                   "Pebble is a local test CA. This certificate is not a public "
                   "production certificate and is not used to configure HTTPS for the lab."),
        "staging": ("Let's Encrypt staging environment", "Let's Encrypt (staging)",
                    "This is a Let's Encrypt STAGING certificate. It proves the full "
                    "protocol flow but is not publicly trusted by browsers."),
        "production": ("Let's Encrypt production CA", "Let's Encrypt",
                       "This is a publicly trusted Let's Encrypt certificate."),
    }.get(renewal.acme_mode, ("the configured ACME CA", "The CA", ""))
    return render_template("renewal_result.html", renewal=renewal, domain=domain,
                           ca_name=ca[0], ca_short=ca[1], ca_note=ca[2])


@renewal_bp.route("/history")
@login_required
def history():
    from datetime import timedelta

    from ..models import Certificate, JobStatus
    cfg = current_app.config
    # The scheduler runs in its own container in Docker; its job heartbeats in
    # the shared JobStatus table are the honest signal that auto-renew is live.
    scheduler_alive = JobStatus.query.filter_by(job_name="renewal_and_alerts").first() is not None \
        or JobStatus.query.filter_by(job_name="scan_all_watchlist").first() is not None
    rows = Renewal.query.order_by(Renewal.created_at.desc()).limit(100).all()
    primary = cfg["PRIMARY_DOMAIN"]
    cert = Certificate.query.filter_by(domain=primary).first()
    next_renewal = (cert.expiry_date - timedelta(days=cfg["RENEW_BEFORE_DAYS"])
                    if cert and cert.expiry_date else None)
    mode_label = {"pebble": "Pebble (Test)",
                  "staging": "Let's Encrypt (Staging)",
                  "production": "Let's Encrypt (Production)"}.get(cfg["ACME_MODE"],
                                                                  cfg["ACME_MODE"])
    return render_template("renewals.html", renewals=rows,
                           acme_mode=cfg["ACME_MODE"],
                           allowed=cfg["ALLOWED_RENEWAL_DOMAINS"],
                           primary_domain=primary, cert=cert,
                           next_renewal=next_renewal, mode_label=mode_label,
                           renew_before=cfg["RENEW_BEFORE_DAYS"],
                           scheduler_enabled=scheduler_alive or cfg["SCHEDULER_ENABLED"])
