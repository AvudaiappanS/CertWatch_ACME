"""Watchlist management (Administrator): domains the scheduler scans."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..audit import audit
from ..auth.routes import role_required
from ..extensions import db
from ..models import Watchlist
from ..security import DomainValidationError, validate_domain

watchlist_bp = Blueprint("watchlist", __name__, url_prefix="/watchlist")


@watchlist_bp.route("/")
@role_required("Administrator")
def index():
    from datetime import timedelta

    from flask import current_app

    from ..models import CTFinding, Certificate, JobStatus
    entries = Watchlist.query.order_by(Watchlist.domain).all()
    interval = current_app.config["SCAN_INTERVAL_HOURS"]
    rows = []
    for e in entries:
        cert = Certificate.query.filter_by(domain=e.domain).first()
        last_scan = cert.last_scanned if cert else None
        rows.append({
            "id": e.id,
            "domain": e.domain,
            "days_left": cert.days_remaining if cert else None,
            "status": cert.status if cert else None,
            "last_scan": last_scan,
            "next_scan": (last_scan + timedelta(hours=interval)) if last_scan else None,
            "ct_count": CTFinding.query.filter_by(protected_domain=e.domain).count(),
        })
    interval_label = int(interval) if float(interval).is_integer() else interval
    return render_template("watchlist.html", entries=entries, rows=rows,
                           scan_interval=interval_label,
                           scheduler_enabled=(JobStatus.query.first() is not None)
                                              or current_app.config["SCHEDULER_ENABLED"])


@watchlist_bp.route("/add", methods=["POST"])
@role_required("Administrator")
def add():
    try:
        domain = validate_domain(request.form.get("domain", ""))
    except DomainValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("watchlist.index"))
    if Watchlist.query.filter_by(domain=domain).first():
        flash(f"{domain} is already on the watchlist.", "error")
    else:
        db.session.add(Watchlist(domain=domain, added_by=__import__("flask").session.get("username")))
        db.session.commit()
        audit("watchlist_add", domain, "SUCCESS", "Domain added to watchlist")
        flash(f"{domain} added to the watchlist.", "success")
    return redirect(url_for("watchlist.index"))


@watchlist_bp.route("/remove/<int:entry_id>", methods=["POST"])
@role_required("Administrator")
def remove(entry_id):
    entry = db.session.get(Watchlist, entry_id)
    if entry:
        domain = entry.domain
        db.session.delete(entry)
        db.session.commit()
        audit("watchlist_remove", domain, "SUCCESS", "Domain removed from watchlist")
        flash(f"{domain} removed from the watchlist.", "success")
    return redirect(url_for("watchlist.index"))
