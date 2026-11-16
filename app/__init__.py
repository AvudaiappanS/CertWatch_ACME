"""Application factory for CertWatch Lab.

create_app() wires together the database, blueprints, security hooks, the
health endpoint and (optionally) the background scheduler. Everything is
kept inside the factory so tests can build isolated instances.
"""
import os

from flask import Flask, jsonify, redirect, url_for

from config import Config
from .audit import audit
from .extensions import db
from .security import csrf_protect, generate_csrf_token


def create_app(config_object=Config):
    app = Flask(__name__, instance_relative_config=False,
                template_folder="../templates", static_folder="../static")
    app.config.from_object(config_object)

    os.makedirs(app.config["ACME_STORAGE"], exist_ok=True)
    os.makedirs(os.path.join(app.config["ACME_STORAGE"], "challenges"), exist_ok=True)
    os.makedirs(os.path.join(app.config["ACME_STORAGE"], "accounts"), exist_ok=True)
    os.makedirs(os.path.join(app.config["ACME_STORAGE"], "certs"), exist_ok=True)

    db.init_app(app)

    from .models import User  # noqa: E402  (import after db init)
    with app.app_context():
        db.create_all()
        _bootstrap_admin(app, User)

    # --- security hooks ---
    app.before_request(csrf_protect)

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": generate_csrf_token}

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return response

    # --- blueprints ---
    from .auth.routes import auth_bp
    from .dashboard.routes import dashboard_bp
    from .scanner.routes import scanner_bp
    from .ct_monitor.routes import ct_bp
    from .renewal.routes import renewal_bp
    from .watchlist.routes import watchlist_bp
    from .alerts.routes import alerts_bp
    from .reports.routes import reports_bp
    from .renewal.challenge import challenge_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(ct_bp)
    app.register_blueprint(renewal_bp)
    app.register_blueprint(watchlist_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(challenge_bp)

    @app.route("/")
    def index():
        return redirect(url_for("dashboard.dashboard"))

    # Unauthenticated health endpoint for load balancers / uptime checks.
    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    # The scheduler only runs when enabled; Docker Compose starts it as its
    # own container (service "scheduler") so jobs never run twice.
    if app.config["SCHEDULER_ENABLED"]:
        from .scheduler import start_scheduler
        start_scheduler(app)

    return app


def _bootstrap_admin(app, User):
    """Create the first Administrator account on a fresh database.

    The password comes from ADMIN_PASSWORD in the environment; if it is not
    set we generate a random one and print it once to the server log.
    """
    from .models import User as UserModel
    if UserModel.query.count() > 0:
        return
    username = app.config["ADMIN_USERNAME"]
    password = app.config["ADMIN_PASSWORD"]
    if not password:
        import secrets
        password = secrets.token_urlsafe(12)
        app.logger.warning(
            "ADMIN_PASSWORD not set: created admin '%s' with random password: %s "
            "(shown once - log in and change it)", username, password)
    UserModel.create(username=username, password=password, role="Administrator")
    audit("user_created", username, "SUCCESS", "Initial administrator account created",
          username="system", role="system")
