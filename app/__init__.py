import os
from flask import Flask
from config import Config
from .extensions import db


def create_app():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, "templates")
    app = Flask(__name__, template_folder=template_dir)
    app.config.from_object(Config)
    db.init_app(app)

    from .auth.routes import auth_bp
    from .dashboard.routes import dashboard_bp
    from .scanner.routes import scanner_bp
    from .renewal.routes import renewal_bp
    from .reports.routes import reports_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(renewal_bp)
    app.register_blueprint(reports_bp)

    with app.app_context():
        from .models import User
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            User.create("admin", "admin123", "Admin")
    return app
