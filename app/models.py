from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default="Analyst")
    @classmethod
    def create(cls, username, password, role="Analyst"):
        u = cls(username=username, password_hash=generate_password_hash(password), role=role)
        db.session.add(u); db.session.commit(); return u
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Certificate(db.Model):
    __tablename__ = "certificates"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    issuer = db.Column(db.String(255))
    serial_number = db.Column(db.String(255))
    issue_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    tls_version = db.Column(db.String(50))
    signature_algorithm = db.Column(db.String(100))
    key_length = db.Column(db.Integer)
    status = db.Column(db.String(50))
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)

class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"))
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    days_remaining = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    scan_status = db.Column(db.String(50))

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"))
    name = db.Column(db.String(255))
    severity = db.Column(db.String(30))
    description = db.Column(db.Text)
    detection_time = db.Column(db.DateTime, default=datetime.utcnow)

class Renewal(db.Model):
    __tablename__ = "renewals"
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"))
    old_expiry_date = db.Column(db.DateTime)
    new_expiry_date = db.Column(db.DateTime)
    renewal_time = db.Column(db.DateTime, default=datetime.utcnow)
    renewal_method = db.Column(db.String(50))
    status = db.Column(db.String(50))

class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    generating_user = db.Column(db.Integer, db.ForeignKey("users.id"))
    generated_time = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(500))
