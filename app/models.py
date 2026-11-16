"""Database models for CertWatch Lab.

A Certificate has many ScanResults and many Renewals. Watchlist domains are
scanned by the scheduler. CTFinding stores look-alike domains found through
Certificate Transparency data. Alert and AuditLog record what the system did.
"""
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Two roles: Administrator (manage watchlist, renewals, settings) and
    # Analyst (run scans and view results).
    role = db.Column(db.String(40), default="Analyst", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def create(cls, username, password, role="Analyst"):
        user = cls(username=username,
                   password_hash=generate_password_hash(password),
                   role=role)
        db.session.add(user)
        db.session.commit()
        return user

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "Administrator"


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(253), unique=True, nullable=False, index=True)
    subject = db.Column(db.String(500))
    san = db.Column(db.Text)  # comma-separated Subject Alternative Names
    issuer = db.Column(db.String(500))
    serial_number = db.Column(db.String(255))
    issue_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    tls_version = db.Column(db.String(30))
    verified = db.Column(db.Boolean, default=True)  # chain/hostname verification result
    verify_error = db.Column(db.String(300))
    status = db.Column(db.String(40))  # Valid / Expiring Soon / Expired
    days_remaining = db.Column(db.Integer)
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("ScanResult", backref="certificate", lazy=True,
                            cascade="all, delete-orphan")
    renewals = db.relationship("Renewal", backref="certificate", lazy=True,
                               cascade="all, delete-orphan")


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificate.id"), index=True)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    days_remaining = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    risk_reasons = db.Column(db.Text)
    status = db.Column(db.String(30))  # Success / Failed
    error = db.Column(db.String(300))


class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(253), unique=True, nullable=False, index=True)
    added_by = db.Column(db.String(80))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)


class CTFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    protected_domain = db.Column(db.String(253), nullable=False, index=True)
    detected_domain = db.Column(db.String(253), nullable=False)
    similarity_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(30), nullable=False)
    reason = db.Column(db.Text)
    issuer = db.Column(db.String(500))
    ct_entry_id = db.Column(db.String(100))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("protected_domain", "detected_domain"),)


class Renewal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificate.id"), index=True)
    acme_mode = db.Column(db.String(20))       # pebble / staging / production
    challenge_type = db.Column(db.String(20))  # HTTP-01
    old_expiry = db.Column(db.DateTime)
    new_expiry = db.Column(db.DateTime)
    issuer = db.Column(db.String(500))
    serial_number = db.Column(db.String(255))
    status = db.Column(db.String(30))  # SUCCESS / FAILED
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(60))   # expiry / expired / lookalike / renewal_failed / renewal_success
    severity = db.Column(db.String(20))     # Info / Warning / High / Critical
    domain = db.Column(db.String(253), index=True)
    threshold_days = db.Column(db.Integer)  # set for expiry alerts; used for deduplication
    message = db.Column(db.Text)
    channel = db.Column(db.String(120))     # email+webhook / test-mode
    delivery_status = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    username = db.Column(db.String(80))
    role = db.Column(db.String(40))
    action = db.Column(db.String(80), index=True)
    object = db.Column(db.String(253))   # domain / setting / job name
    outcome = db.Column(db.String(30))   # SUCCESS / FAILED / DENIED
    summary = db.Column(db.String(500))  # never contains secrets


class JobStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_name = db.Column(db.String(80), unique=True, nullable=False)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    last_status = db.Column(db.String(30))  # Success / Failed / Never run
    last_error = db.Column(db.String(300))
    run_count = db.Column(db.Integer, default=0)
