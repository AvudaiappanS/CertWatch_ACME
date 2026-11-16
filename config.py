"""Central configuration for CertWatch Lab.

Every deployment-specific value is read from an environment variable so the
same code runs on a developer laptop, in Docker, and on the Ubuntu 24.04 VPS.
Copy .env.example to .env (or export the variables) and adjust them there.
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _load_dotenv():
    """Tiny .env loader (no dependency): fills in variables that are not
    already set in the real environment. Docker Compose's env_file does the
    same job for containers."""
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))


def env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    # --- Flask / security ---
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-change-me")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set SESSION_COOKIE_SECURE=true once the site is served over HTTPS.
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.getenv("SESSION_HOURS", "8")))
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "10"))

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///" + os.path.join(DATA_DIR, "certwatch.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Domains ---
    # The primary domain this instance monitors/renews. Renewal for any other
    # domain is refused unless it is also listed in ALLOWED_RENEWAL_DOMAINS.
    PRIMARY_DOMAIN = os.getenv("PRIMARY_DOMAIN", "certwatchlab.in").strip().lower()
    ALLOWED_RENEWAL_DOMAINS = [
        d.strip().lower()
        for d in os.getenv("ALLOWED_RENEWAL_DOMAINS", os.getenv("PRIMARY_DOMAIN", "certwatchlab.in")).split(",")
        if d.strip()
    ]
    # Lab convenience: allow scanning private/loopback targets. Keep false in production (SSRF protection).
    SCAN_ALLOW_PRIVATE = env_bool("SCAN_ALLOW_PRIVATE", False)

    # --- ACME ---
    # pebble = local test CA (Docker), staging = Let's Encrypt staging,
    # production = real publicly trusted certificates (must be enabled explicitly).
    ACME_MODE = os.getenv("ACME_MODE", "pebble").strip().lower()
    ALLOW_PRODUCTION_ACME = env_bool("ALLOW_PRODUCTION_ACME", False)
    ACME_EMAIL = os.getenv("ACME_EMAIL", "")
    ACME_STORAGE = os.getenv("ACME_STORAGE", os.path.join(DATA_DIR, "acme"))
    ACME_CA_CERT = os.getenv("ACME_CA_CERT", os.path.join(BASE_DIR, "pebble.minica.pem"))
    ACME_PEBBLE_DIRECTORY = os.getenv("ACME_PEBBLE_DIRECTORY", "https://pebble:14000/dir")
    ACME_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
    ACME_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
    ACME_POLL_TIMEOUT_SECONDS = int(os.getenv("ACME_POLL_TIMEOUT_SECONDS", "120"))

    # --- Scheduler ---
    SCHEDULER_ENABLED = env_bool("SCHEDULER_ENABLED", True)
    SCAN_INTERVAL_HOURS = float(os.getenv("SCAN_INTERVAL_HOURS", "6"))
    CT_INTERVAL_HOURS = float(os.getenv("CT_INTERVAL_HOURS", "24"))
    RENEWAL_CHECK_INTERVAL_HOURS = float(os.getenv("RENEWAL_CHECK_INTERVAL_HOURS", "24"))
    RENEW_BEFORE_DAYS = int(os.getenv("RENEW_BEFORE_DAYS", "30"))

    # --- Alerts ---
    # Test mode records alerts without sending anything. Default ON so a fresh
    # install can never send unintended mail; set false to deliver for real.
    ALERT_TEST_MODE = env_bool("ALERT_TEST_MODE", True)
    ALERT_THRESHOLDS_DAYS = (30, 14, 7)
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", ""))
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

    # --- First-run admin bootstrap (documented in README) ---
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
