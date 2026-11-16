"""Small security helpers: CSRF tokens, login rate limiting, domain validation
and SSRF protection for outbound scans.

Kept dependency-free and readable so each rule can be explained in a viva.
"""
import ipaddress
import re
import secrets
import socket
import threading
import time

from flask import abort, current_app, request, session

# ---------------------------------------------------------------- CSRF ----

def generate_csrf_token() -> str:
    """One random token per session, embedded in every form."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def csrf_protect():
    """Registered as before_request: reject state-changing requests without
    the session's token. Compare in constant time."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = session.get("_csrf_token", "")
        sent = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, sent):
            abort(400, description="Invalid or missing CSRF token.")


# ------------------------------------------------------- rate limiting ----
_login_attempts = {}  # ip -> list of attempt timestamps
_attempts_lock = threading.Lock()


def login_rate_limited(ip: str) -> bool:
    """True when this IP has too many failed logins inside the time window."""
    max_attempts = current_app.config["MAX_LOGIN_ATTEMPTS"]
    window = current_app.config["LOGIN_WINDOW_MINUTES"] * 60
    now = time.time()
    with _attempts_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < window]
        _login_attempts[ip] = attempts
        return len(attempts) >= max_attempts


def record_failed_login(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


def clear_failed_logins(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.pop(ip, None)


# ---------------------------------------------- domain validation / SSRF --
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class DomainValidationError(ValueError):
    pass


def clean_domain(value: str) -> str:
    """Normalize a user-typed domain: lowercase, strip scheme/path/port,
    remove a leading wildcard, convert IDN names to punycode."""
    value = (value or "").strip().lower().rstrip(".")
    value = re.sub(r"^https?://", "", value).split("/", 1)[0].split(":", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise DomainValidationError("Domain name contains invalid characters.")
    return value


def validate_domain(value: str) -> str:
    """Return a safe normalized domain or raise DomainValidationError."""
    domain = clean_domain(value)
    if not _DOMAIN_RE.match(domain):
        raise DomainValidationError(
            "Enter a valid public domain name, for example certwatchlab.in.")
    return domain


def ssrf_guard(domain: str) -> None:
    """Resolve the domain and refuse destinations that are not public.

    The scanner opens arbitrary hosts on behalf of the user, so without this
    check it could be abused to reach internal services (SSRF). Loopback,
    private, link-local, multicast and reserved addresses are blocked unless
    SCAN_ALLOW_PRIVATE is enabled for a lab environment.
    """
    if current_app.config["SCAN_ALLOW_PRIVATE"]:
        return
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise DomainValidationError(f"Could not resolve domain: {domain}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise DomainValidationError(
                f"Scanning {domain} is not allowed: it resolves to a "
                "non-public address.")
