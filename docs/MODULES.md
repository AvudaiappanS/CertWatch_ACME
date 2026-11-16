# Module guide (viva preparation)

Short, honest descriptions of what each file does and the ideas behind it.

## Entry points
- `run.py` - development server on port 8000.
- `wsgi.py` - Gunicorn entry point for production.
- `config.py` - all configuration from environment variables; tiny built-in
  `.env` loader; every safety switch lives here.

## Core (`app/`)
- `__init__.py` - the application factory: database, blueprints, CSRF hook,
  security headers, health endpoint, first-admin bootstrap, scheduler start.
- `extensions.py` - the shared SQLAlchemy instance (avoids circular imports).
- `models.py` - tables: User, Certificate, ScanResult, Watchlist, CTFinding,
  Renewal, Alert, AuditLog, JobStatus.
- `security.py` - CSRF tokens (one per session, constant-time compare), login
  rate limiting per IP, domain normalization/validation (IDNA, wildcard and
  scheme stripping), and the SSRF guard that refuses non-public IPs.
- `audit.py` - one function that writes an AuditLog row; never logs secrets.
- `scheduler.py` - three APScheduler interval jobs (TLS scan, CT scan,
  renewal + alerts). Runs only when SCHEDULER_ENABLED=true; in Docker only
  the scheduler container sets it, so jobs never run twice. JobStatus rows
  power the dashboard table.

## Features
- `auth/routes.py` - login/logout, change password, admin user management,
  `login_required` and `role_required` decorators. Passwords are stored as
  salted scrypt hashes via Werkzeug.
- `scanner/core.py` - opens a TLS connection, reads the leaf certificate,
  verifies chain + hostname (falls back to an unverified fetch so details of
  broken certs still show, flagged `Verified: NO`), computes the 0-100 risk
  score from days remaining (expired=100, <=7d=90, <=14d=80, <=30d=60,
  <=90d=40, else 20, minus 20 when verified; clamped at 0).
- `scanner/routes.py` - the scan form handler (validates + SSRF-checks the
  domain first) and the certificate detail page.
- `ct_monitor/similarity.py` - look-alike scoring: SequenceMatcher ratio,
  Levenshtein edit distance, character overlap, homoglyph canonicalization
  (0/o, 1/l, 5/s ...), max wins; names containing the protected name are
  floored at 80. Exact matches and real subdomains score 0 (ignored).
  Levels: Critical >=90, High >=75, Medium >=55, else Low.
- `ct_monitor/ct_scanner.py` - queries crt.sh for `%.domain`, expands
  name_value lists, scores each candidate, stores findings >=55, deduplicates
  on (protected, detected), alerts on new findings.
- `renewal/acme_client.py` - a readable ACME v2 (RFC 8555) client: account
  key + registration, order, HTTP-01 challenge (key authorization served from
  `data/acme/challenges/`), polling, CSR finalize, certificate download.
  JWS requests are signed with the ES256 account key. Directories: Pebble,
  Let's Encrypt staging, Let's Encrypt production (opt-in only).
- `renewal/core.py` - the renewal workflow: allowlist check, ACME issuance,
  rescan, Renewal history row, alert on success/failure; `check_and_renew_due`
  is the scheduler's auto-renewal entry (30 days before expiry).
- `renewal/challenge.py` - serves `/.well-known/acme-challenge/<token>` over
  plain HTTP without login; token format is validated before touching disk.
- `alerts/notifier.py` - records every alert; delivers email (SMTP+STARTTLS)
  and webhook only when ALERT_TEST_MODE=false; expiry/expired deduplication.
- `alerts/routes.py` - the alert feed page and the 30/14/7-day threshold
  check used by the scheduler.
- `reports/routes.py` - ReportLab PDF reports (certificates, CT findings,
  renewals) and CSV export.
- `watchlist/routes.py`, `dashboard/routes.py` - watchlist management,
  overview, audit log, read-only settings view (secrets hidden).

## Tests (`tests/`)
46 pytest tests. External services (TLS sockets, crt.sh, the ACME CA) are
mocked, except one deliberately live TLS scan of example.com which is skipped
when there is no network. See FEATURE_CHECKLIST.md for per-feature statuses.

## Design decisions worth explaining
- **Hand-written ACME client** instead of certbot: the project brief asks for
  a demonstrated understanding of ACME; the client follows RFC 8555 step by
  step with comments. Trade-off: less battle-tested than certbot, so Pebble
  and staging are there to exercise it safely.
- **Test-mode alerts default ON** so a fresh install can never spam.
- **SQLite** keeps the lab self-contained; swap DATABASE_URL for PostgreSQL
  if it ever outgrows the VPS.
