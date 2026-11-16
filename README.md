# CertWatch Lab

A self-hosted TLS certificate monitoring lab: it scans certificates, watches
Certificate Transparency logs for potentially similar domains that need
investigation, renews its own
certificate through the ACME protocol (Pebble test CA, Let's Encrypt staging,
or Let's Encrypt production), raises alerts, keeps an audit log and produces
PDF/CSV reports.

Built with Flask + SQLite + APScheduler. Ships with Docker Compose for an
Ubuntu 24.04 VPS.

## What it does

| Area | Features |
|---|---|
| Auth | Login/logout, salted password hashes (Werkzeug), roles (Administrator / Analyst), login rate limiting, CSRF tokens on every form |
| TLS scanning | On-demand and scheduled scans, issuer/subject/SAN/serial/validity/TLS version, chain + hostname verification flag, 0-100 risk score with reasons |
| CT monitoring | crt.sh queries, look-alike scoring (string/edit/overlap/homoglyph, prefix floor), findings deduplicated, Critical/High/Medium/Low |
| Renewal | Hand-written ACME v2 (RFC 8555) client, HTTP-01 challenge, modes: `pebble`, `staging`, `production` (production needs explicit opt-in), auto-renew at 30 days, renewal history |
| Alerts | Expiry thresholds 30/14/7 days (deduplicated), expired, look-alike, renewal success/failure; email + webhook; **test mode ON by default** |
| Audit | Every login, scan, watchlist change, renewal and denial is recorded (no secrets) |
| Reports | Certificate / CT findings / renewal PDFs (ReportLab) and CSV export |
| Ops | `/health` endpoint, security headers, scheduled jobs with duplicate-run prevention, job status on the dashboard |

## Quick start (local, Docker)

```bash
cp .env.example .env            # then edit: SECRET_KEY, ADMIN_PASSWORD
openssl rand -hex 32            # good SECRET_KEY value
docker compose --profile pebble up -d --build
# open http://localhost  - log in with ADMIN_USERNAME / ADMIN_PASSWORD
```

With `ACME_MODE=pebble` the **Renew now** button issues a real certificate
from the local Pebble CA (not publicly trusted - that is the point of a test
CA). `pebble.minica.pem` is the root that secures Pebble's own HTTPS ACME
endpoint (the app trusts the Pebble API through it); the certificates Pebble
issues are still test-only.

## Quick start (local, no Docker)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # edit secrets
python run.py                   # http://localhost:8000
```

## Running the tests

```bash
python3 -m pytest -q
```

External services are mocked except one deliberately live TLS scan of
`example.com` (skipped when the network is unavailable). Docker/Pebble tests
are listed in `docs/FEATURE_CHECKLIST.md` with honest statuses.

## Status

Core features are covered by an automated test suite - see
`docs/FEATURE_CHECKLIST.md` for per-feature results, including the 2026-11-02
VPS run (Docker startup, Pebble renewal, then Let's Encrypt staging and
production issuance). The scheduler's jobs are individually tested, but a full
scheduled cycle end-to-end has not been separately observed. Real email and
webhook delivery is untested: `ALERT_TEST_MODE=true` (the default) records
alerts without sending anything.

## Documentation

- `docs/DEPLOY_VPS.md` - deploy on the Ubuntu 24.04 VPS step by step
- `docs/GODADDY_DNS.md` - point certwatchlab.in at the VPS in GoDaddy
- `docs/LE_STAGING_TEST.md` - verify a real Let's Encrypt staging issuance
- `docs/PRODUCTION_CHECKLIST.md` - safe switch from staging to production
- `docs/TROUBLESHOOTING.md` - common errors and fixes
- `docs/MODULES.md` - what every module does (viva preparation)
- `docs/FEATURE_CHECKLIST.md` - every feature with its honest test status

## Security notes

- The scanner refuses non-public targets (SSRF protection) unless
  `SCAN_ALLOW_PRIVATE=true`.
- Renewal only runs for domains in `ALLOWED_RENEWAL_DOMAINS`.
- `ALERT_TEST_MODE=true` is the default: no email/webhook is sent until you
  deliberately turn it off.
- Production ACME issuance requires `ALLOW_PRODUCTION_ACME=true` after a
  successful staging run. Respect Let's Encrypt rate limits.
- In the packaged `docker-compose.yml` the Pebble test CA binds to
  127.0.0.1 only, so a fresh clone cannot expose it publicly; the web and
  scheduler containers reach it over the internal Docker network.
- Secrets live in `.env` (never committed). Audit logs and the settings page
  never show secrets.
