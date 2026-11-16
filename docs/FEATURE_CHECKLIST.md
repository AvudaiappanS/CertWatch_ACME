# Feature checklist with honest test results

Test environment: Python 3.10.12 sandbox, pytest 9.1.1, Flask 3.1.3,
Flask-SQLAlchemy 3.1.1, APScheduler 3.11.3, reportlab 3.6.8, cryptography 50.0.2.
Run on 2026-10-21: 46 passed, 0 failed. Re-run on 2026-11-16 on this exact
copy: **47 passed, 0 failed** (`python3 -m pytest -q`). Boot check outside
Docker on 2026-11-16: `/health` returns 200, login page renders with CSRF
token.
Statuses: Passed / Failed / Blocked (reason) / Not Run.

## Authentication and access control
| # | Test | Status |
|---|---|---|
| 1 | Valid login redirects to dashboard, audited | Passed |
| 2 | Wrong password rejected + audit row | Passed |
| 3 | POST without CSRF token -> 400 | Passed |
| 4 | Login rate limit after 5 failures / 10 min | Passed |
| 5 | Analyst blocked from admin pages and renewal | Passed |
| 6 | Passwords stored as salted hashes, verify works | Passed |
| 7 | All protected pages redirect to login when anonymous | Passed |

## TLS scanning
| # | Test | Status |
|---|---|---|
| 8 | Risk scoring table (expired=100 ... verified -20, clamp) | Passed (8 cases) |
| 9 | Status/risk labels | Passed |
| 10 | Mocked scan persists Certificate + ScanResult | Passed |
| 11 | Scan failure recorded with error | Passed |
| 12 | **Live TLS scan of example.com** (real network, not mocked) | **Passed** (65 days remaining, TLSv1.3, chain verified) |
| 13 | Domain normalization (case/scheme/wildcard/port/IDN) | Passed |
| 14 | Invalid domains rejected | Passed |
| 15 | SSRF guard blocks private IP targets | Passed (mocked DNS + live localhost test) |

## CT monitoring and look-alike detection
| # | Test | Status |
|---|---|---|
| 16 | Exact match / legitimate subdomain ignored | Passed |
| 17 | Homoglyph certwatch1ab.in -> 100/Critical | Passed |
| 18 | Prefix certwatchlab-login.com -> 80/High | Passed |
| 19 | Unrelated domain -> Low, no finding | Passed |
| 20 | Mocked crt.sh pipeline: findings stored, dedupe, alerts on new only | Passed |
| 21 | **Live crt.sh query** | **Passed on the VPS 2026-11-02** (live CT lookup through the app). Blocked from the original build network (crt.sh HTTP 502, 2026-10-21) |

## Renewal / ACME
| # | Test | Status |
|---|---|---|
| 22 | Full ACME v2 flow against a mocked CA (account, order, HTTP-01, CSR, download, cleanup) | Passed |
| 23 | Production mode refused without explicit opt-in | Passed |
| 24 | Renewal refused for domains outside the allowlist | Passed |
| 25 | Successful renewal recorded in history (mocked client) | Passed |
| 26 | Challenge file served at /.well-known/acme-challenge/<token>; bad tokens rejected | Passed |
| 27 | **Pebble issuance end-to-end in Docker** | **Passed on the VPS 2026-11-02** (Renew now against Pebble succeeded; test certificate valid to 2027-01-31). Laptop: all three containers start with `--profile pebble`; renewal on the laptop itself is unconfirmed |
| 28 | **Let's Encrypt staging issuance** | **Passed 2026-11-02 on the VPS**: staging SUCCESS (test cert to 2027-01-05), then production SUCCESS - real certificate valid to 2027-01-31, serving https://certwatchlab.in |

## Alerts
| # | Test | Status |
|---|---|---|
| 29 | Test mode records alerts without touching SMTP | Passed |
| 30 | 30/14/7 thresholds + expired alert, tightest threshold wins | Passed |
| 31 | Alert deduplication (second run creates none) | Passed |
| 32 | **Real SMTP / webhook delivery** | **Not Run - needs the user's SMTP credentials; test mode is the safe default** |

## Reports
| # | Test | Status |
|---|---|---|
| 33 | Three PDF endpoints return valid PDF (%PDF header) | Passed |
| 34 | CSV export contains header + data row | Passed |

## Operations
| # | Test | Status |
|---|---|---|
| 35 | /health returns {"status":"ok"} | Passed |
| 36 | Security headers (X-Frame-Options, CSP, nosniff) | Passed |
| 37 | Scheduler disabled when SCHEDULER_ENABLED=false (no duplicate jobs) | Passed |
| 38 | JobStatus records runs, errors and counts | Passed |
| 39 | Watchlist add/remove (admin only) + normalization | Passed |
| 40 | **docker compose build + container startup + healthcheck** | **Passed on the VPS 2026-11-02** (web, scheduler and pebble containers up). The packaged compose here additionally binds Pebble to 127.0.0.1; that change is statically verified (YAML parse) but **not re-run in Docker** (no Docker in the packaging sandbox) |
| 41 | **Gunicorn serving** | **Not Run as a server process in the sandbox (gunicorn 26.2.0 installed; WSGI entry `wsgi:app` imports cleanly)** |
| 42 | End-to-end UI walkthrough via test client (login -> scan -> detail -> reports) | Passed |

## Known limitations (honest list)
- crt.sh is sometimes slow/overloaded; the CT scan surfaces the error instead
  of hiding it, and the scheduler retries on its next cycle.
- The ACME client is hand-written for learning purposes; it implements the
  HTTP-01 flow only (no DNS-01, no wildcard certificates).
- SQLite is single-writer; fine for this lab, swap DATABASE_URL for PostgreSQL
  if usage grows.
- HTTP-01 requires port 80 reachable; the app listens there via the Compose
  port mapping until a TLS reverse proxy is added.
