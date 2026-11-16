# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Scan failed: Could not resolve domain` | DNS typo or no outbound DNS | Check spelling; `dig example.com` on the host |
| Scan refused: "non-public address" | SSRF guard blocked a private/loopback target | Working as designed; for a lab set `SCAN_ALLOW_PRIVATE=true` |
| Login loops back to /login | SECRET_KEY changed, or cookies blocked | Restart once after setting SECRET_KEY; check browser cookies |
| "Too many failed attempts" | Rate limiter (5 failures / 10 min per IP) | Wait 10 minutes; restart the container to reset immediately |
| 400 on every form POST | Missing CSRF token (old page) | Reload the page and resubmit |
| `pull access denied for letsencrypt/pebble` | Old compose image name | Fixed in this ZIP: the image is `ghcr.io/letsencrypt/pebble:latest` |
| Pebble renewal fails: connection to `pebble:14000` refused | Pebble not running | Start with `docker compose --profile pebble up -d` |
| Pebble renewal fails: certificate verify failed | Outdated `pebble.minica.pem` | Copy the current one out of the running container: `docker compose cp pebble:/test/certs/pebble.minica.pem .` then `docker compose up -d --build web scheduler` |
| Staging renewal fails: "unauthorized" / "Invalid response" | DNS not pointing at the VPS, or port 80 blocked | Run the checks in GODADDY_DNS.md; `sudo ufw allow 80/tcp` |
| Staging works, dashboard shows `Verified: NO` | Staging root is untrusted by design | Expected for staging; production certs verify cleanly |
| Renewal refused: "not allowed" | Domain missing from ALLOWED_RENEWAL_DOMAINS | Add it (only for domains you control) and restart |
| No jobs on the dashboard | Scheduler container not running | `docker compose ps`; the web container never runs jobs by design |
| Alerts recorded but no email | `ALERT_TEST_MODE=true` | Configure SMTP and set `ALERT_TEST_MODE=false` |
| crt.sh scan fails with 5xx/timeout | crt.sh is frequently overloaded | Retry later; the scheduler retries daily |
| Container keeps restarting | Port 80 already used (e.g. apache2/nginx preinstalled) | `sudo ss -ltnp | grep :80`, stop the other service |

Logs: `docker compose logs -f web` / `docker compose logs -f scheduler`.
Health: `curl -fsS http://127.0.0.1/health`.
