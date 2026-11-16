# Switching from staging to real (production) certificates

Do every step in order. Production rate limits are strict (50 certificates
per registered domain per week, 5 duplicate certificates per week) - a failed
loop can lock you out for days.

- [ ] DNS A records for @ and www resolve to the VPS IP
- [ ] UFW allows 80/tcp; nothing else listens on port 80
- [ ] A staging issuance for the exact same domains SUCCEEDED (LE_STAGING_TEST.md)
- [ ] `.env`: `ACME_MODE=production`, `ALLOW_PRODUCTION_ACME=true`,
      `ACME_EMAIL` set to a real monitored address
- [ ] `docker compose up -d --build`
- [ ] Trigger ONE renewal for certwatchlab.in; confirm SUCCESS in history
- [ ] Dashboard scan shows `Verified: yes` (publicly trusted chain)
- [ ] Enable HTTPS cookies: `SESSION_COOKIE_SECURE=true` (once you front the
      app with TLS, e.g. serve the issued cert via a reverse proxy)
- [ ] Alerts: configure SMTP, then set `ALERT_TEST_MODE=false` and trigger a
      test by adding an almost-due domain to the watchlist
- [ ] Change the admin password; create separate Analyst accounts
- [ ] Backups: `docker run --rm -v certwatch-data:/data -v $PWD:/backup alpine \
      tar czf /backup/certwatch-data-$(date +%F).tgz -C /data .`
- [ ] Auto-renewal is active: the `renewal_and_alerts` job renews at 30 days
      before expiry; confirm it appears on the dashboard job table
