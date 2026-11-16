# Verifying a real Let's Encrypt staging issuance

Staging certificates are signed by the "(STAGING) Pretend Pear" CA: real
HTTP-01 validation, untrusted chain, no rate-limit risk. This proves the
whole ACME path before touching production.

Prerequisite: DNS resolves to the VPS (GODADDY_DNS.md) and port 80 is open.

## Run

1. In `.env` on the VPS:

   ```
   ACME_MODE=staging
   ACME_EMAIL=<your real email>
   ALLOWED_RENEWAL_DOMAINS=certwatchlab.in,www.certwatchlab.in
   ```

2. `docker compose up -d --build`
3. Log in as Administrator -> **Renewals** -> enter `certwatchlab.in` ->
   **Run ACME renewal**.
4. Expected result within ~30 seconds:
   - Flash message: "Renewed certwatchlab.in via staging."
   - Renewal history shows SUCCESS with the staging issuer and a new expiry
     ~90 days out.
   - Files on disk: `data/acme/certs/certwatchlab.in.crt.pem` and `.key.pem`.
5. The dashboard scan of certwatchlab.in will show `Verified: NO` with a
   message about the untrusted staging root - that is correct and expected
   for staging.

## If it fails

See TROUBLESHOOTING.md - the renewal error text is stored verbatim in the
Renewal history row.
