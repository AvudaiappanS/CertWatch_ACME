# Pointing certwatchlab.in at the VPS (GoDaddy)

Let's Encrypt HTTP-01 validation fetches
`http://certwatchlab.in/.well-known/acme-challenge/<token>` from the public
internet, so the domain must resolve to the VPS before any staging or
production issuance.

## Steps

1. Log in at https://dcc.godaddy.com/control/portfolio
2. Select **certwatchlab.in** -> **DNS** -> **DNS Records**.
3. Add / edit records:

   | Type | Name | Value | TTL |
   |------|------|-------|-----|
   | A | @ | <VPS_PUBLIC_IP> | 600 |
   | A | www | <VPS_PUBLIC_IP> | 600 |

4. Delete any parked/forwarding A records for @ that point elsewhere
   (GoDaddy parking IPs usually start with 3.33. / 15.197.).
5. If you added CNAME forwarding earlier ("Domain forwarding"), remove it.

## Verify propagation

```bash
dig +short certwatchlab.in A        # should print the VPS IP
dig +short www.certwatchlab.in A
```

TTL 600 s means changes usually take effect within 10 minutes, but allow up
to an hour. Only proceed to LE_STAGING_TEST.md once both names resolve.
