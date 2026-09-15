import socket, ssl
from datetime import datetime, timezone

def scan_domain(domain, port=443):
    ctx=ssl.create_default_context()
    with socket.create_connection((domain,port),timeout=10) as sock:
        with ctx.wrap_socket(sock,server_hostname=domain) as s:
            cert=s.getpeercert()
            tls_version=s.version()
            cipher=s.cipher()
    def dt(v): return datetime.strptime(v,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    issuer=", ".join("=".join(x) for group in cert.get("issuer",()) for x in group)
    subject=dict(x for group in cert.get("subject",()) for x in group)
    before=dt(cert["notBefore"]); after=dt(cert["notAfter"])
    days=(after-datetime.now(timezone.utc)).days
    return {"domain":subject.get("commonName",domain),"issuer":issuer,
            "serial_number":cert.get("serialNumber"),"issue_date":before.replace(tzinfo=None),
            "expiry_date":after.replace(tzinfo=None),"tls_version":tls_version,
            "signature_algorithm":"Certificate inspection required","key_length":None,
            "days_remaining":days,"cipher":cipher[0] if cipher else None}

def calculate_risk(data):
    score=0; findings=[]; days=data["days_remaining"]
    if days<0:
        score+=60; findings.append(("Expired certificate","Critical","Certificate has expired."))
    elif days<=7:
        score+=40; findings.append(("Certificate expires soon","High","Certificate expires within 7 days."))
    elif days<=30:
        score+=20; findings.append(("Certificate expiry warning","Medium","Certificate expires within 30 days."))
    if data.get("tls_version") in ("TLSv1","TLSv1.1"):
        score+=30; findings.append(("Outdated TLS version","High",f'{data["tls_version"]} is outdated.'))
    return min(score,100),findings
