"""Certificate Transparency monitoring via the public crt.sh API.

crt.sh aggregates certificates from CT logs. We query recent certificates
whose names contain the protected domain, then feed every distinct hostname
through the look-alike detector. Findings are de-duplicated in the database
and new look-alikes trigger an alert.
"""
from datetime import datetime

import requests

from ..extensions import db
from ..models import Alert, CTFinding
from .similarity import analyze_similarity

CRT_SH_URL = "https://crt.sh/"


def query_crtsh(domain: str, timeout: int = 30) -> list:
    """Return raw crt.sh rows for certificates mentioning the domain."""
    resp = requests.get(CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"},
                        timeout=timeout, headers={"User-Agent": "CertWatchLab/1.0"})
    resp.raise_for_status()
    return resp.json()


def scan_ct(domain: str, alert_callback=None) -> dict:
    """Scan CT logs for one protected domain. Returns a summary dict."""
    rows = query_crtsh(domain)
    candidates = set()
    issuer_by_name = {}
    for row in rows:
        for name in row.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name:
                candidates.add(name)
                issuer_by_name.setdefault(name, row.get("issuer_name", ""))

    new_findings, total = [], 0
    for name in candidates:
        score, level, reason = analyze_similarity(domain, name)
        if score < 55:  # only record Medium and above as findings
            continue
        total += 1
        finding = CTFinding.query.filter_by(protected_domain=domain,
                                            detected_domain=name).first()
        if finding:
            finding.last_seen = datetime.utcnow()
            finding.similarity_score = score
            finding.risk_level = level
            finding.reason = reason
        else:
            finding = CTFinding(protected_domain=domain, detected_domain=name,
                                similarity_score=score, risk_level=level,
                                reason=reason, issuer=issuer_by_name.get(name, ""))
            db.session.add(finding)
            new_findings.append(finding)
    db.session.commit()

    if alert_callback:
        for finding in new_findings:
            alert_callback(
                alert_type="lookalike",
                severity="High" if finding.risk_level in ("Critical", "High") else "Warning",
                domain=domain,
                message=(f"Possible look-alike domain found in CT logs: "
                         f"'{finding.detected_domain}' is {finding.similarity_score}% "
                         f"similar to '{domain}' ({finding.risk_level} risk). "
                         f"Issuer: {finding.issuer or 'unknown'}"))

    return {"domain": domain, "ct_entries": len(rows),
            "candidates": len(candidates), "findings": total,
            "new_findings": len(new_findings)}
