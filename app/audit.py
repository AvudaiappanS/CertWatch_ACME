"""Audit logging helper. Records who did what, when, and how it ended.

Never log secrets: passwords, session tokens, private keys or SMTP
credentials must not appear in action summaries.
"""
from flask import session

from .extensions import db
from .models import AuditLog


def audit(action: str, obj: str = "", outcome: str = "SUCCESS",
          summary: str = "", username: str = None, role: str = None) -> None:
    entry = AuditLog(
        username=username if username is not None else session.get("username", "system"),
        role=role if role is not None else session.get("role", "system"),
        action=action, object=obj, outcome=outcome,
        summary=summary[:490])
    db.session.add(entry)
    db.session.commit()
