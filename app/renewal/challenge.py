"""Serves ACME HTTP-01 challenge files.

The CA fetches http://<domain>/.well-known/acme-challenge/<token> over plain
HTTP, so this blueprint must be reachable on port 80 without a login and
without a redirect to HTTPS.
"""
import os
import re

from flask import Blueprint, Response, current_app

challenge_bp = Blueprint("challenge", __name__)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{10,300}$")


@challenge_bp.route("/.well-known/acme-challenge/<token>")
def serve(token):
    if not _TOKEN_RE.match(token):
        return Response("bad token", status=400)
    path = os.path.join(current_app.config["ACME_STORAGE"], "challenges", token)
    if not os.path.isfile(path):
        return Response("not found", status=404)
    with open(path) as fh:
        return Response(fh.read(), mimetype="text/plain")
