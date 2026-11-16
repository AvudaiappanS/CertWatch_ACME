"""Minimal ACME v2 (RFC 8555) client for HTTP-01 certificate issuance.

Works against three directory servers, selected by configuration:

    pebble      - local test CA running in Docker (no real validation)
    staging     - Let's Encrypt staging (real HTTP-01 validation, untrusted certs)
    production  - Let's Encrypt production (real trusted certificates;
                  only used when ALLOW_PRODUCTION_ACME=true)

The protocol flow, written out step by step so it can be explained:

 1. Load or create an ACME account key (EC P-256) and register the account.
 2. Create a new order for the domain.
 3. Read the authorization, pick the http-01 challenge, compute the
    key authorization = token + "." + JWK thumbprint.
 4. Write the key authorization to ACME_STORAGE/challenges/<token>; the web
    app serves it at /.well-known/acme-challenge/<token>.
 5. Tell the CA the challenge is ready, then poll until it is valid.
 6. Generate a fresh EC key + CSR for the domain and finalize the order.
 7. Poll the order, download the issued certificate chain, store it in PEM.
"""
import base64
import hashlib
import json
import os
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class ACMEError(Exception):
    pass


def _b64(data: bytes) -> str:
    """URL-safe base64 without padding, as JWS requires."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class ACMEClient:
    def __init__(self, directory_url: str, storage_dir: str, email: str = "",
                 ca_cert_path: str = None, poll_timeout: int = 120,
                 session: requests.Session = None):
        self.directory_url = directory_url
        self.storage_dir = storage_dir
        self.email = email
        self.poll_timeout = poll_timeout
        self.session = session or requests.Session()
        # Pebble uses a self-signed CA; verify against its root when provided.
        self.verify = ca_cert_path if (ca_cert_path and os.path.exists(ca_cert_path)) else True
        os.makedirs(os.path.join(storage_dir, "challenges"), exist_ok=True)
        os.makedirs(os.path.join(storage_dir, "accounts"), exist_ok=True)
        os.makedirs(os.path.join(storage_dir, "certs"), exist_ok=True)
        self.account_key_path = os.path.join(
            storage_dir, "accounts",
            hashlib.sha256(directory_url.encode()).hexdigest()[:16] + ".key.pem")
        self.account_key = self._load_or_create_account_key()
        directory = self.session.get(directory_url, verify=self.verify, timeout=30).json()
        self.new_nonce_url = directory["newNonce"]
        self.new_account_url = directory["newAccount"]
        self.new_order_url = directory["newOrder"]
        self.account_url = self._register_account()

    # ------------------------------------------------------------- keys ---
    def _load_or_create_account_key(self):
        if os.path.exists(self.account_key_path):
            with open(self.account_key_path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
        with open(self.account_key_path, "wb") as fh:
            fh.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.account_key_path, 0o600)
        return key

    def _jwk(self):
        numbers = self.account_key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256",
                "x": _b64(numbers.x.to_bytes(32, "big")),
                "y": _b64(numbers.y.to_bytes(32, "big"))}

    def _thumbprint(self) -> str:
        canonical = json.dumps(self._jwk(), separators=(",", ":"), sort_keys=True).encode()
        return _b64(hashlib.sha256(canonical).digest())

    # ------------------------------------------------------------ JWS -----
    def _nonce(self) -> str:
        return self.session.head(self.new_nonce_url, verify=self.verify,
                                 timeout=30).headers["Replay-Nonce"]

    def _post(self, url: str, payload: dict, use_kid: bool = True,
              post_as_get: bool = False) -> requests.Response:
        """Sign the payload as a JWS and POST it; retry once on badNonce.

        RFC 8555 section 6.3: fetching a resource is a POST with an EMPTY
        payload (""), called POST-as-GET. Sending {} instead is treated as an
        update request and rejected by strict servers.
        """
        for attempt in range(2):
            protected = {"alg": "ES256", "nonce": self._nonce(), "url": url}
            if use_kid:
                protected["kid"] = self.account_url
            else:
                protected["jwk"] = self._jwk()
            protected_b64 = _b64(json.dumps(protected).encode())
            payload_b64 = "" if post_as_get else _b64(json.dumps(payload).encode())
            signing_input = f"{protected_b64}.{payload_b64}".encode()
            # JWS needs the raw R||S signature (64 bytes for P-256), not the
            # DER encoding that cryptography returns - RFC 7515.
            sig_der = self.account_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(sig_der)
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            body = {"protected": protected_b64, "payload": payload_b64,
                    "signature": _b64(signature)}
            # RFC 8555 section 6.2: JWS posts must use application/jose+json,
            # strict ACME servers (Pebble -strict, Let's Encrypt) reject plain JSON.
            resp = self.session.post(url, data=json.dumps(body),
                                     headers={"Content-Type": "application/jose+json"},
                                     verify=self.verify, timeout=30)
            if not (resp.status_code == 400 and "badNonce" in resp.text):
                return resp
        return resp

    @staticmethod
    def _check(resp: requests.Response, step: str) -> dict:
        if resp.status_code >= 400:
            raise ACMEError(f"ACME {step} failed (HTTP {resp.status_code}): {resp.text[:300]}")
        return resp.json() if resp.content else {}

    # ------------------------------------------------------- protocol -----
    def _register_account(self) -> str:
        contact = [f"mailto:{self.email}"] if self.email else []
        resp = self._post(self.new_account_url,
                          {"termsOfServiceAgreed": True, "contact": contact},
                          use_kid=False)
        data = self._check(resp, "account registration")
        return resp.headers.get("Location") or data.get("account") or self.account_key_path

    def issue_certificate(self, domain: str) -> dict:
        """Run the full issuance flow. Returns paths and validity dates."""
        # 2. New order
        order_resp = self._post(self.new_order_url,
                                {"identifiers": [{"type": "dns", "value": domain}]})
        order = self._check(order_resp, "order creation")
        order_url = order_resp.headers["Location"]

        # 3-5. HTTP-01 challenge
        authz_url = order["authorizations"][0]
        authz = self._check(self._post(authz_url, {}, post_as_get=True), "authorization fetch")
        challenge = next(c for c in authz["challenges"] if c["type"] == "http-01")
        key_auth = f"{challenge['token']}.{self._thumbprint()}"
        challenge_path = os.path.join(self.storage_dir, "challenges", challenge["token"])
        with open(challenge_path, "w") as fh:
            fh.write(key_auth)
        try:
            self._check(self._post(challenge["url"], {}), "challenge trigger")
            deadline = time.time() + self.poll_timeout
            while True:
                authz = self._check(self._post(authz_url, {}, post_as_get=True), "challenge poll")
                if authz["status"] == "valid":
                    break
                if authz["status"] == "invalid":
                    raise ACMEError(f"HTTP-01 challenge failed: {json.dumps(authz)[:300]}")
                if time.time() > deadline:
                    raise ACMEError("Timed out waiting for HTTP-01 validation")
                time.sleep(2)

            # 6. Finalize with a fresh domain key and CSR
            domain_key = ec.generate_private_key(ec.SECP256R1())
            csr = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]),
                                  critical=False)
                   .sign(domain_key, hashes.SHA256()))
            csr_der = csr.public_bytes(serialization.Encoding.DER)
            self._check(self._post(order["finalize"], {"csr": _b64(csr_der)}), "finalize")

            # 7. Download the certificate
            deadline = time.time() + self.poll_timeout
            while True:
                order = self._check(self._post(order_url, {}, post_as_get=True), "order poll")
                if order["status"] == "valid":
                    break
                if order["status"] == "invalid":
                    raise ACMEError(f"Order became invalid: {json.dumps(order)[:300]}")
                if time.time() > deadline:
                    raise ACMEError("Timed out waiting for certificate issuance")
                time.sleep(2)
            cert_pem = self._post(order["certificate"], {}, post_as_get=True).text
        finally:
            if os.path.exists(challenge_path):
                os.remove(challenge_path)

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        safe = domain.replace("*", "wildcard")
        cert_path = os.path.join(self.storage_dir, "certs", f"{safe}.crt.pem")
        key_path = os.path.join(self.storage_dir, "certs", f"{safe}.key.pem")
        with open(cert_path, "w") as fh:
            fh.write(cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(domain_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        return {"certificate_path": cert_path, "private_key_path": key_path,
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": format(cert.serial_number, "X"),
                "not_before": cert.not_valid_before_utc.replace(tzinfo=None),
                "not_after": cert.not_valid_after_utc.replace(tzinfo=None)}


def client_from_config(config) -> ACMEClient:
    """Build an ACMEClient for the configured mode, with safety checks."""
    mode = config["ACME_MODE"]
    if mode == "pebble":
        return ACMEClient(config["ACME_PEBBLE_DIRECTORY"], config["ACME_STORAGE"],
                          email=config["ACME_EMAIL"], ca_cert_path=config["ACME_CA_CERT"],
                          poll_timeout=config["ACME_POLL_TIMEOUT_SECONDS"])
    if mode == "staging":
        return ACMEClient(config["ACME_STAGING_DIRECTORY"], config["ACME_STORAGE"],
                          email=config["ACME_EMAIL"],
                          poll_timeout=config["ACME_POLL_TIMEOUT_SECONDS"])
    if mode == "production":
        if not config["ALLOW_PRODUCTION_ACME"]:
            raise ACMEError("Production issuance is disabled. Set "
                            "ALLOW_PRODUCTION_ACME=true only after a successful "
                            "staging run.")
        return ACMEClient(config["ACME_PRODUCTION_DIRECTORY"], config["ACME_STORAGE"],
                          email=config["ACME_EMAIL"],
                          poll_timeout=config["ACME_POLL_TIMEOUT_SECONDS"])
    raise ACMEError(f"Unknown ACME_MODE '{mode}' (use pebble, staging or production)")
