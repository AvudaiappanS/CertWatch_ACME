"""Small ACME v2 client used only with the local Pebble test CA.

This implements the core RFC 8555 flow with the cryptography + requests
packages already used by CertWatch:

directory -> account -> order -> authorization -> challenge ->
finalize -> certificate download.

Pebble is configured with PEBBLE_VA_ALWAYS_VALID=1 for a laptop demo,
so the challenge POST is real ACME protocol traffic but Pebble
intentionally skips network ownership validation.

Never use this configuration with production.
"""

import base64
import json
import os
import time
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


def b64(data: bytes) -> str:
    """Base64 URL-safe encoding without '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    """Base64 URL-safe decoding."""
    return base64.urlsafe_b64decode(
        value + "=" * (-len(value) % 4)
    )


def _int_bytes(n: int) -> bytes:
    """Convert integer to unsigned big-endian bytes."""
    return n.to_bytes(
        (n.bit_length() + 7) // 8,
        "big"
    )


def _jwk(key):
    """Create RSA JWK from account key."""
    numbers = key.private_numbers().public_numbers

    return {
        "kty": "RSA",
        "n": b64(_int_bytes(numbers.n)),
        "e": b64(_int_bytes(numbers.e)),
    }


def _load_or_create_account(path):
    """Load existing ACME account key or create a new one."""

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows may not support Unix-style permissions.
        pass

    return key


class PebbleACME:

    def __init__(
        self,
        directory_url,
        ca_cert,
        storage_dir,
        email
    ):
        self.directory_url = directory_url
        self.ca_cert = ca_cert
        self.storage_dir = storage_dir
        self.email = email

        os.makedirs(storage_dir, exist_ok=True)

        # ACME account private key
        account_path = os.path.join(
            storage_dir,
            "account.key.pem"
        )

        self.account_key = _load_or_create_account(
            account_path
        )

        # HTTP session
        self.session = requests.Session()

        # Trust the local Pebble test CA
        self.session.verify = ca_cert

        self.session.headers.update({
            "User-Agent": "CertWatch/1.0 ACME demo"
        })

        # Get ACME directory
        self.directory = self._get(directory_url)

        # Get first Replay-Nonce
        self.nonce = self._new_nonce()

        # ACME account URL
        self.kid = None

    # ---------------------------------------------------------
    # GET REQUEST
    # ---------------------------------------------------------

    def _get(self, url):
        """Perform normal HTTPS GET request."""

        response = self.session.get(
            url,
            timeout=15
        )

        response.raise_for_status()

        return response.json()

    # ---------------------------------------------------------
    # NONCE
    # ---------------------------------------------------------

    def _new_nonce(self):
        """Get a fresh Replay-Nonce from Pebble."""

        response = self.session.head(
            self.directory["newNonce"],
            timeout=15
        )

        if response.status_code not in (200, 204):
            response = self.session.get(
                self.directory["newNonce"],
                timeout=15
            )

        response.raise_for_status()

        nonce = response.headers.get("Replay-Nonce")

        if not nonce:
            raise RuntimeError(
                "ACME server did not return Replay-Nonce"
            )

        return nonce

    # ---------------------------------------------------------
    # SIGNED ACME REQUEST
    # ---------------------------------------------------------

    def _signed_request(
        self,
        url,
        payload,
        use_jwk=False
    ):
        """Send an ACME JWS request.

        IMPORTANT:
        ACME requires POST requests to use:
        application/jose+json
        """

        protected = {
            "alg": "RS256",
            "nonce": self.nonce,
            "url": url,
        }

        # New account request uses JWK.
        # Later requests use the account KID.
        if use_jwk or not self.kid:
            protected["jwk"] = _jwk(
                self.account_key
            )
        else:
            protected["kid"] = self.kid

        # Encode protected header
        protected_b64 = b64(
            json.dumps(
                protected,
                separators=(",", ":")
            ).encode("utf-8")
        )

        # Encode payload
        if payload is None:
            payload_b64 = ""
        else:
            payload_b64 = b64(
                json.dumps(
                    payload,
                    separators=(",", ":")
                ).encode("utf-8")
            )

        # JWS signing input
        signing = (
            f"{protected_b64}.{payload_b64}"
        ).encode("ascii")

        # RSA SHA-256 signature
        signature = self.account_key.sign(
            signing,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # JWS body
        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64(signature),
        }

        # -----------------------------------------------------
        # IMPORTANT FIX
        # -----------------------------------------------------
        # DO NOT use:
        #
        # self.session.post(url, json=body)
        #
        # because requests sends:
        # Content-Type: application/json
        #
        # ACME requires:
        # Content-Type: application/jose+json
        # -----------------------------------------------------

        response = self.session.post(
            url,
            data=json.dumps(
                body,
                separators=(",", ":")
            ),
            headers={
                "Content-Type": "application/jose+json"
            },
            timeout=30,
        )

        # Update Replay-Nonce
        new_nonce = response.headers.get(
            "Replay-Nonce"
        )

        if new_nonce:
            self.nonce = new_nonce

        elif response.status_code in (200, 201):
            self.nonce = self._new_nonce()

        # Handle errors
        if response.status_code >= 400:

            try:
                detail = response.json()
            except Exception:
                detail = response.text

            raise RuntimeError(
                f"ACME request failed "
                f"({response.status_code}): {detail}"
            )

        return response

    # ---------------------------------------------------------
    # ACCOUNT
    # ---------------------------------------------------------

    def _ensure_account(self):
        """Create an ACME account in Pebble."""

        payload = {
            "termsOfServiceAgreed": True,
            "contact": [
                f"mailto:{self.email}"
            ],
        }

        response = self._signed_request(
            self.directory["newAccount"],
            payload,
            use_jwk=True
        )

        self.kid = response.headers.get(
            "Location"
        )

        if not self.kid:
            raise RuntimeError(
                "ACME account response did not include Location"
            )

        return self.kid

    # ---------------------------------------------------------
    # POST-AS-GET
    # ---------------------------------------------------------

    def _post_as_get(self, url):
        """ACME POST-as-GET request."""

        return self._signed_request(
            url,
            None
        )

    # ---------------------------------------------------------
    # WAIT
    # ---------------------------------------------------------

    def _wait(
        self,
        url,
        wanted,
        timeout=30
    ):
        """Wait for an ACME resource to reach desired state."""

        end = time.time() + timeout

        while time.time() < end:

            body = self._post_as_get(
                url
            ).json()

            status = body.get("status")

            if status in wanted:
                return body

            if status in {
                "invalid",
                "revoked",
                "deactivated"
            }:
                raise RuntimeError(
                    f"ACME resource became "
                    f"{status}: {body}"
                )

            time.sleep(1)

        raise TimeoutError(
            f"Timed out waiting for ACME resource: {url}"
        )

    # ---------------------------------------------------------
    # ISSUE CERTIFICATE
    # ---------------------------------------------------------

    def issue_certificate(self, domain):
        """Request and obtain a certificate from Pebble."""

        # -----------------------------------------------------
        # 1. CREATE ACCOUNT
        # -----------------------------------------------------

        self._ensure_account()

        # -----------------------------------------------------
        # 2. CREATE ORDER
        # -----------------------------------------------------

        order_payload = {
            "identifiers": [
                {
                    "type": "dns",
                    "value": domain
                }
            ]
        }

        order_response = self._signed_request(
            self.directory["newOrder"],
            order_payload
        )

        order = order_response.json()

        order_url = order_response.headers.get(
            "Location"
        )

        if not order_url:
            raise RuntimeError(
                "ACME order response did not include Location"
            )

        # -----------------------------------------------------
        # 3. AUTHORIZATION + HTTP-01 CHALLENGE
        # -----------------------------------------------------

        challenge_details = []

        for authz_url in order["authorizations"]:

            authz = self._post_as_get(
                authz_url
            ).json()

            http_challenge = next(
                (
                    challenge
                    for challenge in authz["challenges"]
                    if challenge["type"] == "http-01"
                ),
                None
            )

            if not http_challenge:
                raise RuntimeError(
                    "Pebble did not offer HTTP-01"
                )

            challenge_details.append({
                "url": http_challenge["url"],
                "token": http_challenge["token"]
            })

            # Submit HTTP-01 challenge
            self._signed_request(
                http_challenge["url"],
                {}
            )

            # Wait until authorization becomes valid
            self._wait(
                authz_url,
                {"valid"}
            )

        # -----------------------------------------------------
        # 4. CREATE CERTIFICATE PRIVATE KEY
        # -----------------------------------------------------

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # -----------------------------------------------------
        # 5. CREATE CSR
        # -----------------------------------------------------

        csr = (
            x509.CertificateSigningRequestBuilder()

            .subject_name(
                x509.Name([
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        domain
                    )
                ])
            )

            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain)
                ]),
                critical=False
            )

            .sign(
                key,
                hashes.SHA256()
            )
        )

        csr_der = csr.public_bytes(
            serialization.Encoding.DER
        )

        finalize_payload = {
            "csr": b64(csr_der)
        }

        finalize_url = order["finalize"]

        # -----------------------------------------------------
        # 6. FINALIZE ORDER
        # -----------------------------------------------------

        self._signed_request(
            finalize_url,
            finalize_payload
        )

        # -----------------------------------------------------
        # 7. WAIT FOR CERTIFICATE
        # -----------------------------------------------------

        final_order = self._wait(
            order_url,
            {"valid"}
        )

        cert_url = final_order.get(
            "certificate"
        )

        if not cert_url:
            raise RuntimeError(
                "ACME order became valid "
                "without certificate URL"
            )

        # -----------------------------------------------------
        # 8. DOWNLOAD CERTIFICATE
        # -----------------------------------------------------

        cert_response = self._post_as_get(
            cert_url
        )

        cert_pem = cert_response.content

        # -----------------------------------------------------
        # 9. SAVE CERTIFICATE AND PRIVATE KEY
        # -----------------------------------------------------

        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d%H%M%S")

        safe_domain = domain.replace(
            ".",
            "_"
        )

        cert_path = os.path.join(
            self.storage_dir,
            f"{safe_domain}_{timestamp}.pem"
        )

        key_path = os.path.join(
            self.storage_dir,
            f"{safe_domain}_{timestamp}_key.pem"
        )

        with open(
            cert_path,
            "wb"
        ) as f:
            f.write(cert_pem)

        with open(
            key_path,
            "wb"
        ) as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            )

        try:
            os.chmod(
                key_path,
                0o600
            )
        except OSError:
            pass

        # -----------------------------------------------------
        # 10. READ CERTIFICATE INFORMATION
        # -----------------------------------------------------

        first_certificate = (
            cert_pem
            .split(
                b"-----END CERTIFICATE-----"
            )[0]
            + b"-----END CERTIFICATE-----\n"
        )

        cert = x509.load_pem_x509_certificate(
            first_certificate
        )

        # -----------------------------------------------------
        # 11. RETURN RESULT
        # -----------------------------------------------------

        return {
            "domain": domain,

            "order_url": order_url,

            "certificate_url": cert_url,

            "certificate_path": cert_path,

            "private_key_path": key_path,

            "old_challenge_tokens": challenge_details,

            "new_expiry": (
                cert.not_valid_after_utc
                .replace(tzinfo=None)
            ),

            "serial_number": format(
                cert.serial_number,
                "X"
            ),

            "issuer": cert.issuer.rfc4514_string(),
        }