"""JWT minting / verification for the Security Token Service.

KEY PERSISTENCE (the bug fix):
------------------------------
The original prototype generated a fresh RSA keypair on every STS pod start.
Agents and the gateway cached the public key (JWKS), so any STS restart
silently broke signature verification across the whole mesh.

The fix is to load the signing key from a *stable* location. In Kubernetes we
mount it from a Secret at STS_SIGNING_KEY_PATH so it survives restarts and pod
rescheduling. If no key is found we generate one and write it to that path,
logging a loud warning — that path is expected to be backed by a Secret volume
in any real deployment.
"""
from __future__ import annotations

import base64
import logging
import os
import time
import uuid
from typing import Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger("jwt_utils")

ISSUER = os.getenv("STS_ISSUER", "https://sts.agents.local")
KEY_ID = os.getenv("STS_KEY_ID", "sts-signing-key-1")
SIGNING_KEY_PATH = os.getenv("STS_SIGNING_KEY_PATH", "/keys/signing-key.pem")
DEFAULT_TTL_SECONDS = int(os.getenv("STS_TOKEN_TTL_SECONDS", "300"))  # short-lived


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class SigningKey:
    """Wraps the STS RSA private key. Loads from disk or generates+persists."""

    def __init__(self, path: str = SIGNING_KEY_PATH):
        self.path = path
        self._private = self._load_or_create(path)
        self._public = self._private.public_key()

    def _load_or_create(self, path: str) -> rsa.RSAPrivateKey:
        if os.path.exists(path):
            with open(path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            log.info("Loaded persisted STS signing key from %s", path)
            return key  # type: ignore[return-value]

        log.warning(
            "No signing key at %s — generating a new one. In production this "
            "path MUST be backed by a Kubernetes Secret volume, otherwise a "
            "pod restart will rotate the key and break JWT verification "
            "mesh-wide.",
            path,
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(pem)
            log.warning("Persisted freshly generated signing key to %s", path)
        except OSError as e:
            log.error("Could not persist signing key to %s: %s", path, e)
        return key

    def private_pem(self) -> bytes:
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwks(self) -> Dict:
        numbers = self._public.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": KEY_ID,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }

    def mint(
        self,
        subject: str,
        audience: str,
        act_chain: List[Dict],
        agent_id: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        extra_claims: Optional[Dict] = None,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,          # single-hop: valid only for this destination
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,  # short-lived
            "jti": str(uuid.uuid4()),
            "act_chain": act_chain,    # full delegation provenance
        }
        if agent_id:
            claims["agent_id"] = agent_id
        if extra_claims:
            claims.update(extra_claims)
        return jwt.encode(
            claims,
            self.private_pem(),
            algorithm="RS256",
            headers={"kid": KEY_ID},
        )


def verify(
    token: str,
    audience: str,
    public_pem: bytes,
    issuer: str = ISSUER,
) -> Dict:
    """Verify signature, audience, and expiry. Raises jwt exceptions on failure."""
    return jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "aud", "iss"]},
    )
