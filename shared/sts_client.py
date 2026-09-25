"""STS client SDK — the secure-by-default path every agent uses.

This is the equivalent of Uber's Standardized A2A client: it hides the token
exchange so the *easy* path is also the *secure* path. An agent never hand-rolls
a JWT; it calls exchange() and gets a short-lived, audience-scoped token whose
act_chain already has this agent appended by the STS.

Workload authentication (how this agent proves ITS identity to the STS, prior
to and independent of the act_chain the STS mints) is selected by
ATTESTATION_MODE, and swapping it does not change exchange()'s signature —
only how _attest_headers() proves who's calling:
  - "shared_secret" (Phase 1, default): mocked with WORKLOAD_ID + WORKLOAD_SECRET
    env vars sent as headers.
  - "spire" (Phase 3): a real SPIRE JWT-SVID fetched from the local Workload
    API socket, scoped to audience "sts", sent as a bearer token. The STS
    derives workload_id from the validated SVID itself rather than trusting
    a client-supplied header.
"""
from __future__ import annotations

import os
import logging
from typing import Dict, List, Optional

import requests

log = logging.getLogger("sts_client")

STS_URL = os.getenv("STS_URL", "http://sts:8080")
WORKLOAD_ID = os.getenv("WORKLOAD_ID", "")       # e.g. spiffe://agents.local/ns/agents/sa/oncall
WORKLOAD_SECRET = os.getenv("WORKLOAD_SECRET", "")  # Phase 1 mock attestation
ATTESTATION_MODE = os.getenv("ATTESTATION_MODE", "shared_secret")  # "shared_secret" | "spire"
STS_AUDIENCE = "sts"  # audience a workload's own SVID is scoped to when calling the STS

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
USER_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"  # first-hop user context


def _attest_headers() -> Dict[str, str]:
    if ATTESTATION_MODE == "spire":
        from shared.svid_client import fetch_svid_jwt

        svid_jwt = fetch_svid_jwt(audience=STS_AUDIENCE)
        # Log the SPIFFE ID we're about to present, not the raw SVID — the
        # JWT itself is a bearer credential and doesn't belong in logs.
        spiffe_id = _jwt_sub(svid_jwt)
        log.info("ATTEST mode=spire workload_id=%s audience=%s", spiffe_id, STS_AUDIENCE)
        return {"Authorization": f"Bearer {svid_jwt}"}
    # Phase 1: shared-secret mock.
    log.info("ATTEST mode=shared_secret workload_id=%s", WORKLOAD_ID)
    return {
        "X-Workload-Id": WORKLOAD_ID,
        "X-Workload-Secret": WORKLOAD_SECRET,
    }


def _jwt_sub(token: str) -> str:
    """Best-effort peek at a JWT's `sub` claim for logging, without verifying
    the signature (we're about to send this token to be verified server-side;
    this is purely so the log line is readable, not a trust decision)."""
    try:
        import base64
        import json

        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64)).get("sub", "<unknown>")
    except Exception:
        return "<unparsed>"


def exchange(
    audience: str,
    subject_token: str,
    subject_token_type: str = JWT_TOKEN_TYPE,
    sts_url: str = STS_URL,
) -> str:
    """Perform an RFC 8693 token exchange for the given next-hop audience.

    subject_token:
        - first hop (from the human): the user id, with type USER_TOKEN_TYPE
        - subsequent hops: the inbound JWT this agent received, type JWT_TOKEN_TYPE

    Returns a new short-lived JWT scoped to `audience`, with this workload's
    agent appended to the act_chain by the STS.
    """
    payload = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "audience": audience,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
    }
    resp = requests.post(
        f"{sts_url}/token",
        json=payload,
        headers=_attest_headers(),
        timeout=5,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"STS token exchange failed ({resp.status_code}): {resp.text}"
        )
    return resp.json()["access_token"]


def first_hop(audience: str, user_id: str, sts_url: str = STS_URL) -> str:
    """Convenience: entry agent exchanges the human's context for a scoped token."""
    return exchange(
        audience=audience,
        subject_token=user_id,
        subject_token_type=USER_TOKEN_TYPE,
        sts_url=sts_url,
    )


def fetch_jwks(sts_url: str = STS_URL) -> Dict:
    resp = requests.get(f"{sts_url}/jwks", timeout=5)
    resp.raise_for_status()
    return resp.json()
