"""Generic agent workload — one image, parameterized by env into oncall /
investigation / monitoring.

Each agent:
  - verifies any inbound JWT was minted by the STS and addressed to it,
  - uses the STS client to exchange for a token scoped to its NEXT_HOP,
  - forwards the request, letting the act_chain grow by exactly one link per hop.

ROLE            AGENT_ID              NEXT_HOP (audience)     calls
oncall          oncall-agent         investigation-agent     investigation svc
investigation   investigation-agent  mcp-gateway             gateway /invoke
monitoring      monitoring-agent     mcp-gateway             gateway /invoke  (alt branch)
"""
from __future__ import annotations

import logging
import os
import sys

from flask import Flask, jsonify, request
import requests

sys.path.insert(0, os.getenv("APP_ROOT", "/app"))
from shared import jwt_utils, sts_client  # noqa: E402

ROLE = os.getenv("AGENT_ROLE", "oncall")
AGENT_ID = os.getenv("AGENT_ID", "oncall-agent")
NEXT_HOP_AUDIENCE = os.getenv("NEXT_HOP_AUDIENCE", "investigation-agent")
NEXT_HOP_URL = os.getenv("NEXT_HOP_URL", "http://investigation-agent:8080/handle")

logging.basicConfig(level=logging.INFO,
                    format=f"%(asctime)s [{ROLE}] %(message)s")
log = logging.getLogger(ROLE)

app = Flask(__name__)

# Public key cached once; the persisted STS signing key makes this safe.
_jwks_pem = None


def sts_public_pem() -> bytes:
    global _jwks_pem
    if _jwks_pem is None:
        # Fetch the STS public key in PEM via the JWKS -> PEM helper.
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        import base64

        jwks = sts_client.fetch_jwks()
        k = jwks["keys"][0]

        def _int(b64: str) -> int:
            pad = "=" * (-len(b64) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(b64 + pad), "big")

        pub = RSAPublicNumbers(_int(k["e"]), _int(k["n"])).public_key()
        from cryptography.hazmat.primitives import serialization

        _jwks_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return _jwks_pem


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", role=ROLE)


@app.post("/start")
def start():
    """Entry point (oncall). Anchors the human, then delegates to the next hop."""
    body = request.get_json(force=True, silent=True) or {}
    user_id = body.get("user_id", "unknown@example.com")
    task = body.get("task", "investigate alert")
    log.info("START user=%s task=%r", user_id, task)

    # First-hop exchange: human context -> token scoped for the next agent.
    token = sts_client.first_hop(NEXT_HOP_AUDIENCE, user_id)
    resp = requests.post(
        NEXT_HOP_URL,
        json={"task": task},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    return jsonify(role=ROLE, downstream=resp.json()), resp.status_code


@app.post("/handle")
def handle():
    """Non-entry agents. Verify inbound token, exchange, delegate onward."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing bearer token"), 401
    inbound = auth[len("Bearer "):]

    try:
        claims = jwt_utils.verify(
            inbound, audience=AGENT_ID, public_pem=sts_public_pem()
        )
    except Exception as e:
        log.warning("DENY inbound token: %s", e)
        return jsonify(error=f"token verification failed: {e}"), 401

    log.info("HANDLE verified chain=[%s]",
             " -> ".join(l["sub"] for l in claims.get("act_chain", [])))

    body = request.get_json(force=True, silent=True) or {}
    task = body.get("task", "")

    # Exchange the inbound token for one scoped to our next hop.
    token = sts_client.exchange(NEXT_HOP_AUDIENCE, inbound)
    resp = requests.post(
        NEXT_HOP_URL,
        json={"task": task, "from": AGENT_ID},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    return jsonify(role=ROLE, downstream=resp.json()), resp.status_code


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
