"""Security Token Service (STS) — the trust broker.

Only the STS may mint tokens for agents. On every RFC 8693 token exchange it:
  1. Authenticates the calling workload — Phase 1: shared-secret headers, or
     Phase 3 (ATTESTATION_MODE=spire): a SPIRE JWT-SVID bearer token,
     validated via the local Workload API rather than trusted from a header.
  2. Verifies via the Agent Registry that the workload is authorized to act as
     the agent it claims — blocking workload->agent impersonation.
  3. Derives the act_chain: anchors it to the human on the first hop, otherwise
     carries forward the inbound token's chain, then appends THIS caller.
  4. Mints a short-lived, single-audience JWT carrying the extended chain.

Because the chain is assembled centrally at every hop, the token that finally
reaches the MCP Gateway carries a cryptographic record of the entire lineage
(user -> oncall -> investigation -> ...), which is what makes full-lineage
authorization and audit possible downstream.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from flask import Flask, jsonify, request

sys.path.insert(0, os.getenv("APP_ROOT", "/app"))
from shared import actchain, jwt_utils, registry  # noqa: E402
from shared.sts_client import (  # noqa: E402
    JWT_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT,
    USER_TOKEN_TYPE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [STS] %(message)s")
log = logging.getLogger("sts")

app = Flask(__name__)
signing_key = jwt_utils.SigningKey()

ATTESTATION_MODE = os.getenv("ATTESTATION_MODE", "shared_secret")  # "shared_secret" | "spire"
STS_AUDIENCE = "sts"  # audience the calling workload's own SVID must be scoped to


def _attest_caller(req) -> tuple[Optional[str], Optional[str]]:
    """Authenticate the calling workload. Returns (workload_id, agent_id), or
    (presented-or-none workload_id, None) if attestation/registry lookup fails.
    """
    if ATTESTATION_MODE == "spire":
        from shared.svid_client import validate_svid_jwt

        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None, None
        svid_jwt = auth_header[len("Bearer "):]
        workload_id = validate_svid_jwt(svid_jwt, audience=STS_AUDIENCE)
        if not workload_id:
            return None, None
        # Identity is already cryptographically proven by the SVID signature
        # check above; only the registry binding remains to verify.
        return workload_id, registry.verify_workload(workload_id, verified=True)

    workload_id = req.headers.get("X-Workload-Id", "")
    workload_secret = req.headers.get("X-Workload-Secret", "")
    return workload_id, registry.verify_workload(workload_id, presented_secret=workload_secret)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/jwks")
def jwks():
    # Public keys, consumed by every agent and the gateway to verify signatures.
    return jsonify(signing_key.jwks())


@app.post("/token")
def token():
    body = request.get_json(force=True, silent=True) or {}

    if body.get("grant_type") != TOKEN_EXCHANGE_GRANT:
        return jsonify(error="unsupported_grant_type"), 400

    # ---- 1. Authenticate the calling workload -----------------------------
    workload_id, agent_id = _attest_caller(request)
    if not agent_id:
        log.warning("DENY unattested workload_id=%s mode=%s",
                     workload_id or "<none>", ATTESTATION_MODE)
        return jsonify(error="invalid_client",
                       error_description="workload attestation failed"), 401
    log.info("ATTEST workload_id=%s agent=%s mode=%s",
              workload_id, agent_id, ATTESTATION_MODE)

    audience = body.get("audience")
    if not audience:
        return jsonify(error="invalid_request",
                       error_description="audience required"), 400

    subject_token = body.get("subject_token", "")
    subject_token_type = body.get("subject_token_type", JWT_TOKEN_TYPE)

    # ---- 2. Derive the inbound chain --------------------------------------
    if subject_token_type == USER_TOKEN_TYPE:
        # First hop: anchor the chain to the human originator.
        inbound_chain = [actchain.user_link(subject_token)]
    elif subject_token_type == JWT_TOKEN_TYPE:
        # Subsequent hop: carry forward the verified inbound token's chain.
        try:
            # Verify the inbound token was minted by us and was addressed to
            # this calling agent (its audience must be this agent_id).
            claims = jwt_utils.verify(
                subject_token,
                audience=agent_id,
                public_pem=signing_key.public_pem(),
            )
        except Exception as e:  # jwt exceptions -> reject
            log.warning("DENY bad subject_token from %s: %s", agent_id, e)
            return jsonify(error="invalid_grant",
                           error_description=f"subject_token rejected: {e}"), 400
        inbound_chain = claims.get("act_chain", [])
    else:
        return jsonify(error="invalid_request",
                       error_description="unsupported subject_token_type"), 400

    # ---- 3. Append THIS caller to the chain -------------------------------
    new_chain = actchain.append(
        inbound_chain, actchain.agent_link(workload_id, agent_id)
    )

    # ---- 4. Mint the short-lived, single-audience token -------------------
    minted = signing_key.mint(
        subject=workload_id,
        audience=audience,
        act_chain=new_chain,
        agent_id=agent_id,
    )
    log.info("MINT agent=%s aud=%s chain=[%s]",
             agent_id, audience, actchain.render(new_chain))

    return jsonify(
        access_token=minted,
        issued_token_type=JWT_TOKEN_TYPE,
        token_type="Bearer",
        expires_in=jwt_utils.DEFAULT_TTL_SECONDS,
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
