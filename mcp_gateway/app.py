"""MCP Gateway — the Policy Enforcement Point (PEP).

Every tool invocation from the agent mesh funnels through here. The gateway:
  - verifies the JWT was minted by the STS and is addressed to `mcp-gateway`,
  - extracts the full act_chain (user -> ... -> calling agent),
  - authorizes on the ENTIRE lineage, not just the immediate caller,
  - on allow, proxies to the downstream tool and echoes the audited chain.

Phase 1 policy is hardcoded here (allowlisted originators + tools). Phase 2
lifts this into OPA/Rego: this handler instead POSTs the {act_chain, tool}
input to the OPA sidecar and enforces its decision. The verification and
audit logic stay identical.
"""
from __future__ import annotations

import logging
import os
import sys

from flask import Flask, jsonify, request
import requests

sys.path.insert(0, os.getenv("APP_ROOT", "/app"))
from shared import actchain, jwt_utils, sts_client  # noqa: E402

GATEWAY_AUDIENCE = os.getenv("GATEWAY_AUDIENCE", "mcp-gateway")
DOWNSTREAM_URL = os.getenv("DOWNSTREAM_URL", "http://downstream:8080/pr")
OPA_URL = os.getenv("OPA_URL", "")  # set in Phase 2 to enable Rego enforcement

# Phase 1 hardcoded policy.
ALLOWED_ORIGINS = set(
    (os.getenv("ALLOWED_ORIGINS") or "user:rachit@example.com").split(",")
)
ALLOWED_TOOLS = set((os.getenv("ALLOWED_TOOLS") or "open_pr,read_logs").split(","))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [gateway] %(message)s")
log = logging.getLogger("gateway")

app = Flask(__name__)
_pem = None


def sts_public_pem() -> bytes:
    global _pem
    if _pem is None:
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        jwks = sts_client.fetch_jwks()
        k = jwks["keys"][0]

        def _int(b64: str) -> int:
            pad = "=" * (-len(b64) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(b64 + pad), "big")

        pub = RSAPublicNumbers(_int(k["e"]), _int(k["n"])).public_key()
        _pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return _pem


def authorize(chain, tool) -> tuple[bool, str]:
    """Return (allowed, reason). Delegates to OPA if configured, else Phase 1."""
    if OPA_URL:
        resp = requests.post(
            OPA_URL,
            json={"input": {"act_chain": chain, "tool": tool,
                            "origin": actchain.origin(chain)}},
            timeout=5,
        )
        result = resp.json().get("result", {})
        return bool(result.get("allow")), result.get("reason", "opa decision")

    origin = actchain.origin(chain)
    if origin not in ALLOWED_ORIGINS:
        return False, f"origin {origin!r} not allowlisted"
    if tool not in ALLOWED_TOOLS:
        return False, f"tool {tool!r} not permitted"
    return True, "origin and tool permitted"


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.post("/invoke")
def invoke():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing bearer token"), 401
    token = auth[len("Bearer "):]

    try:
        claims = jwt_utils.verify(
            token, audience=GATEWAY_AUDIENCE, public_pem=sts_public_pem()
        )
    except Exception as e:
        log.warning("DENY token verification: %s", e)
        return jsonify(error=f"token verification failed: {e}"), 401

    chain = claims.get("act_chain", [])
    body = request.get_json(force=True, silent=True) or {}
    tool = body.get("tool", "open_pr")

    allowed, reason = authorize(chain, tool)
    log.info("AUDIT tool=%s decision=%s chain=[%s] reason=%s",
             tool, "ALLOW" if allowed else "DENY",
             actchain.render(chain), reason)
    if not allowed:
        return jsonify(decision="DENY", reason=reason,
                       audited_chain=actchain.render(chain)), 403

    # Proxy to the downstream tool, forwarding the audited lineage.
    resp = requests.post(
        DOWNSTREAM_URL,
        json={"tool": tool, "act_chain": chain,
              "origin": actchain.origin(chain)},
        timeout=10,
    )
    return jsonify(
        decision="ALLOW",
        audited_chain=actchain.render(chain),
        tool=tool,
        downstream=resp.json(),
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
