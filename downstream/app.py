"""Downstream mock backend — stands in for source control / observability.

It never sees the agent mesh directly; only the MCP Gateway (after it has
verified identity and authorized the call) reaches it. It echoes back the
audited act_chain so the demo can show the full lineage surviving all the way
to the system that performs the actual mutation — the whole point of the
provenance design.
"""
from __future__ import annotations

import logging
import os
import uuid

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [downstream] %(message)s")
log = logging.getLogger("downstream")

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.post("/pr")
def open_pr():
    body = request.get_json(force=True, silent=True) or {}
    chain = body.get("act_chain", [])
    origin = body.get("origin", "unknown")
    pr_id = uuid.uuid4().hex[:8]
    pr_url = f"https://git.internal.example/repo/pull/{pr_id}"
    rendered = " -> ".join(
        (f"agent:{l['agent_id']}" if l.get("agent_id") else l["sub"])
        for l in chain
    )
    log.info("PR opened %s requested_by=%s chain=[%s]", pr_url, origin, rendered)
    return jsonify(
        pr_url=pr_url,
        requested_by=origin,
        audited_chain=rendered,
        note="Change attributable to the full delegation chain above.",
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
