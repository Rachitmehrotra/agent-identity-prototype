"""Agent Registry — the source of truth binding a workload to an agent_id.

This is the control that stops a workload from impersonating an agent it isn't
authorized to host. The STS consults it during every token exchange: it verifies
that the *attested workload* (Phase 1: the shared secret; Phase 3: the SPIRE
SVID) is actually registered to run the agent it claims to be.

In production this would be a real service backed by a datastore. For the
prototype it's a static map loaded from an env-provided JSON or the defaults
below.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Optional

# workload SPIFFE ID -> {agent_id, shared_secret}
_DEFAULT_REGISTRY = {
    "spiffe://agents.local/ns/agents/sa/oncall": {
        "agent_id": "oncall-agent",
        "shared_secret": "oncall-phase1-secret",
    },
    "spiffe://agents.local/ns/agents/sa/investigation": {
        "agent_id": "investigation-agent",
        "shared_secret": "investigation-phase1-secret",
    },
    "spiffe://agents.local/ns/agents/sa/monitoring": {
        "agent_id": "monitoring-agent",
        "shared_secret": "monitoring-phase1-secret",
    },
}


def _load() -> Dict[str, Dict]:
    raw = os.getenv("AGENT_REGISTRY_JSON")
    if raw:
        return json.loads(raw)
    return _DEFAULT_REGISTRY


REGISTRY = _load()


def verify_workload(
    workload_id: str, presented_secret: Optional[str] = None, verified: bool = False
) -> Optional[str]:
    """Return the authorized agent_id if the workload attests correctly, else None.

    `verified=True` (Phase 3) means the caller has already cryptographically
    proven it holds `workload_id` — a SPIRE SVID validated via the Workload
    API — so only the registry binding (is this workload allowed to run as
    this agent at all?) remains to check; no secret comparison happens.

    `verified=False` (Phase 1) falls back to matching `presented_secret`
    against the registry's mock shared secret. Same registry, same
    workload_id -> agent_id contract, different proof of identity.
    """
    entry = REGISTRY.get(workload_id)
    if not entry:
        return None
    if verified:
        return entry["agent_id"]
    if presented_secret != entry.get("shared_secret"):
        return None
    return entry["agent_id"]
