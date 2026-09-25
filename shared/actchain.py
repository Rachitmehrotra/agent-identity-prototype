"""act_chain: the delegation-provenance claim carried inside every minted JWT.

Mirrors Uber's `act_chain` design. Each hop appends the acting entity so the
MCP Gateway (the policy enforcement point) can authorize on the *full* lineage
(user -> agent-1 -> agent-2 -> ...) rather than only the immediate caller.

Index 0 is always the human originator; the last element is the most recent
agent to have performed a token exchange.
"""
from __future__ import annotations

import time
from typing import List, Dict


def user_link(user_id: str) -> Dict:
    """Anchor link for the human originator (first hop)."""
    return {"sub": f"user:{user_id}", "agent_id": None, "iat": int(time.time())}


def agent_link(spiffe_id: str, agent_id: str) -> Dict:
    """A hop performed by an agent workload."""
    return {"sub": spiffe_id, "agent_id": agent_id, "iat": int(time.time())}


def append(chain: List[Dict], link: Dict) -> List[Dict]:
    """Return a new chain with `link` appended. Never mutates the input."""
    return list(chain) + [link]


def subjects(chain: List[Dict]) -> List[str]:
    return [l["sub"] for l in chain]


def agent_ids(chain: List[Dict]) -> List[str]:
    return [l["agent_id"] for l in chain if l.get("agent_id")]


def origin(chain: List[Dict]) -> str:
    """The human originator subject (e.g. 'user:rachit@example.com'), or ''."""
    return chain[0]["sub"] if chain else ""


def render(chain: List[Dict]) -> str:
    """Human-readable chain for logs: user:x -> agent:oncall -> agent:investigation."""
    parts = []
    for l in chain:
        if l.get("agent_id"):
            parts.append(f"agent:{l['agent_id']}")
        else:
            parts.append(l["sub"])
    return " -> ".join(parts)
