# Agent Identity Prototype — Zero Trust for AI Agents

A Kubernetes prototype for cryptographic agent identity and end-to-end
delegation provenance, modeled on Uber's *Solving the Agent Identity Crisis*
but built on an Istio-native / platform-engineering stack.

The core idea: every agent action must be attributable to the **full lineage**
that produced it — `user -> agent -> agent -> tool` — not just the immediate
caller. This is enforced with SPIFFE workload identity, RFC 8693 token exchange,
an `act_chain` JWT claim assembled centrally at every hop, and a policy
enforcement point (the MCP Gateway) that authorizes on the entire chain.

## Architecture

```
  human ──> oncall-agent ──> investigation-agent ──> MCP Gateway ──> downstream
                │                    │                    │  (PEP: verify JWT,
                └──── STS ───────────┘                    │   audit act_chain,
                (RFC 8693 token exchange,                 │   authorize on
                 mints short-lived,                       │   full lineage)
                 single-audience JWTs with                │
                 the act_chain extended                   └──> OPA (Phase 2)
                 one link per hop)
```

| Component | Role |
|---|---|
| **STS** | Only entity that mints agent tokens. Authenticates the workload, verifies the workload→agent binding via the Agent Registry, extends the `act_chain`, mints a short-lived single-audience JWT. |
| **Agents** (oncall / investigation / monitoring) | One image, parameterized by env. Verify inbound JWTs, exchange for the next hop via the STS client SDK, forward the request. |
| **MCP Gateway** | Policy enforcement point. Verifies the JWT, extracts the full `act_chain`, authorizes (hardcoded in Phase 1, OPA/Rego in Phase 2), proxies to downstream. |
| **Downstream** | Mock source-control / observability backend; echoes the audited chain to prove lineage survives to the system of record. |
| **Agent Registry** | Source of truth binding workload SPIFFE ID → authorized `agent_id`. Blocks workload→agent impersonation. |

## Three phases

The build is layered so each phase adds one real-world property:

- **Phase 1 — identity model (this is what `bootstrap.sh` deploys).**
  No mTLS, no SPIRE, no OPA. Workload attestation is mocked with shared secrets
  in a K8s Secret; policy is hardcoded Python; transport is plain HTTP. This
  isolates the *identity and provenance* mechanics so they're easy to inspect.
- **Phase 2 — the mesh (`enable-istio.sh`).** Istio injects sidecars, STRICT
  mTLS is enforced, AuthorizationPolicies pin the allowed call graph by SPIFFE
  principal, and policy lifts into OPA/Rego. Defense in depth: the mesh says
  *who may call whom*; the JWT says *on whose behalf and why*.
- **Phase 3 — real identity + observability (`enable-spire.sh`,
  `enable-observability.sh`).** SPIRE issues real SVIDs via the Workload API
  (k8s_psat node attestation, no static secrets); Kiali/Jaeger/Prometheus/Grafana
  visualize the delegation chain moving across the mesh.

## Run it

### Prerequisites
Docker Desktop, [kind](https://kind.sigs.k8s.io/) ≥ 0.20, kubectl,
and (for Phases 2–3) istioctl + helm. On the new Mac: `brew install kind kubectl istioctl helm`.

### Steps
```bash
./scripts/bootstrap.sh          # kind cluster + build + deploy Phase 1
./scripts/demo.sh               # happy path end-to-end
./scripts/inspect-jwt.sh        # watch the act_chain grow, hop by hop
./scripts/demo-deny.sh          # rejection paths (bad attestation, forged token)

./scripts/enable-istio.sh          # Phase 2: mTLS + OPA
./scripts/enable-observability.sh  # Phase 3 addons + Kiali on :20001
./scripts/enable-spire.sh          # Phase 3: real SVIDs
```

### What you should see
`demo.sh` prints a nested response showing the chain verified at each agent
(`user:rachit@example.com -> agent:oncall-agent -> agent:investigation-agent`),
the gateway's policy decision and the chain it audited, and a fake PR URL from
downstream with the audited chain echoed back. STS logs show a `MINT` per hop;
the gateway logs an `AUDIT` allow/deny.

## The key-persistence fix (baked in)

The original build regenerated the STS RSA keypair on every pod start, so any
STS restart silently broke JWT verification mesh-wide (agents had cached the old
public key). Here the signing key is generated once by `bootstrap.sh` and stored
in the `sts-signing-key` Secret, mounted read-only at `/keys`. The STS loads the
persisted key on startup, so restarts and reschedules keep the same key. See
`shared/jwt_utils.py::SigningKey`.

## Layout
```
shared/        # act_chain model, JWT utils (+ key persistence), STS client SDK, Agent Registry
sts/           # Security Token Service (RFC 8693 trust broker)
agents/        # oncall / investigation / monitoring (one parameterized image)
mcp_gateway/   # policy enforcement point + downstream proxy
downstream/    # mock backend
k8s/           # manifests (00 ns+secrets, 10 sts, 20 agents, 30 gw+downstream, 40 opa, 50 istio)
scripts/       # bootstrap, demo, inspect-jwt, demo-deny, enable-{istio,spire,observability}
Dockerfile     # single image; component chosen per-Deployment via command:
```
