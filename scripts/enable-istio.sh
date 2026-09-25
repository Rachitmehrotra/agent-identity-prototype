#!/usr/bin/env bash
# Phase 2: add the mesh. Installs Istio, injects sidecars into the agents ns,
# turns on STRICT mTLS + the SPIFFE-principal AuthorizationPolicies, deploys OPA
# and flips the gateway from hardcoded policy to Rego.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Installing Istio (demo profile)"
istioctl install --set profile=demo -y

echo "==> Restarting workloads so sidecars inject (ns already labeled)"
kubectl rollout restart deploy -n agents
kubectl rollout status  deploy -n agents --timeout=180s

echo "==> Deploying OPA and lifting policy into Rego"
kubectl apply -f k8s/40-opa.yaml
kubectl rollout status deploy/opa -n agents --timeout=120s
kubectl set env deploy/mcp-gateway -n agents \
  OPA_URL=http://opa:8181/v1/data/agent/authz
kubectl rollout status deploy/mcp-gateway -n agents --timeout=120s

echo "==> Enforcing STRICT mTLS + AuthorizationPolicies"
kubectl apply -f k8s/50-istio-mtls-authz.yaml

echo
echo "Phase 2 active. Re-run ./scripts/demo.sh — traffic is now mTLS and policy"
echo "decisions come from OPA. Install addons + view the mesh with enable-observability.sh"
