#!/usr/bin/env bash
# Bootstrap the prototype on a local kind cluster (Phase 1: identity model only).
# Phase 2 (Istio mTLS + OPA) and Phase 3 (SPIRE) are activated by the enable-*
# scripts once this is green.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${CLUSTER:-agent-identity}"
IMAGE="agent-identity:latest"

echo "==> Creating kind cluster '${CLUSTER}' (if absent)"
kind get clusters | grep -qx "${CLUSTER}" || kind create cluster --name "${CLUSTER}"

echo "==> Building image ${IMAGE}"
docker build -t "${IMAGE}" .

echo "==> Loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

echo "==> Applying namespace + secrets"
kubectl apply -f k8s/00-namespace-and-secrets.yaml

echo "==> Generating a PERSISTED STS signing key and storing it in a Secret"
# This is the fix for the ephemeral-key bug: the key lives in a Secret, so pod
# restarts reuse the same key and JWT verification never silently breaks.
TMPKEY="$(mktemp)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${TMPKEY}" 2>/dev/null
kubectl create secret generic sts-signing-key -n agents \
  --from-file=signing-key.pem="${TMPKEY}" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -f "${TMPKEY}"

echo "==> Deploying STS, agents, gateway, downstream"
kubectl apply -f k8s/10-sts.yaml
kubectl apply -f k8s/20-agents.yaml
kubectl apply -f k8s/30-gateway-and-downstream.yaml

echo "==> Waiting for rollouts"
for d in sts oncall-agent investigation-agent monitoring-agent mcp-gateway downstream; do
  kubectl rollout status deploy/"$d" -n agents --timeout=120s
done

echo
echo "Phase 1 is up. Run:  ./scripts/demo.sh"
echo "Then layer the mesh: ./scripts/enable-istio.sh   (Phase 2)"
echo "And real identity:   ./scripts/enable-spire.sh    (Phase 3)"
