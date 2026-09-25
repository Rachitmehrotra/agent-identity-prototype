#!/usr/bin/env bash
# Phase 3: swap mock shared-secret attestation for real SPIRE SVIDs.
# Installs the SPIRE server + agent DaemonSet (k8s_psat node attestation),
# registers ClusterSPIFFEIDs so each workload gets a real identity via the
# Workload API socket, then mounts that socket into the STS + the three
# agents and flips them to validate/present SVIDs instead of the Phase 1
# shared secret. workload-secrets is left in place (not deleted) so you can
# roll back to ATTESTATION_MODE=shared_secret without redeploying it.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${CLUSTER:-agent-identity}"
IMAGE="agent-identity:latest"
TRUST_DOMAIN="${TRUST_DOMAIN:-agents.local}"

echo "==> Installing SPIRE via Helm (trust domain ${TRUST_DOMAIN})"
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null
helm repo update >/dev/null
kubectl create namespace spire-server --dry-run=client -o yaml | kubectl apply -f -

echo "==> Installing SPIRE CRDs (spire chart no longer bundles these)"
helm upgrade --install spire-crds spiffe/spire-crds --namespace spire-server

helm upgrade --install spire spiffe/spire \
  --namespace spire-server \
  --set global.spire.trustDomain="${TRUST_DOMAIN}" \
  --set global.spire.clusterName=agent-identity

echo "==> Registering ClusterSPIFFEIDs for each agent workload"
for sa in oncall investigation monitoring; do
  cat <<EOF | kubectl apply -f -
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: agents-${sa}
spec:
  spiffeIDTemplate: "spiffe://${TRUST_DOMAIN}/ns/{{ .PodMeta.Namespace }}/sa/${sa}"
  podSelector:
    matchLabels:
      app: ${sa}-agent
  workloadSelectorTemplates:
    - "k8s:ns:agents"
    - "k8s:sa:${sa}"
EOF
done

echo "==> Rebuilding image (adds the spiffe SDK + svid_client) and loading into kind"
docker build -t "${IMAGE}" .
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

echo "==> Mounting the SPIFFE Workload API socket into STS + the three agents"
# Deliberately done as a `kubectl patch`, not baked into 10-sts.yaml/20-agents.yaml:
# those manifests must keep working standalone in Phase 1/2, before the
# SPIFFE CSI driver (csi.spiffe.io) exists to satisfy this volume. A patch
# only adds the named volume/volumeMount; unlike `kubectl apply`'s 3-way
# merge, it won't try to null out fields (e.g. spec.selector) this partial
# spec omits.
for target in "sts:sts" "oncall-agent:agent" "investigation-agent:agent" "monitoring-agent:agent"; do
  deploy="${target%%:*}"
  container="${target##*:}"
  kubectl patch deployment "${deploy}" -n agents --type strategic -p "$(cat <<EOF
{
  "spec": { "template": { "spec": {
    "volumes": [
      { "name": "spiffe-workload-api", "csi": { "driver": "csi.spiffe.io", "readOnly": true } }
    ],
    "containers": [
      { "name": "${container}",
        "volumeMounts": [
          { "name": "spiffe-workload-api", "mountPath": "/spiffe-workload-api", "readOnly": true }
        ]
      }
    ]
  } } }
}
EOF
)"
done

echo "==> Switching STS + agents to SPIRE SVID attestation"
kubectl set env deploy/sts deploy/oncall-agent deploy/investigation-agent deploy/monitoring-agent \
  -n agents ATTESTATION_MODE=spire

echo "==> Restarting so pods pick up the new image, CSI mount, and SVID attestation"
kubectl rollout restart deploy/sts deploy/oncall-agent deploy/investigation-agent deploy/monitoring-agent -n agents
for d in sts oncall-agent investigation-agent monitoring-agent; do
  kubectl rollout status deploy/"$d" -n agents --timeout=120s
done

echo
echo "SPIRE is up and live: STS validates JWT-SVIDs via the local Workload API,"
echo "and oncall/investigation/monitoring present them instead of the Phase 1"
echo "shared secret. Re-run ./scripts/demo.sh to confirm the happy path still works."
echo "workload-secrets is still present (unused) — safe to delete once you're"
echo "sure you won't roll back to ATTESTATION_MODE=shared_secret."
