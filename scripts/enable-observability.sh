#!/usr/bin/env bash
# Install the Istio observability addon bundle and open Kiali to watch the
# delegation chain move across the agents namespace over mTLS.
# Pin ISTIO_BRANCH to the minor you installed (e.g. release-1.24, release-1.29).
set -euo pipefail

ISTIO_BRANCH="${ISTIO_BRANCH:-release-1.24}"
BASE="https://raw.githubusercontent.com/istio/istio/${ISTIO_BRANCH}/samples/addons"

echo "==> Installing Kiali + Jaeger + Prometheus + Grafana (${ISTIO_BRANCH})"
for addon in prometheus grafana jaeger kiali; do
  kubectl apply -f "${BASE}/${addon}.yaml"
done
kubectl rollout status deploy/kiali -n istio-system --timeout=180s

echo
echo "==> Port-forwarding Kiali on http://localhost:20001"
echo "    In Kiali: Graph -> namespace 'agents' to see the live mTLS request flow."
kubectl port-forward -n istio-system svc/kiali 20001:20001
