#!/usr/bin/env bash
# Happy path: human -> oncall -> investigation -> gateway -> downstream.
# You should see the act_chain grow one link per hop and a PR URL attributed to
# the full lineage.
set -euo pipefail

USER_ID="${USER_ID:-rachit@example.com}"
TASK="${TASK:-fix misconfigured alert}"

MODE="$(kubectl get deploy/sts -n agents \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ATTESTATION_MODE")].value}')"
echo "==> Workload attestation mode: ${MODE:-shared_secret (Phase 1 default)}"

echo "==> Triggering oncall-agent as ${USER_ID}"
kubectl exec -n agents deploy/oncall-agent -- \
  python -c "
import json, urllib.request
req = urllib.request.Request(
    'http://localhost:8080/start',
    data=json.dumps({'user_id': '${USER_ID}', 'task': '${TASK}'}).encode(),
    headers={'Content-Type': 'application/json'})
print(json.dumps(json.loads(urllib.request.urlopen(req).read()), indent=2))
"

echo
echo "==> Workload attestation (SVID/secret presented + verified, per hop):"
for d in oncall-agent investigation-agent monitoring-agent sts; do
  kubectl logs -n agents deploy/"$d" | grep ATTEST | tail -2 || true
done
echo
echo "==> STS MINT events (chain grows per hop):"
kubectl logs -n agents deploy/sts | grep MINT | tail -5 || true
echo
echo "==> Gateway AUDIT decision:"
kubectl logs -n agents deploy/mcp-gateway | grep AUDIT | tail -3 || true
echo
echo "==> Downstream PR record:"
kubectl logs -n agents deploy/downstream | grep "PR opened" | tail -3 || true
