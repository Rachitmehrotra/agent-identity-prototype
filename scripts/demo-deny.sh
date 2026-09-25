#!/usr/bin/env bash
# Negative tests, one per layer in the stack: (1) an unattested workload
# trying to mint a token (STS/SPIRE), (2) a forged token presented at the
# gateway by a caller the mesh already permits (app-layer JWT check, not the
# mesh's own RBAC deny), and (3)/(4) a fully legitimate, correctly-attested,
# correctly-signed request that OPA itself still rejects on policy grounds
# (disallowed tool / disallowed origin) — proving Rego is the real last gate,
# not a rubber stamp the gateway always agrees with.
set -euo pipefail

MODE="$(kubectl get deploy/sts -n agents \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ATTESTATION_MODE")].value}')"
echo "==> Workload attestation mode: ${MODE:-shared_secret (Phase 1 default)}"
echo

echo "==> DENY 1: workload fails attestation to the STS"
# Sends a bad credential for BOTH attestation modes at once (wrong shared
# secret AND a garbage SVID bearer) so this test stays meaningful whichever
# mode the STS is actually running in (ATTESTATION_MODE=shared_secret vs
# spire), without the script needing to know which. STS looks at only the
# header(s) relevant to its own mode and ignores the other pair.
kubectl exec -n agents deploy/oncall-agent -- python -c "
import json, urllib.request, urllib.error
body = json.dumps({'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange',
  'audience':'investigation-agent','subject_token':'x',
  'subject_token_type':'urn:ietf:params:oauth:token-type:id_token'}).encode()
req = urllib.request.Request('http://sts:8080/token', data=body, headers={
  'Content-Type':'application/json',
  'X-Workload-Id':'spiffe://agents.local/ns/agents/sa/oncall',
  'X-Workload-Secret':'WRONG-SECRET',
  'Authorization':'Bearer forged.svid.token'})
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    print('  status', e.code, e.read().decode())
"
echo "  STS side (why attestation actually failed):"
kubectl logs -n agents deploy/sts | grep -E "DENY|SVID validation failed" | tail -2 | sed 's/^/    /'

echo
echo "==> DENY 2: forged token presented at the MCP Gateway"
# Must run from investigation-agent (or monitoring-agent): the gateway's mesh
# AuthorizationPolicy (gateway-allow-agents) only admits those SPIFFE
# principals. Calling from oncall-agent would be rejected at the mesh layer
# (403 RBAC: access denied) before the forged token ever reaches the app's
# JWT check, which is what this test is meant to exercise.
kubectl exec -n agents deploy/investigation-agent -- python -c "
import urllib.request, urllib.error
req = urllib.request.Request('http://mcp-gateway:8080/invoke',
  data=b'{\"tool\":\"open_pr\"}',
  headers={'Content-Type':'application/json','Authorization':'Bearer forged.token.here'})
try:
    urllib.request.urlopen(req)
except urllib.error.HTTPError as e:
    print('  status', e.code, e.read().decode())
"

echo
echo "==> DENY 3: legitimately-attested request, but OPA rejects the tool"
kubectl exec -n agents deploy/investigation-agent -c agent -- python -c "
import sys; sys.path.insert(0, '/app')
from shared import sts_client
import requests
token = sts_client.first_hop('mcp-gateway', 'rachit@example.com')
resp = requests.post('http://mcp-gateway:8080/invoke',
  json={'tool': 'delete_repo'}, headers={'Authorization': f'Bearer {token}'})
print('  status', resp.status_code, resp.json())
"
echo "  STS side (attestation succeeded before OPA rejected the tool):"
kubectl logs -n agents deploy/sts | grep ATTEST | tail -1 | sed 's/^/    /'

echo
echo "==> DENY 4: legitimately-attested request, but OPA rejects the origin"
kubectl exec -n agents deploy/investigation-agent -c agent -- python -c "
import sys; sys.path.insert(0, '/app')
from shared import sts_client
import requests
token = sts_client.first_hop('mcp-gateway', 'someone-else@example.com')
resp = requests.post('http://mcp-gateway:8080/invoke',
  json={'tool': 'open_pr'}, headers={'Authorization': f'Bearer {token}'})
print('  status', resp.status_code, resp.json())
"
echo "  STS side (attestation succeeded before OPA rejected the origin):"
kubectl logs -n agents deploy/sts | grep ATTEST | tail -1 | sed 's/^/    /'
