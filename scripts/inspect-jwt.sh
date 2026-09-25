#!/usr/bin/env bash
# Manually perform each token exchange and decode the act_chain so you can watch
# it grow. Runs inside the oncall pod (which can reach the STS Service).
set -euo pipefail

USER_ID="${USER_ID:-rachit@example.com}"

kubectl exec -n agents deploy/oncall-agent -- python -c "
import json, base64, urllib.request

STS='http://sts:8080/token'

def decode(tok):
    p = tok.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

def exchange(wid, secret, aud, subject, stype):
    body = json.dumps({
        'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange',
        'audience':aud,'subject_token':subject,'subject_token_type':stype
    }).encode()
    req = urllib.request.Request(STS, data=body, headers={
        'Content-Type':'application/json',
        'X-Workload-Id':wid,'X-Workload-Secret':secret})
    return json.loads(urllib.request.urlopen(req).read())['access_token']

print('HOP 1: oncall exchanges the human context (aud=investigation-agent)')
t1 = exchange('spiffe://agents.local/ns/agents/sa/oncall','oncall-phase1-secret',
              'investigation-agent','${USER_ID}',
              'urn:ietf:params:oauth:token-type:id_token')
print('  act_chain =', [l['sub'] for l in decode(t1)['act_chain']])

print('HOP 2: investigation exchanges that token (aud=mcp-gateway)')
t2 = exchange('spiffe://agents.local/ns/agents/sa/investigation','investigation-phase1-secret',
              'mcp-gateway', t1, 'urn:ietf:params:oauth:token-type:jwt')
c = decode(t2)
print('  act_chain =', [l['sub'] for l in c['act_chain']])
print('  aud       =', c['aud'], ' exp-iat(s) =', c['exp']-c['iat'])
"
