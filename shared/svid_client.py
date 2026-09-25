"""SPIRE SVID client — Phase 3 workload attestation.

Wraps the SPIFFE Workload API (the `spiffe` py-spiffe SDK) so a caller can
fetch a JWT-SVID scoped to an audience, and the STS can validate one it
receives. Both sides talk to the *local* spire-agent over the Workload API
Unix domain socket, mounted into the pod via the SPIFFE CSI driver
(csi.spiffe.io) — only a pod SPIRE has actually attested (k8s_psat node
attestation + k8s workload attestor matching its namespace/service account)
can reach a socket there at all, so a usable connection is itself part of
the proof.

validate_svid_jwt() does not parse or verify the token itself: it delegates
to the local spire-agent's ValidateJWTSVID RPC, which checks the signature
against the trust bundle spire-agent maintains and the audience/expiry
claims. This module only translates that into the workload_id (SPIFFE ID)
the caller is proven to hold, or None.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("svid_client")

WORKLOAD_API_SOCKET = os.getenv(
    "SPIFFE_ENDPOINT_SOCKET", "unix:///spiffe-workload-api/spire-agent.sock"
)


def fetch_svid_jwt(audience: str) -> str:
    """Fetch a JWT-SVID from the local SPIRE Workload API, scoped to `audience`.

    Raises whatever the Workload API client raises (e.g. FetchJwtSvidError) if
    the socket is unreachable or no SVID could be issued — callers should let
    this surface as a hard failure rather than silently falling back, since a
    missing SVID means this workload was never attested by SPIRE.
    """
    from spiffe.workloadapi.workload_api_client import WorkloadApiClient

    client = WorkloadApiClient(socket_path=WORKLOAD_API_SOCKET)
    try:
        svid = client.fetch_jwt_svid(audience={audience})
        return svid.token
    finally:
        client.close()


def validate_svid_jwt(token: str, audience: str) -> Optional[str]:
    """Validate a JWT-SVID via the local Workload API.

    Returns the verified SPIFFE ID (str) on success, or None on any failure
    (bad signature, wrong/missing audience, expired, socket unreachable).
    Never raises — this sits on the STS's request-authentication path, where
    a validation error and a rejected token mean the same thing: deny.
    """
    from spiffe.workloadapi.workload_api_client import WorkloadApiClient

    client = WorkloadApiClient(socket_path=WORKLOAD_API_SOCKET)
    try:
        svid = client.validate_jwt_svid(token, audience)
        return str(svid.spiffe_id)
    except Exception as e:  # noqa: BLE001 - any failure here means "deny"
        log.warning("SVID validation failed: %s", e)
        return None
    finally:
        client.close()
