"""One-time enrollment: trade an admin-issued enroll token for this
device's identity (cert, api token, relay connection info), and persist it.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from frp_jump.agent.state import AgentState, save
from frp_jump.common.api import AGENT_API_PREFIX

# Longer than agent/poller.py's routine per-request timeout: enroll also
# does a CA-signing round trip server-side, and it's a one-off interactive
# command, not a background poll -- worth waiting a bit longer for.
_ENROLL_TIMEOUT_SECONDS = 30.0


class EnrollError(RuntimeError):
    pass


def enroll(
    *, control_url: str, token: str, data_dir: Path, requested_name: str | None = None
) -> AgentState:
    control_url = control_url.rstrip("/")
    request_body = {"token": token, "requested_name": requested_name}
    try:
        resp = httpx.post(
            f"{control_url}{AGENT_API_PREFIX}/enroll",
            json=request_body,
            timeout=_ENROLL_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise EnrollError(f"could not reach {control_url}: {exc}") from exc
    if resp.status_code != 200:
        raise EnrollError(f"enroll failed ({resp.status_code}): {resp.text}")

    body = resp.json()
    state = AgentState(
        device_id=body["device_id"],
        device_name=body["device_name"],
        control_url=control_url,
        relay_addr=body["server_addr"],
        relay_port=body["server_port"],
        api_token=body["api_token"],
        cert_pem=body["cert_pem"],
        key_pem=body["key_pem"],
        ca_cert_pem=body["ca_cert_pem"],
    )
    save(data_dir, state)
    return state
