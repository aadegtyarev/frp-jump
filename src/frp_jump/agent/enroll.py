"""One-time enrollment: trade an admin-issued enroll token for this
device's identity (cert, api token, relay connection info), and persist it.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from frp_jump.agent.state import AgentState, save


class EnrollError(RuntimeError):
    pass


def enroll(*, control_url: str, token: str, data_dir: Path) -> AgentState:
    control_url = control_url.rstrip("/")
    try:
        resp = httpx.post(f"{control_url}/api/agent/enroll", json={"token": token}, timeout=30.0)
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
