"""Agent sync loop: pull desired state from the server, converge the local
tunnel driver and ssh config to match it.
"""

from __future__ import annotations

import logging
import socket
import time
from pathlib import Path

import httpx

from frp_jump.agent import hosts
from frp_jump.agent.state import AgentState, save
from frp_jump.driver.base import (
    ConsumedGrant,
    DesiredState,
    ExposedService,
    ServiceProtocol,
    TunnelDriver,
)

logger = logging.getLogger(__name__)


class SyncError(RuntimeError):
    pass


def _allocate_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _auth_headers(state: AgentState) -> dict[str, str]:
    return {"Authorization": f"Bearer {state.api_token}"}


def fetch_desired_state(state: AgentState, *, timeout: float = 15.0) -> dict:
    resp = httpx.get(
        f"{state.control_url}/api/agent/desired-state",
        headers=_auth_headers(state),
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise SyncError(f"desired-state fetch failed ({resp.status_code}): {resp.text}")
    return resp.json()


def send_heartbeat(
    state: AgentState, *, agent_version: str | None = None, timeout: float = 15.0
) -> None:
    resp = httpx.post(
        f"{state.control_url}/api/agent/heartbeat",
        json={"agent_version": agent_version},
        headers=_auth_headers(state),
        timeout=timeout,
    )
    if resp.status_code != 204:
        raise SyncError(f"heartbeat failed ({resp.status_code}): {resp.text}")


def build_desired_state(state: AgentState, remote: dict, *, data_dir: Path) -> DesiredState:
    """Turn the server's response into a ``DesiredState``, allocating and
    persisting a stable local port for any newly-seen consumed grant."""
    exposed = tuple(
        ExposedService(grant_id=g["grant_id"], secret=g["secret"], local_port=g["target_port"])
        for g in remote["exposed"]
    )

    changed = False
    consumed: list[ConsumedGrant] = []
    for g in remote["consumed"]:
        grant_id = g["grant_id"]
        local_port = state.local_ports.get(grant_id)
        if local_port is None:
            local_port = _allocate_local_port()
            state.local_ports[grant_id] = local_port
            changed = True
        consumed.append(
            ConsumedGrant(grant_id=grant_id, secret=g["secret"], local_bind_port=local_port)
        )
    if changed:
        save(data_dir, state)

    return DesiredState(
        device_id=state.device_id,
        server_addr=state.relay_addr,
        server_port=state.relay_port,
        ca_cert_pem=state.ca_cert_pem.encode(),
        cert_pem=state.cert_pem.encode(),
        key_pem=state.key_pem.encode(),
        exposed=exposed,
        consumed=tuple(consumed),
    )


def sync_ssh_config(
    state: AgentState, remote: dict, *, data_dir: Path, ssh_config_path: Path
) -> None:
    ssh_entries = [
        (g["service_name"], state.local_ports[g["grant_id"]])
        for g in remote["consumed"]
        if g["protocol"] == ServiceProtocol.SSH.value
    ]
    managed_path = hosts.write_ssh_config(data_dir, ssh_entries)
    hosts.ensure_include(ssh_config_path, managed_path)


def sync_once(
    state: AgentState,
    driver: TunnelDriver,
    *,
    data_dir: Path,
    ssh_config_path: Path,
    agent_version: str | None = None,
) -> DesiredState:
    """One full cycle: heartbeat, pull desired state, apply it, refresh ssh config."""
    send_heartbeat(state, agent_version=agent_version)
    remote = fetch_desired_state(state)
    desired = build_desired_state(state, remote, data_dir=data_dir)
    driver.apply(desired)
    sync_ssh_config(state, remote, data_dir=data_dir, ssh_config_path=ssh_config_path)
    return desired


def run_forever(
    state: AgentState,
    driver: TunnelDriver,
    *,
    data_dir: Path,
    ssh_config_path: Path,
    poll_interval_seconds: float,
    agent_version: str | None = None,
) -> None:
    while True:
        try:
            sync_once(
                state,
                driver,
                data_dir=data_dir,
                ssh_config_path=ssh_config_path,
                agent_version=agent_version,
            )
        except SyncError as exc:
            logger.warning("sync failed, will retry next cycle: %s", exc)
        time.sleep(poll_interval_seconds)
