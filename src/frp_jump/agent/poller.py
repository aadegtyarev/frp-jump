"""Agent sync loop: pull desired state from the server, converge the local
tunnel driver and ssh config to match it.
"""

from __future__ import annotations

import logging
import socket
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from frp_jump.agent import hosts
from frp_jump.agent.state import AgentState, save
from frp_jump.common.api import AGENT_API_PREFIX
from frp_jump.driver.base import (
    ConsumedGrant,
    DesiredState,
    ExposedService,
    ServiceProtocol,
    TunnelDriver,
)

logger = logging.getLogger(__name__)

# Control-plane requests are small metadata calls (never the tunneled
# traffic itself, see common/models.py's module docstring), so one timeout
# covers all of them; still overridable per call for e.g. a slower link.
_HTTP_TIMEOUT_SECONDS = 15.0


class SyncError(RuntimeError):
    pass


class NotConnectedError(SyncError):
    """`disconnect` targeted a connection the server has no record of --
    the desired end state (not connected) is already reached, so this is
    safe for a caller to treat as success (e.g. prune local state anyway)
    rather than as a real failure, unlike other `SyncError`s."""


def _is_bindable(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _allocate_local_port(port_range: range, taken: set[int]) -> int:
    """Pick a free port from ``port_range``, skipping anything already
    handed to another grant this cycle. Binding it here is still a TOCTOU
    (something else could grab it before frpc does) -- but restricting to a
    dedicated range well outside the kernel's ephemeral range, instead of
    asking the OS for `:0`, makes that collision rare instead of routine.
    """
    for port in port_range:
        if port not in taken and _is_bindable(port):
            return port
    raise SyncError(f"no free local port in range {port_range.start}-{port_range.stop - 1}")


def _auth_headers(state: AgentState) -> dict[str, str]:
    return {"Authorization": f"Bearer {state.api_token}"}


def fetch_desired_state(state: AgentState, *, timeout: float = _HTTP_TIMEOUT_SECONDS) -> dict:
    try:
        resp = httpx.get(
            f"{state.control_url}{AGENT_API_PREFIX}/desired-state",
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 200:
        raise SyncError(f"desired-state fetch failed ({resp.status_code}): {resp.text}")
    return resp.json()


def send_heartbeat(
    state: AgentState, *, agent_version: str | None = None, timeout: float = _HTTP_TIMEOUT_SECONDS
) -> None:
    try:
        resp = httpx.post(
            f"{state.control_url}{AGENT_API_PREFIX}/heartbeat",
            json={"agent_version": agent_version},
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 204:
        raise SyncError(f"heartbeat failed ({resp.status_code}): {resp.text}")


def add_device(
    state: AgentState,
    *,
    device_name_hint: str | None = None,
    timeout: float = _HTTP_TIMEOUT_SECONDS,
) -> dict:
    """`client add-device`: mint an enroll token for one more device owned by
    the same person as this one. Returns the server's JSON body (``token``,
    ``device_name_hint``, ``expires_at``)."""
    try:
        resp = httpx.post(
            f"{state.control_url}{AGENT_API_PREFIX}/devices/enroll-tokens",
            json={"device_name_hint": device_name_hint},
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 200:
        raise SyncError(f"add-device failed ({resp.status_code}): {resp.text}")
    return resp.json()


def list_devices(state: AgentState, *, timeout: float = _HTTP_TIMEOUT_SECONDS) -> list[dict]:
    """`client list`: every device owned by the same person as this one."""
    try:
        resp = httpx.get(
            f"{state.control_url}{AGENT_API_PREFIX}/devices",
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 200:
        raise SyncError(f"list failed ({resp.status_code}): {resp.text}")
    return resp.json()


def delete_device(
    state: AgentState, device_name: str, *, timeout: float = _HTTP_TIMEOUT_SECONDS
) -> None:
    """`client delete-device`: permanently remove one of your own devices."""
    try:
        resp = httpx.post(
            f"{state.control_url}{AGENT_API_PREFIX}/devices/{quote(device_name, safe='')}/delete",
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 204:
        raise SyncError(f"delete-device failed ({resp.status_code}): {resp.text}")


def connect(
    state: AgentState,
    *,
    device_name: str,
    target_port: int,
    protocol: ServiceProtocol,
    timeout: float = _HTTP_TIMEOUT_SECONDS,
) -> dict:
    """`client connect`: wire this device up to consume a port on another
    device you own. Returns the server's JSON body (``grant_id``,
    ``exposer_device_name``, ``target_port``, ``protocol``)."""
    try:
        resp = httpx.post(
            f"{state.control_url}{AGENT_API_PREFIX}/connect",
            json={
                "device_name": device_name,
                "target_port": target_port,
                "protocol": protocol.value,
            },
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code != 200:
        raise SyncError(f"connect failed ({resp.status_code}): {resp.text}")
    return resp.json()


def disconnect(
    state: AgentState, *, device_name: str, target_port: int, timeout: float = _HTTP_TIMEOUT_SECONDS
) -> None:
    """`client disconnect`: drop a connection this device made with `connect`."""
    try:
        resp = httpx.post(
            f"{state.control_url}{AGENT_API_PREFIX}/disconnect",
            json={"device_name": device_name, "target_port": target_port},
            headers=_auth_headers(state),
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise SyncError(f"could not reach {state.control_url}: {exc}") from exc
    if resp.status_code == 404:
        raise NotConnectedError(f"not connected: {resp.text}")
    if resp.status_code != 204:
        raise SyncError(f"disconnect failed ({resp.status_code}): {resp.text}")


def build_desired_state(
    state: AgentState,
    remote: dict,
    *,
    data_dir: Path,
    port_range: range,
    revalidate: bool = False,
) -> DesiredState:
    """Turn the server's response into a ``DesiredState``, allocating and
    persisting a stable local port for any newly-seen consumed grant.

    ``revalidate``: re-check that each *already-allocated* port is still
    bindable before trusting it, reallocating if not. Only safe to pass
    True when frpc has not bound anything yet this process's lifetime (the
    very first cycle after a restart) -- once frpc holds a persisted port,
    it is correctly not bindable by us, and revalidating every cycle would
    misread that as "taken by something else" and reallocate forever,
    restarting the tunnel on every poll. See ``run_forever``.
    """
    exposed = tuple(
        ExposedService(grant_id=g["grant_id"], secret=g["secret"], local_port=g["target_port"])
        for g in remote["exposed"]
    )

    changed = False
    taken = set(state.local_ports.values())
    consumed: list[ConsumedGrant] = []
    for g in remote["consumed"]:
        grant_id = g["grant_id"]
        local_port = state.local_ports.get(grant_id)
        needs_allocation = local_port is None
        if not needs_allocation and revalidate and not _is_bindable(local_port):
            taken.discard(local_port)
            needs_allocation = True
        if needs_allocation:
            local_port = _allocate_local_port(port_range, taken)
            state.local_ports[grant_id] = local_port
            changed = True
        taken.add(local_port)
        consumed.append(
            ConsumedGrant(grant_id=grant_id, secret=g["secret"], local_bind_port=local_port)
        )

    # Reclaim ports for grants the server no longer lists (revoked/deleted).
    current_grant_ids = {g["grant_id"] for g in remote["consumed"]}
    for stale_id in set(state.local_ports) - current_grant_ids:
        del state.local_ports[stale_id]
        changed = True

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
    """SSH ``Host`` alias per consumed SSH grant: the local `connect` profile
    name for it if one exists, else the exposing device's own name (the
    common case -- one SSH connection per device). Service names are a
    private server-side implementation detail (see
    ``registry.find_or_create_service``) and never shown here."""
    profile_by_target = {(p.device_name, p.target_port): name for name, p in state.profiles.items()}
    ssh_entries: list[tuple[str, int]] = []
    seen_aliases: set[str] = set()
    for g in remote["consumed"]:
        if g["protocol"] != ServiceProtocol.SSH.value:
            continue
        alias = profile_by_target.get(
            (g["exposer_device_name"], g["target_port"]), g["exposer_device_name"]
        )
        if alias in seen_aliases:
            # A `connect --as <name>` profile can collide with another
            # grant's fallback (the exposing device's own name) -- ssh
            # config is first-match-wins, so a silent second `Host <alias>`
            # block would make `ssh <alias>` land on whichever grant this
            # dict happened to list first, and could flip between polls.
            # Keep only the first and say so, rather than guess.
            logger.warning(
                "ssh alias %r used by more than one connection -- keeping the "
                "first, `disconnect` or `connect --as <other-name>` the rest",
                alias,
            )
            continue
        seen_aliases.add(alias)
        ssh_entries.append((alias, state.local_ports[g["grant_id"]]))
    managed_path = hosts.write_ssh_config(data_dir, ssh_entries)
    hosts.ensure_include(ssh_config_path, managed_path)


def sync_once(
    state: AgentState,
    driver: TunnelDriver,
    *,
    data_dir: Path,
    ssh_config_path: Path,
    port_range: range,
    agent_version: str | None = None,
    revalidate_ports: bool = False,
) -> DesiredState:
    """One full cycle: heartbeat, pull desired state, apply it, refresh ssh config."""
    send_heartbeat(state, agent_version=agent_version)
    remote = fetch_desired_state(state)
    desired = build_desired_state(
        state, remote, data_dir=data_dir, port_range=port_range, revalidate=revalidate_ports
    )
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
    port_range: range,
    agent_version: str | None = None,
) -> None:
    # Revalidate persisted local ports only on the first successful cycle
    # after a (re)start -- see build_desired_state's docstring for why this
    # must not happen on every cycle.
    first_cycle = True
    while True:
        try:
            sync_once(
                state,
                driver,
                data_dir=data_dir,
                ssh_config_path=ssh_config_path,
                port_range=port_range,
                agent_version=agent_version,
                revalidate_ports=first_cycle,
            )
            first_cycle = False
        except SyncError as exc:
            logger.warning("sync failed, will retry next cycle: %s", exc)
        except Exception:
            # A long-running daemon must not die from a transient error (a
            # network blip, a server hiccup) -- log and keep polling rather
            # than requiring a process supervisor to notice and restart it.
            logger.exception("unexpected error during sync, will retry next cycle")
        time.sleep(poll_interval_seconds)
