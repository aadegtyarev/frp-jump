"""frp-backed implementations of TunnelDriver / RelayDriver.

``FrpsRelayDriver`` applies a config change by rewriting frps.toml and
restarting frps -- relay settings change only on an admin action.

``FrpDriver`` (the client side) hot-reloads frpc instead whenever it can.
A device that exposes several services gets a new grant every time
someone connects to another of its ports, and a restart would drop every
live connection through every other grant on that device (an ssh session
dies because a phone opened the web UI). frpc's ``GET /api/reload``
re-reads frpc.toml and, per proxy/visitor name, stops only the entries
whose config changed and starts only the new ones -- verified in frp
v0.70.0, ``client/proxy/proxy_manager.go`` and
``client/visitor/visitor_manager.go`` ``UpdateAll`` (``reflect.DeepEqual``
on each entry). Everything outside proxies/visitors is fixed at process
start and a reload would silently keep the old value, so a change there
(server address, TLS paths or file contents, metadatas/token, transport,
log) still restarts; see ``config.needs_restart``. A failed reload falls
back to a restart too.

The reload needs frpc's ``webServer`` (admin API), and that is a real
attack surface here: every other device of the same owner can reach any
``127.0.0.1`` port of this device through an ordinary grant, and the
admin API can rewrite frpc.toml (``PUT /api/config``) and reload it -- a
remote-config channel into this device. So the webServer is never left
open:

- it binds ``127.0.0.1`` on a random free port, chosen per frpc start;
- every route but ``/healthz`` (an empty 200) requires HTTP basic auth
  (frp's ``webServer.user``/``password``,
  checked in constant time with a 200ms delay per failure, and with both
  empty frp would skip auth entirely, so both are always set), each a
  fresh ``secrets.token_urlsafe(32)`` per frpc start;
- the credentials live only in this process's memory and in frpc.toml,
  which already holds every grant's secret and is written ``0600``.

A peer that tunnels into the port still has to guess 2x256 random bits.
The server does not refuse grants to the admin port: it cannot know it
(random, local, changes every start), and a grant to an arbitrary local
port is the product's purpose -- the authentication is the boundary, not
port filtering. frpc reads ``webServer`` once at start and a reload does
not touch it, so the credentials and port stay the same for the whole
process lifetime; new credentials always mean a new process.

``status()`` still reports per-grant state as ``UNKNOWN`` rather than
querying the admin API; see docs/architecture.md for what a future
improvement here would need (e.g. tailing frpc's log for
hole-punch/fallback messages instead).

Traffic accounting (see ``fetch_all_proxy_traffic``) has the mirror-image
limitation, verified by reading fatedier/frp's own source
(``server/proxy/xtcp.go`` vs. ``server/proxy/stcp.go``/``proxy.go``): frps
only ever counts bytes for a proxy whose data actually flows through it.
A grant's ``stcp`` proxy always does (relay, by construction), so frps's
own admin API gives real numbers for it; a grant's ``xtcp`` proxy, when
hole-punching succeeds, carries data directly between the two frpc
processes, entirely bypassing frps -- and neither frps nor frpc counts
that anywhere. So relayed bytes are the only traffic this project can
ever report; a fully peer-to-peer grant is invisible to any counter and
reports zero despite carrying real traffic.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import socket
from collections.abc import Container
from dataclasses import dataclass
from pathlib import Path

import httpx
import tomli_w

from frp_jump.common.crypto import write_private_key
from frp_jump.driver.base import (
    DesiredState,
    DriverStatus,
    RelayState,
)
from frp_jump.driver.frp.config import build_frpc_config, build_frps_config, needs_restart
from frp_jump.driver.frp.process import ProcessSupervisor, SubprocessSupervisor

logger = logging.getLogger(__name__)

_RELOAD_TIMEOUT = 5.0
_PORT_PICK_ATTEMPTS = 100


def _fingerprint(config: dict) -> str:
    return hashlib.sha256(tomli_w.dumps(config).encode("utf-8")).hexdigest()


def fetch_all_proxy_traffic(admin_port: int, *, timeout: float = 5.0) -> dict[str, tuple[int, int]]:
    """Query the relay's own local admin API for every grant's *relayed*
    traffic in one request -- frps's ``todayTrafficIn``/``todayTrafficOut``
    counters for each ``stcp`` proxy (see this module's docstring for why
    that's the only traffic frp itself ever tracks), keyed by grant_id
    (undoing ``stcp_proxy_name``). One batched call instead of one per
    grant matters for `devices list`/`users show`, which may report on
    many grants at once. Returns ``{}`` if frps isn't reachable; a grant_id
    missing from the result means frps has no record of it yet (nothing
    has connected through it) -- same as a per-grant ``None`` used to."""
    try:
        resp = httpx.get(f"http://127.0.0.1:{admin_port}/api/proxy/stcp", timeout=timeout)
    except httpx.HTTPError:
        return {}
    if resp.status_code != 200:
        return {}
    result: dict[str, tuple[int, int]] = {}
    suffix = "-stcp"
    for proxy in resp.json().get("proxies", []):
        name = proxy.get("name", "")
        if name.endswith(suffix):
            grant_id = name[: -len(suffix)]
            result[grant_id] = (proxy.get("todayTrafficIn", 0), proxy.get("todayTrafficOut", 0))
    return result


@dataclass(frozen=True)
class _AdminApi:
    """frpc's webServer address and credentials for one frpc process. See
    the module docstring for why this exists and why it is never reused
    across processes."""

    port: int
    user: str
    password: str

    @classmethod
    def generate(cls, *, reserved_ports: Container[int] = ()) -> _AdminApi:
        return cls(
            port=_free_loopback_port(reserved_ports),
            user=secrets.token_urlsafe(32),
            password=secrets.token_urlsafe(32),
        )

    def web_server_config(self) -> dict:
        return {
            "addr": "127.0.0.1",
            "port": self.port,
            "user": self.user,
            "password": self.password,
        }


def _free_loopback_port(reserved_ports: Container[int]) -> int:
    """A kernel-chosen free port outside ``reserved_ports``. The agent's
    local port range sits inside the kernel's ephemeral range, and a port
    the agent has persisted for a grant that is not bound right now looks
    free -- the admin API must not take it, or that grant's visitor could
    never bind. Racy by nature otherwise (free now, bound by frpc a moment
    later); if something takes it in between, frpc exits on the failed
    bind and the next apply() restarts it with a new port."""
    for _ in range(_PORT_PICK_ATTEMPTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in reserved_ports:
            return port
    raise RuntimeError("no free loopback port outside the reserved range for frpc's admin API")


def _reload_frpc(admin: _AdminApi, *, timeout: float = _RELOAD_TIMEOUT) -> bool:
    """Ask the running frpc to re-read frpc.toml. ``strictConfig`` matches
    how frpc parsed the file at start (its ``--strict_config`` defaults to
    true). ``trust_env=False`` keeps an ``http_proxy`` from the environment
    from receiving the request, and the credentials with it."""
    try:
        resp = httpx.get(
            f"http://127.0.0.1:{admin.port}/api/reload",
            params={"strictConfig": "true"},
            auth=(admin.user, admin.password),
            timeout=timeout,
            trust_env=False,
        )
    except httpx.HTTPError as exc:
        logger.warning("frpc reload failed (%s), restarting frpc instead", exc)
        return False
    if not resp.is_success:
        logger.warning(
            "frpc reload failed (HTTP %s: %s), restarting frpc instead",
            resp.status_code,
            resp.text.strip()[:200],
        )
        return False
    return True


def _write_if_changed(path: Path, data: bytes, *, restrictive: bool = False) -> bool:
    """Skip the write entirely when the content on disk already matches --
    ``apply()`` calls this every poll cycle (default every few seconds)
    regardless of whether anything actually changed, and an embedded
    device's flash has a finite write budget worth not burning on
    rewriting identical bytes."""
    if path.is_file() and path.read_bytes() == data:
        if restrictive:
            path.chmod(0o600)
        return False
    if restrictive:
        write_private_key(path, data)
    else:
        path.write_bytes(data)
    return True


def _write_tls_files(
    tls_dir: Path, desired_or_relay: DesiredState | RelayState
) -> tuple[str, str, str, bool]:
    """Returns the three paths plus whether any file's content changed."""
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_file = tls_dir / "tls.crt"
    key_file = tls_dir / "tls.key"
    ca_file = tls_dir / "ca.crt"
    changed = _write_if_changed(cert_file, desired_or_relay.cert_pem)
    changed |= _write_if_changed(key_file, desired_or_relay.key_pem, restrictive=True)
    changed |= _write_if_changed(ca_file, desired_or_relay.ca_cert_pem)
    return str(cert_file), str(key_file), str(ca_file), changed


class FrpDriver:
    """Device-side TunnelDriver, backed by a single frpc process."""

    def __init__(
        self,
        *,
        binary: Path,
        state_dir: Path,
        fallback_timeout_ms: int,
        supervisor: ProcessSupervisor | None = None,
        reserved_ports: Container[int] = (),
    ) -> None:
        self._binary = binary
        self._config_path = state_dir / "frpc.toml"
        self._tls_dir = state_dir / "tls"
        self._fallback_timeout_ms = fallback_timeout_ms
        # Ports the admin API must never take: the agent's own range for
        # visitors' local bind ports (see _free_loopback_port).
        self._reserved_ports = reserved_ports
        self._supervisor = supervisor or SubprocessSupervisor()
        self._fingerprint: str | None = None
        # The config the running frpc was last given, without webServer,
        # and that process's admin API credentials. Both None when no frpc
        # was started by this driver (or after stop()).
        self._config: dict | None = None
        self._admin: _AdminApi | None = None

    def apply(self, desired: DesiredState, *, disable_p2p: bool = False) -> None:
        cert_file, key_file, ca_file, tls_changed = _write_tls_files(self._tls_dir, desired)
        config = build_frpc_config(
            desired,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            fallback_timeout_ms=self._fallback_timeout_ms,
            disable_p2p=disable_p2p,
        )

        fingerprint = _fingerprint(config)
        running = self._supervisor.is_running()
        if fingerprint == self._fingerprint and running and not tls_changed:
            return

        # frpc may read the TLS files again on a later reconnect, but not on
        # a reload, so changed TLS content is a restart like any other
        # change outside proxies/visitors.
        if (
            running
            and self._admin is not None
            and not tls_changed
            and not needs_restart(self._config, config)
        ):
            self._write_config(config, self._admin)
            if _reload_frpc(self._admin):
                self._config = config
                self._fingerprint = fingerprint
                return

        # New process, new admin API credentials: they are never carried
        # over to another frpc process (see the module docstring).
        admin = _AdminApi.generate(reserved_ports=self._reserved_ports)
        self._write_config(config, admin)
        self._supervisor.start([str(self._binary), "-c", str(self._config_path)])
        self._admin = admin
        self._config = config
        self._fingerprint = fingerprint

    def _write_config(self, config: dict, admin: _AdminApi) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        full = {**config, "webServer": admin.web_server_config()}
        # Not literally a private key, but just as secret -- every proxy's
        # secretKey and the admin API credentials live in here, and
        # write_private_key keeps it 0600 from creation on.
        write_private_key(self._config_path, tomli_w.dumps(full).encode("utf-8"))

    def status(self) -> DriverStatus:
        return DriverStatus(running=self._supervisor.is_running())

    def stop(self) -> None:
        self._supervisor.stop()
        self._fingerprint = None
        self._config = None
        self._admin = None


class FrpsRelayDriver:
    """Server-side RelayDriver, backed by a single frps process."""

    def __init__(
        self,
        *,
        binary: Path,
        state_dir: Path,
        admin_port: int,
        supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self._binary = binary
        self._config_path = state_dir / "frps.toml"
        self._tls_dir = state_dir / "tls"
        self._admin_port = admin_port
        self._supervisor = supervisor or SubprocessSupervisor()
        self._fingerprint: str | None = None

    def apply(self, desired: RelayState) -> None:
        cert_file, key_file, ca_file, _ = _write_tls_files(self._tls_dir, desired)
        config = build_frps_config(desired, cert_file=cert_file, key_file=key_file, ca_file=ca_file)
        config["webServer"] = {"addr": "127.0.0.1", "port": self._admin_port}

        fingerprint = _fingerprint(config)
        if fingerprint == self._fingerprint and self._supervisor.is_running():
            return

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        write_private_key(self._config_path, tomli_w.dumps(config).encode("utf-8"))
        self._supervisor.start([str(self._binary), "-c", str(self._config_path)])
        self._fingerprint = fingerprint

    def status(self) -> DriverStatus:
        return DriverStatus(running=self._supervisor.is_running())

    def stop(self) -> None:
        self._supervisor.stop()
        self._fingerprint = None
