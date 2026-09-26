"""frp-backed implementations of TunnelDriver / RelayDriver.

Config changes are applied by writing a new frpc.toml/frps.toml and
restarting the process — frp does have a hot-reload admin API, but a full
restart is simpler and correct, and grants change rarely enough (an admin
action, not a hot path) that the brief reconnect blip does not matter here.

``FrpDriver`` (the client side) never enables frpc's own ``webServer``
(admin API) -- it has no authentication of its own, and every device of
the same owner can already reach any of another device's `127.0.0.1`
ports via a normal grant, which would turn an unauthenticated admin API
into a free remote-config channel between devices. ``status()`` therefore
reports per-grant state as ``UNKNOWN`` rather than querying it; see
docs/architecture.md for what a future improvement here would need
(e.g. tailing frpc's log for hole-punch/fallback messages instead).

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
from pathlib import Path

import httpx
import tomli_w

from frp_jump.common.crypto import write_private_key
from frp_jump.driver.base import (
    DesiredState,
    DriverStatus,
    RelayState,
)
from frp_jump.driver.frp.config import build_frpc_config, build_frps_config
from frp_jump.driver.frp.process import ProcessSupervisor, SubprocessSupervisor


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


def _write_if_changed(path: Path, data: bytes, *, restrictive: bool = False) -> None:
    """Skip the write entirely when the content on disk already matches --
    ``apply()`` calls this every poll cycle (default every few seconds)
    regardless of whether anything actually changed, and an embedded
    device's flash has a finite write budget worth not burning on
    rewriting identical bytes."""
    if path.is_file() and path.read_bytes() == data:
        return
    if restrictive:
        write_private_key(path, data)
    else:
        path.write_bytes(data)


def _write_tls_files(
    tls_dir: Path, desired_or_relay: DesiredState | RelayState
) -> tuple[str, str, str]:
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_file = tls_dir / "tls.crt"
    key_file = tls_dir / "tls.key"
    ca_file = tls_dir / "ca.crt"
    _write_if_changed(cert_file, desired_or_relay.cert_pem)
    _write_if_changed(key_file, desired_or_relay.key_pem, restrictive=True)
    _write_if_changed(ca_file, desired_or_relay.ca_cert_pem)
    return str(cert_file), str(key_file), str(ca_file)


class FrpDriver:
    """Device-side TunnelDriver, backed by a single frpc process."""

    def __init__(
        self,
        *,
        binary: Path,
        state_dir: Path,
        fallback_timeout_ms: int,
        supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self._binary = binary
        self._config_path = state_dir / "frpc.toml"
        self._tls_dir = state_dir / "tls"
        self._fallback_timeout_ms = fallback_timeout_ms
        self._supervisor = supervisor or SubprocessSupervisor()
        self._fingerprint: str | None = None

    def apply(self, desired: DesiredState) -> None:
        cert_file, key_file, ca_file = _write_tls_files(self._tls_dir, desired)
        config = build_frpc_config(
            desired,
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_file,
            fallback_timeout_ms=self._fallback_timeout_ms,
        )
        # Deliberately no webServer/admin API here: frpc's admin API has no
        # auth of its own and nothing in this codebase ever reads it (unlike
        # frps's, which fetch_proxy_traffic below does use) -- enabling it
        # would only be a free, unauthenticated remote-config surface on
        # every device, reachable by any other device of the same owner
        # that can already reach 127.0.0.1:<this port> via a normal grant.

        fingerprint = _fingerprint(config)
        if fingerprint == self._fingerprint and self._supervisor.is_running():
            return

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        # Not literally a private key, but just as secret -- every proxy's
        # secretKey lives in here, and write_private_key's restrictive-
        # from-creation write closes the same window a plain write_bytes
        # (subject to umask, world-readable by default) would leave open.
        write_private_key(self._config_path, tomli_w.dumps(config).encode("utf-8"))
        self._supervisor.start([str(self._binary), "-c", str(self._config_path)])
        self._fingerprint = fingerprint

    def status(self) -> DriverStatus:
        return DriverStatus(running=self._supervisor.is_running())

    def stop(self) -> None:
        self._supervisor.stop()
        self._fingerprint = None


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
        cert_file, key_file, ca_file = _write_tls_files(self._tls_dir, desired)
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
