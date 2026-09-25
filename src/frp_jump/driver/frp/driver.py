"""frp-backed implementations of TunnelDriver / RelayDriver.

Config changes are applied by writing a new frpc.toml/frps.toml and
restarting the process — frp does have a hot-reload admin API, but a full
restart is simpler and correct, and grants change rarely enough (an admin
action, not a hot path) that the brief reconnect blip does not matter here.

Known limitation: frpc's admin API (``/api/status``) reports proxy status
on the exposing side, but does not expose whether a given *visitor*
actually ended up peer-to-peer or fell back to relay — there is no
``/api/visitor-status`` route (checked against fatedier/frp's
``client/api_router.go``, dev branch). So ``status()`` reports per-grant
state as ``UNKNOWN`` for now; see docs/architecture.md for how to improve
this later (e.g. tailing frpc's log for hole-punch/fallback messages).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import tomli_w

from frp_jump.driver.base import (
    DesiredState,
    DriverStatus,
    RelayState,
)
from frp_jump.driver.frp.config import build_frpc_config, build_frps_config
from frp_jump.driver.frp.process import ProcessSupervisor, SubprocessSupervisor


def _fingerprint(config: dict) -> str:
    return hashlib.sha256(tomli_w.dumps(config).encode("utf-8")).hexdigest()


def _write_tls_files(
    tls_dir: Path, desired_or_relay: DesiredState | RelayState
) -> tuple[str, str, str]:
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert_file = tls_dir / "tls.crt"
    key_file = tls_dir / "tls.key"
    ca_file = tls_dir / "ca.crt"
    cert_file.write_bytes(desired_or_relay.cert_pem)
    key_file.write_bytes(desired_or_relay.key_pem)
    ca_file.write_bytes(desired_or_relay.ca_cert_pem)
    return str(cert_file), str(key_file), str(ca_file)


class FrpDriver:
    """Device-side TunnelDriver, backed by a single frpc process."""

    def __init__(
        self,
        *,
        binary: Path,
        state_dir: Path,
        admin_port: int,
        fallback_timeout_ms: int,
        supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self._binary = binary
        self._config_path = state_dir / "frpc.toml"
        self._tls_dir = state_dir / "tls"
        self._admin_port = admin_port
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
        config["webServer"] = {"addr": "127.0.0.1", "port": self._admin_port}

        fingerprint = _fingerprint(config)
        if fingerprint == self._fingerprint and self._supervisor.is_running():
            return

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config_path.write_bytes(tomli_w.dumps(config).encode("utf-8"))
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
        self._config_path.write_bytes(tomli_w.dumps(config).encode("utf-8"))
        self._supervisor.start([str(self._binary), "-c", str(self._config_path)])
        self._fingerprint = fingerprint

    def status(self) -> DriverStatus:
        return DriverStatus(running=self._supervisor.is_running())

    def stop(self) -> None:
        self._supervisor.stop()
        self._fingerprint = None
