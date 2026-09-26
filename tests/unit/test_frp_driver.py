from pathlib import Path

import httpx

from frp_jump.driver.base import ConsumedGrant, DesiredState, DriverStatus, RelayState
from frp_jump.driver.frp.driver import FrpDriver, FrpsRelayDriver, fetch_all_proxy_traffic

_ADMIN_PORT = 17400
_FALLBACK_TIMEOUT_MS = 1500


class FakeSupervisor:
    def __init__(self) -> None:
        self.start_calls: list[list[str]] = []
        self.stop_calls = 0
        self._running = False

    def start(self, argv: list[str], *, cwd: Path | None = None) -> None:
        self.start_calls.append(argv)
        self._running = True

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def is_running(self) -> bool:
        return self._running


def _make_driver(tmp_path, supervisor: FakeSupervisor) -> FrpDriver:
    return FrpDriver(
        binary=Path("/opt/frp/frpc"),
        state_dir=tmp_path,
        fallback_timeout_ms=_FALLBACK_TIMEOUT_MS,
        supervisor=supervisor,
    )


def _make_relay_driver(tmp_path, supervisor: FakeSupervisor) -> FrpsRelayDriver:
    return FrpsRelayDriver(
        binary=Path("/opt/frp/frps"),
        state_dir=tmp_path,
        admin_port=_ADMIN_PORT,
        supervisor=supervisor,
    )


def _desired(**overrides) -> DesiredState:
    base = dict(
        device_id="dev-1",
        server_addr="relay.example.com",
        server_port=7000,
        ca_cert_pem=b"ca",
        cert_pem=b"cert",
        key_pem=b"key",
    )
    base.update(overrides)
    return DesiredState(**base)


def test_apply_writes_tls_material_and_starts_process(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())

    assert (tmp_path / "tls" / "tls.crt").read_bytes() == b"cert"
    assert (tmp_path / "tls" / "tls.key").read_bytes() == b"key"
    assert (tmp_path / "tls" / "ca.crt").read_bytes() == b"ca"
    key_mode = (tmp_path / "tls" / "tls.key").stat().st_mode & 0o777
    assert key_mode == 0o600
    assert (tmp_path / "frpc.toml").exists()
    # frpc.toml holds every grant's secretKey -- just as secret as tls.key.
    config_mode = (tmp_path / "frpc.toml").stat().st_mode & 0o777
    assert config_mode == 0o600
    assert len(supervisor.start_calls) == 1
    assert supervisor.start_calls[0][0] == "/opt/frp/frpc"


def test_apply_is_idempotent_when_desired_state_is_unchanged(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    desired = _desired()
    driver.apply(desired)
    driver.apply(desired)
    assert len(supervisor.start_calls) == 1


def test_apply_does_not_rewrite_unchanged_tls_files(tmp_path) -> None:
    """Regression test: `_write_tls_files` used to run unconditionally on
    every `apply()` call, before the fingerprint-based restart check --
    rewriting identical bytes on every poll cycle burns an embedded
    device's finite flash write budget for nothing."""
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    desired = _desired()
    driver.apply(desired)
    mtime_before = (tmp_path / "tls" / "tls.crt").stat().st_mtime_ns

    driver.apply(desired)

    assert (tmp_path / "tls" / "tls.crt").stat().st_mtime_ns == mtime_before


def test_apply_restarts_when_desired_state_changes(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    driver.apply(
        _desired(consumed=(ConsumedGrant(grant_id="g1", secret="s", local_bind_port=2222),))
    )
    assert len(supervisor.start_calls) == 2


def test_apply_restarts_if_process_died_even_with_same_config(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    desired = _desired()
    driver.apply(desired)
    supervisor._running = False  # simulate crash
    driver.apply(desired)
    assert len(supervisor.start_calls) == 2


def test_status_reflects_supervisor(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    assert driver.status() == DriverStatus(running=False)
    driver.apply(_desired())
    assert driver.status() == DriverStatus(running=True)


def test_stop_stops_supervisor_and_forces_next_apply_to_restart(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    desired = _desired()
    driver.apply(desired)
    driver.stop()
    assert supervisor.stop_calls == 1
    assert driver.status().running is False


def test_apply_uses_configured_fallback_timeout(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = FrpDriver(
        binary=Path("/opt/frp/frpc"),
        state_dir=tmp_path,
        fallback_timeout_ms=750,
        supervisor=supervisor,
    )
    consumed = (ConsumedGrant(grant_id="g1", secret="s", local_bind_port=2222),)
    driver.apply(_desired(consumed=consumed))
    config_text = (tmp_path / "frpc.toml").read_text()
    assert "fallbackTimeoutMs = 750" in config_text


def test_apply_disable_p2p_omits_xtcp_visitor(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    consumed = (ConsumedGrant(grant_id="g1", secret="s", local_bind_port=2222),)
    driver.apply(_desired(consumed=consumed), disable_p2p=True)
    config_text = (tmp_path / "frpc.toml").read_text()
    assert "g1-xtcp-visitor" not in config_text
    assert "fallbackTo" not in config_text


def test_apply_disable_p2p_is_not_sticky_across_calls(tmp_path) -> None:
    """Regression test: `disable_p2p` used to be baked into the driver at
    construction time, so a `set-p2p` toggle written to state.json never
    reached an already-running daemon until it was restarted -- despite
    `set-p2p --help` promising the next poll cycle picks it up. It must be
    read fresh on every `apply()` call instead."""
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    consumed = (ConsumedGrant(grant_id="g1", secret="s", local_bind_port=2222),)
    desired = _desired(consumed=consumed)

    driver.apply(desired, disable_p2p=True)
    assert "g1-xtcp-visitor" not in (tmp_path / "frpc.toml").read_text()

    driver.apply(desired, disable_p2p=False)
    assert "g1-xtcp-visitor" in (tmp_path / "frpc.toml").read_text()


def test_relay_driver_writes_tls_material_and_forces_tls(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_relay_driver(tmp_path, supervisor)
    relay = RelayState(bind_port=7000, ca_cert_pem=b"ca", cert_pem=b"cert", key_pem=b"key")
    driver.apply(relay)

    assert (tmp_path / "tls" / "tls.crt").read_bytes() == b"cert"
    config_text = (tmp_path / "frps.toml").read_text()
    assert "force = true" in config_text
    config_mode = (tmp_path / "frps.toml").stat().st_mode & 0o777
    assert config_mode == 0o600
    assert len(supervisor.start_calls) == 1


def test_relay_driver_status_and_stop(tmp_path) -> None:
    supervisor = FakeSupervisor()
    driver = _make_relay_driver(tmp_path, supervisor)
    relay = RelayState(bind_port=7000, ca_cert_pem=b"ca", cert_pem=b"cert", key_pem=b"key")
    driver.apply(relay)
    assert driver.status().running is True
    driver.stop()
    assert driver.status().running is False


def test_fetch_all_proxy_traffic_keys_by_grant_id(monkeypatch):
    def fake_get(url, *, timeout):
        assert url == "http://127.0.0.1:17400/api/proxy/stcp"
        return httpx.Response(
            200,
            json={
                "proxies": [
                    {"name": "g1-stcp", "todayTrafficIn": 100, "todayTrafficOut": 200},
                    {"name": "g2-stcp", "todayTrafficIn": 0, "todayTrafficOut": 0},
                    {"name": "not-an-stcp-name"},
                ]
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = fetch_all_proxy_traffic(_ADMIN_PORT)

    assert result == {"g1": (100, 200), "g2": (0, 0)}


def test_fetch_all_proxy_traffic_returns_empty_dict_when_frps_unreachable(monkeypatch):
    def fake_get(url, *, timeout):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert fetch_all_proxy_traffic(_ADMIN_PORT) == {}
