import logging
import tomllib
from pathlib import Path

import httpx
import pytest

from frp_jump.driver.base import (
    ConsumedGrant,
    DesiredState,
    DriverStatus,
    ExposedService,
    RelayState,
)
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


@pytest.fixture
def reload_calls(monkeypatch) -> list[dict]:
    """Stands in for frpc's admin API: records every reload request and
    answers 200. No unit test may reach a real port."""
    calls: list[dict] = []

    def fake_get(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    return calls


def _frpc_toml(tmp_path) -> dict:
    return tomllib.loads((tmp_path / "frpc.toml").read_text())


def _exposed(*grant_ids: str) -> tuple[ExposedService, ...]:
    return tuple(
        ExposedService(grant_id=g, secret=f"secret-{g}", local_port=22 + i)
        for i, g in enumerate(grant_ids)
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


def test_apply_restarts_when_common_settings_change(tmp_path, reload_calls) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    driver.apply(_desired(server_port=7001))
    assert len(supervisor.start_calls) == 2
    assert reload_calls == []


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


def test_apply_disable_p2p_is_not_sticky_across_calls(tmp_path, reload_calls) -> None:
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


def test_frpc_admin_api_is_loopback_only_and_authenticated(tmp_path) -> None:
    driver = _make_driver(tmp_path, FakeSupervisor())
    driver.apply(_desired())

    web = _frpc_toml(tmp_path)["webServer"]
    assert web["addr"] == "127.0.0.1"
    assert 0 < web["port"] < 65536
    # frp skips auth entirely when both are empty; both must be long and random.
    assert len(web["user"]) >= 43
    assert len(web["password"]) >= 43
    assert web["user"] != web["password"]
    assert (tmp_path / "frpc.toml").stat().st_mode & 0o777 == 0o600


def test_frpc_admin_credentials_are_fresh_for_every_driver(tmp_path) -> None:
    _make_driver(tmp_path / "a", FakeSupervisor()).apply(_desired())
    _make_driver(tmp_path / "b", FakeSupervisor()).apply(_desired())
    assert _frpc_toml(tmp_path / "a")["webServer"] != _frpc_toml(tmp_path / "b")["webServer"]


def test_new_grant_hot_reloads_without_restarting(tmp_path, reload_calls) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired(exposed=_exposed("g1")))
    web = _frpc_toml(tmp_path)["webServer"]

    driver.apply(_desired(exposed=_exposed("g1", "g2")))

    assert len(supervisor.start_calls) == 1
    assert len(reload_calls) == 1
    call = reload_calls[0]
    assert call["url"] == f"http://127.0.0.1:{web['port']}/api/reload"
    assert call["auth"] == (web["user"], web["password"])
    assert call["params"] == {"strictConfig": "true"}
    assert call["trust_env"] is False
    names = {proxy["name"] for proxy in _frpc_toml(tmp_path)["proxies"]}
    assert names == {"g1-xtcp", "g1-stcp", "g2-xtcp", "g2-stcp"}


def test_consumed_grant_and_p2p_toggle_also_hot_reload(tmp_path, reload_calls) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    consumed = (ConsumedGrant(grant_id="g1", secret="s", local_bind_port=2222),)
    driver.apply(_desired())
    driver.apply(_desired(consumed=consumed))
    driver.apply(_desired(consumed=consumed), disable_p2p=True)
    driver.apply(_desired())

    assert len(supervisor.start_calls) == 1
    assert len(reload_calls) == 3


def test_admin_credentials_stay_the_same_across_reloads(tmp_path, reload_calls) -> None:
    driver = _make_driver(tmp_path, FakeSupervisor())
    driver.apply(_desired())
    web = _frpc_toml(tmp_path)["webServer"]

    driver.apply(_desired(exposed=_exposed("g1")))
    driver.apply(_desired(exposed=_exposed("g1", "g2")))

    assert _frpc_toml(tmp_path)["webServer"] == web
    assert {call["auth"] for call in reload_calls} == {(web["user"], web["password"])}


def test_restart_rotates_admin_credentials(tmp_path, reload_calls) -> None:
    driver = _make_driver(tmp_path, FakeSupervisor())
    driver.apply(_desired())
    first = _frpc_toml(tmp_path)["webServer"]

    driver.apply(_desired(server_port=7001))

    second = _frpc_toml(tmp_path)["webServer"]
    assert second["user"] != first["user"]
    assert second["password"] != first["password"]


def test_tls_content_change_restarts_even_with_identical_config(
    tmp_path, reload_calls
) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    driver.apply(_desired(cert_pem=b"renewed cert"))
    assert len(supervisor.start_calls) == 2
    assert reload_calls == []


def test_dead_frpc_is_restarted_not_reloaded(tmp_path, reload_calls) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    supervisor._running = False
    driver.apply(_desired(exposed=_exposed("g1")))
    assert len(supervisor.start_calls) == 2
    assert reload_calls == []


def test_stop_then_apply_starts_with_new_credentials(tmp_path, reload_calls) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    first = _frpc_toml(tmp_path)["webServer"]
    driver.stop()
    driver.apply(_desired(exposed=_exposed("g1")))
    assert len(supervisor.start_calls) == 2
    assert reload_calls == []
    assert _frpc_toml(tmp_path)["webServer"]["password"] != first["password"]


def _raise(exc):
    def fake_get(url, **kwargs):
        raise exc

    return fake_get


def _respond(status: int):
    def fake_get(url, **kwargs):
        return httpx.Response(status, text="boom", request=httpx.Request("GET", url))

    return fake_get


@pytest.mark.parametrize(
    "fake_get",
    [
        _raise(httpx.ConnectError("connection refused")),
        _raise(httpx.ReadTimeout("timed out")),
        _respond(400),
        _respond(401),
        _respond(500),
    ],
    ids=["refused", "timeout", "http-400", "http-401", "http-500"],
)
def test_failed_reload_falls_back_to_restart(tmp_path, monkeypatch, caplog, fake_get) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    first = _frpc_toml(tmp_path)["webServer"]
    monkeypatch.setattr(httpx, "get", fake_get)

    with caplog.at_level(logging.WARNING, logger="frp_jump.driver.frp.driver"):
        driver.apply(_desired(exposed=_exposed("g1")))

    assert len(supervisor.start_calls) == 2
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "restarting frpc" in warnings[0].getMessage()
    # The restarted process gets the new config and its own credentials.
    restarted = _frpc_toml(tmp_path)
    assert {p["name"] for p in restarted["proxies"]} == {"g1-xtcp", "g1-stcp"}
    assert restarted["webServer"]["password"] != first["password"]
    assert first["password"] not in caplog.text


def test_failed_reload_then_unchanged_state_does_not_restart_again(
    tmp_path, monkeypatch
) -> None:
    supervisor = FakeSupervisor()
    driver = _make_driver(tmp_path, supervisor)
    driver.apply(_desired())
    monkeypatch.setattr(httpx, "get", _respond(500))
    driver.apply(_desired(exposed=_exposed("g1")))
    driver.apply(_desired(exposed=_exposed("g1")))
    assert len(supervisor.start_calls) == 2


def test_admin_port_avoids_reserved_ports(tmp_path, monkeypatch) -> None:
    """The agent's local port range lies inside the kernel's ephemeral range;
    an admin API on a port the agent hands to a visitor would block it."""
    import frp_jump.driver.frp.driver as driver_module

    picks = iter([40001, 40002, 51000])

    class FakeSocket:
        def __init__(self, *args) -> None:
            self._port = next(picks)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            pass

        def bind(self, addr) -> None:
            pass

        def getsockname(self):
            return ("127.0.0.1", self._port)

    monkeypatch.setattr(driver_module.socket, "socket", FakeSocket)
    driver = FrpDriver(
        binary=Path("/opt/frp/frpc"),
        state_dir=tmp_path,
        fallback_timeout_ms=_FALLBACK_TIMEOUT_MS,
        supervisor=FakeSupervisor(),
        reserved_ports=range(40000, 41000),
    )
    driver.apply(_desired())
    assert _frpc_toml(tmp_path)["webServer"]["port"] == 51000
