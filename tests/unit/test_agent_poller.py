import socket

import httpx
import pytest

from frp_jump.agent import poller
from frp_jump.agent.state import AgentState, load

_PORT_RANGE = range(40000, 40010)


def _state(**overrides) -> AgentState:
    base = dict(
        device_id="dev-1",
        device_name="wb01",
        control_url="http://ctl.example.com",
        relay_addr="relay.example.com",
        relay_port=7000,
        api_token="tok",
        cert_pem="cert",
        key_pem="key",
        ca_cert_pem="ca",
        local_ports={},
    )
    base.update(overrides)
    return AgentState(**base)


class FakeDriver:
    def __init__(self) -> None:
        self.applied = []

    def apply(self, desired) -> None:
        self.applied.append(desired)

    def status(self):
        raise NotImplementedError

    def stop(self) -> None:
        pass


def test_send_heartbeat_posts_to_control_url_with_bearer_auth(monkeypatch) -> None:
    state = _state()
    captured = {}

    def fake_post(url, *, json, headers, timeout):
        captured.update(url=url, json=json, headers=headers)
        return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr(poller.httpx, "post", fake_post)
    poller.send_heartbeat(state, agent_version="1.0")

    assert captured["url"] == "http://ctl.example.com/api/agent/heartbeat"
    assert captured["headers"]["Authorization"] == "Bearer tok"
    assert captured["json"] == {"agent_version": "1.0"}


def test_send_heartbeat_raises_sync_error_on_non_204(monkeypatch) -> None:
    state = _state()

    def fake_post(url, *, json, headers, timeout):
        return httpx.Response(401, text="nope", request=httpx.Request("POST", url))

    monkeypatch.setattr(poller.httpx, "post", fake_post)
    with pytest.raises(poller.SyncError):
        poller.send_heartbeat(state)


def test_fetch_desired_state_returns_parsed_json(monkeypatch) -> None:
    state = _state()
    payload = {"exposed": [], "consumed": []}

    def fake_get(url, *, headers, timeout):
        return httpx.Response(200, json=payload, request=httpx.Request("GET", url))

    monkeypatch.setattr(poller.httpx, "get", fake_get)
    assert poller.fetch_desired_state(state) == payload


def test_fetch_desired_state_raises_sync_error_on_failure(monkeypatch) -> None:
    state = _state()

    def fake_get(url, *, headers, timeout):
        return httpx.Response(500, text="boom", request=httpx.Request("GET", url))

    monkeypatch.setattr(poller.httpx, "get", fake_get)
    with pytest.raises(poller.SyncError):
        poller.fetch_desired_state(state)


def test_fetch_desired_state_raises_sync_error_on_transport_failure(monkeypatch) -> None:
    """A connection error (DNS failure, refused, timeout) is a different exception
    tree than an HTTP error response -- must also become SyncError, not propagate
    raw and kill the agent loop."""
    state = _state()

    def fake_get(url, *, headers, timeout):
        raise httpx.ConnectError("refused", request=httpx.Request("GET", url))

    monkeypatch.setattr(poller.httpx, "get", fake_get)
    with pytest.raises(poller.SyncError):
        poller.fetch_desired_state(state)


def test_send_heartbeat_raises_sync_error_on_transport_failure(monkeypatch) -> None:
    state = _state()

    def fake_post(url, *, json, headers, timeout):
        raise httpx.ConnectTimeout("timed out", request=httpx.Request("POST", url))

    monkeypatch.setattr(poller.httpx, "post", fake_post)
    with pytest.raises(poller.SyncError):
        poller.send_heartbeat(state)


def test_build_desired_state_maps_exposed_and_consumed(tmp_path) -> None:
    state = _state()
    remote = {
        "exposed": [
            {"grant_id": "g1", "secret": "s1", "service_name": "wb01-ssh", "target_port": 22}
        ],
        "consumed": [
            {
                "grant_id": "g2",
                "secret": "s2",
                "service_name": "other-ssh",
                "protocol": "ssh",
                "exposer_device_name": "wb02",
            }
        ],
    }
    desired = poller.build_desired_state(state, remote, data_dir=tmp_path, port_range=_PORT_RANGE)

    assert desired.device_id == "dev-1"
    assert desired.server_addr == "relay.example.com"
    assert desired.server_port == 7000
    assert len(desired.exposed) == 1
    assert desired.exposed[0].grant_id == "g1"
    assert desired.exposed[0].local_port == 22
    assert len(desired.consumed) == 1
    assert desired.consumed[0].grant_id == "g2"
    assert desired.consumed[0].local_bind_port in _PORT_RANGE


def test_build_desired_state_allocates_a_stable_persisted_port(tmp_path) -> None:
    state = _state()
    remote = {
        "exposed": [],
        "consumed": [
            {
                "grant_id": "g2",
                "secret": "s2",
                "service_name": "x",
                "protocol": "ssh",
                "exposer_device_name": "wb02",
            }
        ],
    }
    poller.build_desired_state(state, remote, data_dir=tmp_path, port_range=_PORT_RANGE)
    first_port = state.local_ports["g2"]

    reloaded = load(tmp_path)
    assert reloaded.local_ports["g2"] == first_port

    desired_again = poller.build_desired_state(
        state, remote, data_dir=tmp_path, port_range=_PORT_RANGE
    )
    assert desired_again.consumed[0].local_bind_port == first_port


def test_build_desired_state_gives_distinct_ports_to_distinct_grants_in_one_call(
    tmp_path,
) -> None:
    state = _state()
    remote = {
        "exposed": [],
        "consumed": [
            {"grant_id": "g1", "secret": "s1", "service_name": "a", "protocol": "ssh",
             "exposer_device_name": "wb01"},
            {"grant_id": "g2", "secret": "s2", "service_name": "b", "protocol": "ssh",
             "exposer_device_name": "wb02"},
        ],
    }
    desired = poller.build_desired_state(state, remote, data_dir=tmp_path, port_range=_PORT_RANGE)
    ports = {c.local_bind_port for c in desired.consumed}
    assert len(ports) == 2


def test_build_desired_state_raises_when_port_range_exhausted(tmp_path) -> None:
    state = _state()
    tiny_range = range(50000, 50000)  # empty range
    remote = {
        "exposed": [],
        "consumed": [
            {"grant_id": "g1", "secret": "s1", "service_name": "a", "protocol": "ssh",
             "exposer_device_name": "wb01"},
        ],
    }
    with pytest.raises(poller.SyncError):
        poller.build_desired_state(state, remote, data_dir=tmp_path, port_range=tiny_range)


def test_build_desired_state_reclaims_ports_for_grants_no_longer_present(tmp_path) -> None:
    state = _state(local_ports={"gone": 40005})
    remote = {"exposed": [], "consumed": []}
    poller.build_desired_state(state, remote, data_dir=tmp_path, port_range=_PORT_RANGE)
    assert state.local_ports == {}
    reloaded = load(tmp_path)
    assert reloaded.local_ports == {}


def test_build_desired_state_revalidates_and_reallocates_when_persisted_port_is_taken(
    tmp_path,
) -> None:
    state = _state(local_ports={"g1": 40001})
    remote = {
        "exposed": [],
        "consumed": [
            {"grant_id": "g1", "secret": "s1", "service_name": "a", "protocol": "ssh",
             "exposer_device_name": "wb01"},
        ],
    }
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 40001))
    try:
        desired = poller.build_desired_state(
            state, remote, data_dir=tmp_path, port_range=_PORT_RANGE, revalidate=True
        )
        assert desired.consumed[0].local_bind_port != 40001
        assert state.local_ports["g1"] != 40001
    finally:
        blocker.close()


def test_build_desired_state_does_not_revalidate_by_default(tmp_path) -> None:
    """Without revalidate=True, an already-allocated port is trusted even if
    something is currently bound to it (e.g. our own already-running frpc) --
    see build_desired_state's docstring for why re-checking every cycle would
    cause the tunnel to restart on every poll."""
    state = _state(local_ports={"g1": 40001})
    remote = {
        "exposed": [],
        "consumed": [
            {"grant_id": "g1", "secret": "s1", "service_name": "a", "protocol": "ssh",
             "exposer_device_name": "wb01"},
        ],
    }
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 40001))
    try:
        desired = poller.build_desired_state(
            state, remote, data_dir=tmp_path, port_range=_PORT_RANGE
        )
        assert desired.consumed[0].local_bind_port == 40001
    finally:
        blocker.close()


def test_sync_ssh_config_only_includes_ssh_protocol_grants(tmp_path) -> None:
    state = _state(local_ports={"g1": 5000, "g2": 5001})
    remote = {
        "consumed": [
            {"grant_id": "g1", "service_name": "wb01-ssh", "protocol": "ssh"},
            {"grant_id": "g2", "service_name": "wb01-http", "protocol": "http"},
        ]
    }
    ssh_config_path = tmp_path / "ssh_config_real"
    poller.sync_ssh_config(state, remote, data_dir=tmp_path, ssh_config_path=ssh_config_path)

    managed_text = (tmp_path / "ssh_config").read_text()
    assert "wb01-ssh" in managed_text
    assert "wb01-http" not in managed_text
    assert "Include" in ssh_config_path.read_text()


def test_sync_once_runs_the_full_cycle(tmp_path, monkeypatch) -> None:
    state = _state()
    driver = FakeDriver()

    def fake_post(url, *, json, headers, timeout):
        return httpx.Response(204, request=httpx.Request("POST", url))

    def fake_get(url, *, headers, timeout):
        return httpx.Response(
            200, json={"exposed": [], "consumed": []}, request=httpx.Request("GET", url)
        )

    monkeypatch.setattr(poller.httpx, "post", fake_post)
    monkeypatch.setattr(poller.httpx, "get", fake_get)

    ssh_config_path = tmp_path / "ssh_config_real"
    desired = poller.sync_once(
        state, driver, data_dir=tmp_path, ssh_config_path=ssh_config_path, port_range=_PORT_RANGE
    )

    assert len(driver.applied) == 1
    assert driver.applied[0] is desired


def test_sync_once_propagates_heartbeat_failure_without_applying(tmp_path, monkeypatch) -> None:
    state = _state()
    driver = FakeDriver()

    def fake_post(url, *, json, headers, timeout):
        return httpx.Response(401, text="nope", request=httpx.Request("POST", url))

    monkeypatch.setattr(poller.httpx, "post", fake_post)
    ssh_config_path = tmp_path / "ssh_config_real"

    with pytest.raises(poller.SyncError):
        poller.sync_once(
            state,
            driver,
            data_dir=tmp_path,
            ssh_config_path=ssh_config_path,
            port_range=_PORT_RANGE,
        )
    assert driver.applied == []


def test_run_forever_survives_an_unexpected_exception_and_keeps_looping(
    tmp_path, monkeypatch
) -> None:
    """A bug in sync_once (or a transport error, or anything else) must not kill
    the daemon -- it should log and retry next cycle, forever, by design."""
    state = _state()
    driver = FakeDriver()
    calls = {"n": 0}

    def boom(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 3:
            raise SystemExit("stop the test")
        raise RuntimeError("simulated bug unrelated to networking")

    monkeypatch.setattr(poller, "sync_once", boom)
    monkeypatch.setattr(poller.time, "sleep", lambda _seconds: None)

    with pytest.raises(SystemExit):
        poller.run_forever(
            state,
            driver,
            data_dir=tmp_path,
            ssh_config_path=tmp_path / "ssh_config_real",
            poll_interval_seconds=0,
            port_range=_PORT_RANGE,
        )
    assert calls["n"] == 3


def test_run_forever_only_revalidates_ports_on_the_first_successful_cycle(
    tmp_path, monkeypatch
) -> None:
    state = _state()
    driver = FakeDriver()
    seen_revalidate: list[bool] = []

    def fake_sync_once(*args, revalidate_ports=False, **kwargs):
        seen_revalidate.append(revalidate_ports)
        if len(seen_revalidate) >= 3:
            raise SystemExit("stop the test")

    monkeypatch.setattr(poller, "sync_once", fake_sync_once)
    monkeypatch.setattr(poller.time, "sleep", lambda _seconds: None)

    with pytest.raises(SystemExit):
        poller.run_forever(
            state,
            driver,
            data_dir=tmp_path,
            ssh_config_path=tmp_path / "ssh_config_real",
            poll_interval_seconds=0,
            port_range=_PORT_RANGE,
        )
    assert seen_revalidate == [True, False, False]
