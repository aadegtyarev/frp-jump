import httpx
import pytest

from frp_jump.agent import poller
from frp_jump.agent.state import AgentState, load


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
    desired = poller.build_desired_state(state, remote, data_dir=tmp_path)

    assert desired.device_id == "dev-1"
    assert desired.server_addr == "relay.example.com"
    assert desired.server_port == 7000
    assert len(desired.exposed) == 1
    assert desired.exposed[0].grant_id == "g1"
    assert desired.exposed[0].local_port == 22
    assert len(desired.consumed) == 1
    assert desired.consumed[0].grant_id == "g2"
    assert desired.consumed[0].local_bind_port > 0


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
    poller.build_desired_state(state, remote, data_dir=tmp_path)
    first_port = state.local_ports["g2"]

    reloaded = load(tmp_path)
    assert reloaded.local_ports["g2"] == first_port

    desired_again = poller.build_desired_state(state, remote, data_dir=tmp_path)
    assert desired_again.consumed[0].local_bind_port == first_port


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
    desired = poller.sync_once(state, driver, data_dir=tmp_path, ssh_config_path=ssh_config_path)

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
        poller.sync_once(state, driver, data_dir=tmp_path, ssh_config_path=ssh_config_path)
    assert driver.applied == []
