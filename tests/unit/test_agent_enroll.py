import httpx
import pytest

from frp_jump.agent import enroll
from frp_jump.agent.state import load


def _payload(**overrides) -> dict:
    base = dict(
        device_id="dev-1",
        device_name="wb01",
        api_token="apitok",
        cert_pem="cert",
        key_pem="key",
        ca_cert_pem="ca",
        server_addr="relay.example.com",
        server_port=7000,
    )
    base.update(overrides)
    return base


def test_enroll_success_saves_state(tmp_path, monkeypatch) -> None:
    payload = _payload()

    def fake_post(url, *, json, timeout):
        assert url == "https://ctl.example.com/api/agent/enroll"
        assert json == {"token": "tok123"}
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr(enroll.httpx, "post", fake_post)
    state = enroll.enroll(
        control_url="https://ctl.example.com/", token="tok123", data_dir=tmp_path
    )

    assert state.device_id == "dev-1"
    assert state.device_name == "wb01"
    assert state.control_url == "https://ctl.example.com"
    assert state.relay_addr == "relay.example.com"
    assert state.relay_port == 7000
    assert state.api_token == "apitok"

    reloaded = load(tmp_path)
    assert reloaded == state


def test_enroll_raises_on_non_200(monkeypatch, tmp_path) -> None:
    def fake_post(url, *, json, timeout):
        return httpx.Response(400, text="bad token", request=httpx.Request("POST", url))

    monkeypatch.setattr(enroll.httpx, "post", fake_post)
    with pytest.raises(enroll.EnrollError):
        enroll.enroll(control_url="https://ctl.example.com", token="tok123", data_dir=tmp_path)


def test_enroll_raises_on_connection_error(monkeypatch, tmp_path) -> None:
    def fake_post(url, *, json, timeout):
        raise httpx.ConnectError("refused", request=httpx.Request("POST", url))

    monkeypatch.setattr(enroll.httpx, "post", fake_post)
    with pytest.raises(enroll.EnrollError):
        enroll.enroll(control_url="https://ctl.example.com", token="tok123", data_dir=tmp_path)
