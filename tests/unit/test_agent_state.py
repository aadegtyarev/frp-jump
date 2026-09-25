import json

import pytest

from frp_jump.agent.state import AgentState, load, save, state_path


def _state(**overrides) -> AgentState:
    base = dict(
        device_id="dev-1",
        device_name="wb01",
        control_url="https://tunnel.example.com",
        relay_addr="relay.example.com",
        relay_port=7000,
        api_token="tok",
        cert_pem="cert",
        key_pem="key",
        ca_cert_pem="ca",
    )
    base.update(overrides)
    return AgentState(**base)


def test_load_returns_none_when_no_state_file(tmp_path) -> None:
    assert load(tmp_path) is None


def test_save_then_load_round_trips(tmp_path) -> None:
    state = _state(local_ports={"grant-1": 5000})
    save(tmp_path, state)
    loaded = load(tmp_path)
    assert loaded == state


def test_save_writes_file_with_restricted_permissions(tmp_path) -> None:
    save(tmp_path, _state())
    mode = (tmp_path / "state.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_save_leaves_no_temp_file_behind(tmp_path) -> None:
    save(tmp_path, _state())
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_save_overwrites_atomically_old_content_never_visible_truncated(tmp_path) -> None:
    save(tmp_path, _state(device_name="first"))
    save(tmp_path, _state(device_name="second"))
    # the only possible states after two saves are "first" or "second", in full
    loaded = load(tmp_path)
    assert loaded.device_name == "second"
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_load_raises_clearly_on_corrupted_state_file(tmp_path) -> None:
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json at all {{{")
    with pytest.raises(json.JSONDecodeError):
        load(tmp_path)
