from frp_jump.agent.state import AgentState, load, save


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
