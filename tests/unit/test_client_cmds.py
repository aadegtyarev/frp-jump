import pytest
from typer.testing import CliRunner

from frp_jump.agent import poller
from frp_jump.agent.state import AgentState, Profile, load, save
from frp_jump.cli import client_cmds

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FRP_JUMP_DATA_DIR", str(tmp_path))
    return tmp_path


def _enrolled_state(tmp_path, **overrides) -> AgentState:
    base = dict(
        device_id="dev-1",
        device_name="wb01",
        control_url="https://ctl.example.com",
        relay_addr="relay.example.com",
        relay_port=7000,
        api_token="tok",
        cert_pem="cert",
        key_pem="key",
        ca_cert_pem="ca",
    )
    base.update(overrides)
    state = AgentState(**base)
    save(tmp_path, state)
    return state


def test_connect_saves_a_local_profile(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "connect",
        lambda state, *, device_name, target_port, protocol: {"grant_id": "g1"},
    )

    result = runner.invoke(client_cmds.app, ["connect", "wb02", "22"])

    assert result.exit_code == 0, result.output
    assert "Connected" in result.output
    reloaded = load(tmp_path)
    assert reloaded.profiles["wb02"] == Profile(device_name="wb02", target_port=22)


def test_connect_rejects_reusing_an_as_name_for_a_different_target(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"work": Profile(device_name="wb02", target_port=22)})
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(client_cmds.app, ["connect", "wb03", "80", "--as", "work"])

    assert result.exit_code == 1
    assert "already used" in result.output


def test_connect_rejects_unknown_protocol(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(
        client_cmds.app, ["connect", "wb02", "22", "--protocol", "carrier-pigeon"]
    )

    assert result.exit_code == 1
    assert "unknown protocol" in result.output


def test_disconnect_removes_the_local_profile(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    called = {}

    def fake_disconnect(state, *, device_name, target_port):
        called.update(device_name=device_name, target_port=target_port)

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert called == {"device_name": "wb02", "target_port": 22}
    assert load(tmp_path).profiles == {}


def test_disconnect_rejects_an_unknown_profile(tmp_path):
    _enrolled_state(tmp_path)
    result = runner.invoke(client_cmds.app, ["disconnect", "no-such-profile"])
    assert result.exit_code == 1
    assert "no such connection" in result.output


def test_add_device_without_a_name_shows_the_placeholder_flag(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "add_device",
        lambda state, *, device_name_hint=None: {"token": "newtok", "device_name_hint": None},
    )

    result = runner.invoke(client_cmds.app, ["add-device"])

    assert result.exit_code == 0, result.output
    assert "enroll https://ctl.example.com newtok --name <pick-a-name>" in result.output


def test_delete_device_requires_confirmation_without_yes(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller, "delete_device", lambda *a, **k: pytest.fail("should not be called")
    )

    result = runner.invoke(client_cmds.app, ["delete-device", "old-laptop"], input="n\n")

    assert result.exit_code == 0
    assert "Deleted" not in result.output


def test_delete_device_with_yes_skips_confirmation(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = []
    monkeypatch.setattr(poller, "delete_device", lambda state, name: called.append(name))

    result = runner.invoke(client_cmds.app, ["delete-device", "old-laptop", "--yes"])

    assert result.exit_code == 0, result.output
    assert called == ["old-laptop"]


def test_list_shows_devices_from_the_server(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "list_devices",
        lambda state: [
            {"name": "wb01", "revoked": False, "last_seen_at": None},
            {"name": "old", "revoked": True, "last_seen_at": "2024-01-01T00:00:00"},
        ],
    )

    result = runner.invoke(client_cmds.app, ["list"])

    assert result.exit_code == 0, result.output
    assert "wb01" in result.output
    assert "old" in result.output


def test_commands_require_enrollment_first(tmp_path):
    for args in (["list"], ["connect", "wb01", "22"], ["disconnect", "wb01"], ["add-device"]):
        result = runner.invoke(client_cmds.app, args)
        assert result.exit_code == 1
        assert "not enrolled" in result.output


def test_disconnect_prunes_the_local_profile_even_if_already_gone_server_side(
    tmp_path, monkeypatch
):
    """If the grant already disappeared server-side (device deleted, admin
    revoked it), disconnect must still drop the stuck local profile instead
    of leaving it permanently unreusable."""
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})

    def fake_disconnect(state, *, device_name, target_port):
        raise poller.NotConnectedError("not connected")

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).profiles == {}


def test_delete_device_prunes_profiles_pointing_at_the_deleted_device(tmp_path, monkeypatch):
    _enrolled_state(
        tmp_path,
        profiles={
            "old": Profile(device_name="old-laptop", target_port=22),
            "other": Profile(device_name="wb01", target_port=22),
        },
    )
    monkeypatch.setattr(poller, "delete_device", lambda state, name: None)

    result = runner.invoke(client_cmds.app, ["delete-device", "old-laptop", "--yes"])

    assert result.exit_code == 0, result.output
    assert list(load(tmp_path).profiles) == ["other"]
