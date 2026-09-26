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
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40001)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:22"])

    assert result.exit_code == 0, result.output
    assert "Connected" in result.output
    assert "40001" in result.output
    reloaded = load(tmp_path)
    assert reloaded.profiles["wb02"] == Profile(device_name="wb02", target_port=22)


def test_connect_auto_disambiguates_a_second_port_on_the_same_device(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    monkeypatch.setattr(
        poller,
        "connect",
        lambda state, *, device_name, target_port, protocol: {"grant_id": "g2"},
    )
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40002)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:8080", "--protocol", "http"])

    assert result.exit_code == 0, result.output
    reloaded = load(tmp_path)
    assert reloaded.profiles["wb02"] == Profile(device_name="wb02", target_port=22)
    assert reloaded.profiles["wb02-8080"] == Profile(device_name="wb02", target_port=8080)


def test_connect_shows_a_fallback_message_when_no_local_port_appears(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller, "connect", lambda state, *, device_name, target_port, protocol: {"grant_id": "g1"}
    )
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: None)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:22"])

    assert result.exit_code == 0, result.output
    assert "no local port yet" in result.output


def test_connect_rejects_a_target_without_a_colon(tmp_path):
    _enrolled_state(tmp_path)
    result = runner.invoke(client_cmds.app, ["connect", "wb02"])
    assert result.exit_code != 0
    assert "DEVICE:PORT" in result.output


def test_connect_rejects_reusing_an_as_name_for_a_different_target(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"work": Profile(device_name="wb02", target_port=22)})
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(client_cmds.app, ["connect", "wb03:80", "--as", "work"])

    assert result.exit_code == 1
    assert "already used" in result.output


def test_connect_rejects_unknown_protocol(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(
        client_cmds.app, ["connect", "wb02:22", "--protocol", "carrier-pigeon"]
    )

    assert result.exit_code == 1
    assert "unknown protocol" in result.output


def test_disconnect_tears_down_the_tunnel_but_keeps_the_profile(tmp_path, monkeypatch):
    """Profiles are persistent saved shortcuts, independent of whether the
    tunnel is currently up -- `disconnect` only brings the tunnel down;
    `profiles delete` is the only thing that removes the shortcut itself."""
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    called = {}

    def fake_disconnect(state, *, device_name, target_port):
        called.update(device_name=device_name, target_port=target_port)

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert called == {"device_name": "wb02", "target_port": 22}
    assert load(tmp_path).profiles == {"wb02": Profile(device_name="wb02", target_port=22)}


def test_disconnect_rejects_an_unknown_profile(tmp_path):
    _enrolled_state(tmp_path)
    result = runner.invoke(client_cmds.app, ["disconnect", "no-such-profile"])
    assert result.exit_code == 1
    assert "no such connection" in result.output


def test_disconnect_accepts_device_port_directly_without_a_profile(tmp_path, monkeypatch):
    """A profile can be missing (lost to the race this release fixes, or
    just never set) -- `disconnect DEVICE:PORT` must still work without one."""
    _enrolled_state(tmp_path)
    called = {}

    def fake_disconnect(state, *, device_name, target_port):
        called.update(device_name=device_name, target_port=target_port)

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02:22"])

    assert result.exit_code == 0, result.output
    assert called == {"device_name": "wb02", "target_port": 22}


def test_connect_reconnects_by_existing_profile_name(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"my-nickname": Profile(device_name="wb02", target_port=22)})
    called = {}

    def fake_connect(state, *, device_name, target_port, protocol):
        called.update(device_name=device_name, target_port=target_port)
        return {"grant_id": "g1"}

    monkeypatch.setattr(poller, "connect", fake_connect)
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40001)

    result = runner.invoke(client_cmds.app, ["connect", "my-nickname"])

    assert result.exit_code == 0, result.output
    assert called == {"device_name": "wb02", "target_port": 22}


def test_connect_rejects_an_unknown_profile_name(tmp_path):
    _enrolled_state(tmp_path)
    result = runner.invoke(client_cmds.app, ["connect", "no-such-profile"])
    assert result.exit_code == 1
    assert "no profile named" in result.output


def test_connect_rejects_as_option_when_reconnecting_by_profile_name(tmp_path):
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    result = runner.invoke(client_cmds.app, ["connect", "wb02", "--as", "renamed"])
    assert result.exit_code == 1
    assert "only applies when connecting via DEVICE:PORT" in result.output


def test_profiles_list_shows_saved_profiles(tmp_path):
    _enrolled_state(
        tmp_path,
        profiles={
            "wb01": Profile(device_name="wb01", target_port=22),
            "wb01-web": Profile(device_name="wb01", target_port=8080),
        },
    )
    result = runner.invoke(client_cmds.app, ["profiles", "list"])
    assert result.exit_code == 0, result.output
    assert "wb01-web" in result.output
    assert "8080" in result.output


def test_profiles_delete_removes_a_profile(tmp_path):
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    result = runner.invoke(client_cmds.app, ["profiles", "delete", "wb02"])
    assert result.exit_code == 0, result.output
    assert load(tmp_path).profiles == {}


def test_profiles_delete_rejects_an_unknown_name(tmp_path):
    _enrolled_state(tmp_path)
    result = runner.invoke(client_cmds.app, ["profiles", "delete", "no-such-profile"])
    assert result.exit_code == 1
    assert "no such profile" in result.output


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
    for args in (["list"], ["connect", "wb01:22"], ["disconnect", "wb01"], ["add-device"]):
        result = runner.invoke(client_cmds.app, args)
        assert result.exit_code == 1
        assert "not enrolled" in result.output


def test_disconnect_succeeds_and_keeps_the_profile_even_if_already_gone_server_side(
    tmp_path, monkeypatch
):
    """If the grant already disappeared server-side (device deleted, admin
    revoked it), disconnect is still a success (the desired end state --
    not connected -- is reached either way), and the profile is untouched."""
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})

    def fake_disconnect(state, *, device_name, target_port):
        raise poller.NotConnectedError("not connected")

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).profiles == {"wb02": Profile(device_name="wb02", target_port=22)}


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
