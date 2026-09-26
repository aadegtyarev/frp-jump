from datetime import UTC, datetime
from pathlib import Path

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

    result = runner.invoke(client_cmds.app, ["connect", "wb02:8080"])

    assert result.exit_code == 0, result.output
    reloaded = load(tmp_path)
    assert reloaded.profiles["wb02"] == Profile(device_name="wb02", target_port=22)
    assert reloaded.profiles["wb02-8080"] == Profile(device_name="wb02", target_port=8080)


def test_connect_classifies_well_known_ssh_ports_automatically(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    captured = {}

    def fake_connect(state, *, device_name, target_port, protocol):
        captured["protocol"] = protocol
        return {"grant_id": "g1"}

    monkeypatch.setattr(poller, "connect", fake_connect)
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40001)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:22"])

    assert result.exit_code == 0, result.output
    from frp_jump.driver.base import ServiceProtocol

    assert captured["protocol"] == ServiceProtocol.SSH


def test_connect_classifies_other_ports_as_tcp_by_default(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    captured = {}

    def fake_connect(state, *, device_name, target_port, protocol):
        captured["protocol"] = protocol
        return {"grant_id": "g1"}

    monkeypatch.setattr(poller, "connect", fake_connect)
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40001)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:8080"])

    assert result.exit_code == 0, result.output
    from frp_jump.driver.base import ServiceProtocol

    assert captured["protocol"] == ServiceProtocol.TCP


def test_connect_ssh_flag_forces_ssh_classification_for_a_nonstandard_port(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    captured = {}

    def fake_connect(state, *, device_name, target_port, protocol):
        captured["protocol"] = protocol
        return {"grant_id": "g1"}

    monkeypatch.setattr(poller, "connect", fake_connect)
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40001)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:2200", "--ssh"])

    assert result.exit_code == 0, result.output
    from frp_jump.driver.base import ServiceProtocol

    assert captured["protocol"] == ServiceProtocol.SSH


def test_connect_local_port_pins_the_port_in_state(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "connect",
        lambda state, *, device_name, target_port, protocol: {"grant_id": "g1"},
    )
    monkeypatch.setattr(poller, "is_bindable", lambda port: True)
    monkeypatch.setattr(client_cmds, "_wait_for_local_port", lambda data_dir, grant_id: 40777)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:22", "--local-port", "40777"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).local_ports["g1"] == 40777


def test_connect_rejects_a_local_port_already_in_use(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))
    monkeypatch.setattr(poller, "is_bindable", lambda port: False)

    result = runner.invoke(client_cmds.app, ["connect", "wb02:22", "--local-port", "40777"])

    assert result.exit_code == 1
    assert "not free" in result.output


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
    assert "no profile named" in result.output
    assert "DEVICE:22" in result.output


def test_connect_rejects_reusing_an_as_name_for_a_different_target(tmp_path, monkeypatch):
    _enrolled_state(tmp_path, profiles={"work": Profile(device_name="wb02", target_port=22)})
    monkeypatch.setattr(poller, "connect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(client_cmds.app, ["connect", "wb03:80", "--as", "work"])

    assert result.exit_code == 1
    assert "already used" in result.output


def test_disconnect_tears_down_the_tunnel_but_keeps_the_profile(tmp_path, monkeypatch):
    """Profiles are persistent saved shortcuts, independent of whether the
    tunnel is currently up -- `disconnect` only brings the tunnel down;
    `profiles delete` is the only thing that removes the shortcut itself."""
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})
    called = {}

    def fake_disconnect(state, *, device_name, target_port, consumer_device_name=None):
        called.update(
            device_name=device_name, target_port=target_port,
            consumer_device_name=consumer_device_name,
        )

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert called == {
        "device_name": "wb02", "target_port": 22, "consumer_device_name": None,
    }
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

    def fake_disconnect(state, *, device_name, target_port, consumer_device_name=None):
        called.update(device_name=device_name, target_port=target_port)

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02:22"])

    assert result.exit_code == 0, result.output
    assert called == {"device_name": "wb02", "target_port": 22}


def test_disconnect_from_a_different_device_passes_it_through_and_confirms(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = {}

    def fake_disconnect(state, *, device_name, target_port, consumer_device_name=None):
        called.update(
            device_name=device_name, target_port=target_port,
            consumer_device_name=consumer_device_name,
        )

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(
        client_cmds.app, ["disconnect", "wb02:22", "--from", "phone"], input="y\n"
    )

    assert result.exit_code == 0, result.output
    assert called == {
        "device_name": "wb02", "target_port": 22, "consumer_device_name": "phone",
    }


def test_disconnect_from_a_different_device_aborts_without_confirmation(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(poller, "disconnect", lambda *a, **k: pytest.fail("should not be called"))

    result = runner.invoke(
        client_cmds.app, ["disconnect", "wb02:22", "--from", "phone"], input="n\n"
    )

    assert result.exit_code == 0


def test_disconnect_from_a_different_device_skips_confirmation_with_yes(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = {}
    monkeypatch.setattr(
        poller,
        "disconnect",
        lambda state, *, device_name, target_port, consumer_device_name=None: called.update(
            consumer_device_name=consumer_device_name
        ),
    )

    result = runner.invoke(
        client_cmds.app, ["disconnect", "wb02:22", "--from", "phone", "--yes"]
    )

    assert result.exit_code == 0, result.output
    assert called == {"consumer_device_name": "phone"}


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


def test_devices_add_token_without_a_name_shows_the_placeholder_flag(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "add_device",
        lambda state, *, device_name_hint=None: {"token": "newtok", "device_name_hint": None},
    )

    result = runner.invoke(client_cmds.app, ["devices", "add-token"])

    assert result.exit_code == 0, result.output
    assert "enroll https://ctl.example.com newtok --name <pick-a-name>" in result.output


def test_devices_delete_requires_confirmation_without_yes(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller, "delete_device", lambda *a, **k: pytest.fail("should not be called")
    )

    result = runner.invoke(client_cmds.app, ["devices", "delete", "old-laptop"], input="n\n")

    assert result.exit_code == 0
    assert "Deleted" not in result.output


def test_devices_delete_with_yes_skips_confirmation(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = []
    monkeypatch.setattr(poller, "delete_device", lambda state, name: called.append(name))

    result = runner.invoke(client_cmds.app, ["devices", "delete", "old-laptop", "--yes"])

    assert result.exit_code == 0, result.output
    assert called == ["old-laptop"]


def test_devices_disable_calls_poller(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = []
    monkeypatch.setattr(poller, "disable_device", lambda state, name: called.append(name))

    result = runner.invoke(client_cmds.app, ["devices", "disable", "old-laptop"])

    assert result.exit_code == 0, result.output
    assert called == ["old-laptop"]
    assert "Disabled" in result.output


def test_devices_enable_calls_poller(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    called = []
    monkeypatch.setattr(poller, "enable_device", lambda state, name: called.append(name))

    result = runner.invoke(client_cmds.app, ["devices", "enable", "old-laptop"])

    assert result.exit_code == 0, result.output
    assert called == ["old-laptop"]
    assert "Enabled" in result.output


def test_devices_list_shows_devices_from_the_server(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "list_devices",
        lambda state: [
            {"name": "wb01", "enabled": True, "last_seen_at": None},
            {"name": "old", "enabled": False, "last_seen_at": "2024-01-01T00:00:00"},
        ],
    )

    result = runner.invoke(client_cmds.app, ["devices", "list"])

    assert result.exit_code == 0, result.output
    assert "wb01" in result.output
    assert "old" in result.output
    assert "offline" in result.output


def test_devices_list_shows_a_recently_seen_device_as_online(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "list_devices",
        lambda state: [
            {"name": "wb01", "enabled": True, "last_seen_at": datetime.now(UTC).isoformat()},
        ],
    )

    result = runner.invoke(client_cmds.app, ["devices", "list"])

    assert result.exit_code == 0, result.output
    assert "online" in result.output


def test_is_recent_treats_a_naive_timestamp_as_utc():
    naive_now = datetime.now(UTC).replace(tzinfo=None).isoformat()
    assert client_cmds._is_recent(naive_now, threshold_seconds=30.0) is True


def test_is_recent_is_false_for_none():
    assert client_cmds._is_recent(None, threshold_seconds=30.0) is False


def _write_keypair(path: Path, public_key: str) -> Path:
    path.write_text("private-key-material")
    path.with_suffix(".pub").write_text(public_key)
    return path


def test_set_key_signs_the_challenge_with_both_keys(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    key_path = _write_keypair(tmp_path / "new_key", "ssh-ed25519 AAAA... me@host\n")
    current_key_path = _write_keypair(tmp_path / "current_key", "ssh-ed25519 BBBB... me@host\n")
    called = []
    monkeypatch.setattr(
        poller,
        "set_key",
        lambda state, identity_path, public_key, *, current_identity_path: called.append(
            (identity_path, public_key, current_identity_path)
        ),
    )

    result = runner.invoke(client_cmds.app, ["set-key", str(key_path), str(current_key_path)])

    assert result.exit_code == 0, result.output
    assert called == [(key_path, "ssh-ed25519 AAAA... me@host\n", current_key_path)]


def test_set_key_accepts_the_pub_sibling_too(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    key_path = _write_keypair(tmp_path / "new_key", "ssh-ed25519 AAAA... me@host\n")
    current_key_path = _write_keypair(tmp_path / "current_key", "ssh-ed25519 BBBB... me@host\n")
    called = []
    monkeypatch.setattr(
        poller,
        "set_key",
        lambda state, identity_path, public_key, *, current_identity_path: called.append(
            (identity_path, public_key, current_identity_path)
        ),
    )

    result = runner.invoke(
        client_cmds.app,
        ["set-key", str(key_path.with_suffix(".pub")), str(current_key_path)],
    )

    assert result.exit_code == 0, result.output
    assert called == [(key_path, "ssh-ed25519 AAAA... me@host\n", current_key_path)]


def test_set_key_rejects_a_missing_pub_file(tmp_path):
    _enrolled_state(tmp_path)
    key_path = tmp_path / "new_key"
    key_path.write_text("private-key-material")
    current_key_path = _write_keypair(tmp_path / "current_key", "ssh-ed25519 BBBB... me@host\n")

    result = runner.invoke(client_cmds.app, ["set-key", str(key_path), str(current_key_path)])

    assert result.exit_code == 1
    assert "could not find" in result.output


def test_set_key_rejects_an_empty_pub_file(tmp_path):
    _enrolled_state(tmp_path)
    key_path = tmp_path / "new_key"
    key_path.write_text("private-key-material")
    key_path.with_suffix(".pub").write_text("")
    current_key_path = _write_keypair(tmp_path / "current_key", "ssh-ed25519 BBBB... me@host\n")

    result = runner.invoke(client_cmds.app, ["set-key", str(key_path), str(current_key_path)])

    assert result.exit_code == 1
    assert "empty" in result.output


def test_status_flags_an_exposed_port_nothing_is_listening_on(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "fetch_desired_state",
        lambda state: {
            "exposed": [{"grant_id": "g1", "target_port": 8080}],
            "consumed": [],
        },
    )
    monkeypatch.setattr(poller, "is_listening", lambda port: False)

    result = runner.invoke(client_cmds.app, ["status"])

    assert result.exit_code == 0, result.output
    assert "8080" in result.output
    assert "no -- nothing is listening" in result.output


def test_status_reports_an_exposed_port_that_is_listening(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(
        poller,
        "fetch_desired_state",
        lambda state: {
            "exposed": [{"grant_id": "g1", "target_port": 22}],
            "consumed": [],
        },
    )
    monkeypatch.setattr(poller, "is_listening", lambda port: True)

    result = runner.invoke(client_cmds.app, ["status"])

    assert result.exit_code == 0, result.output
    assert "22" in result.output
    assert "yes" in result.output


def test_doctor_reports_a_compatible_protocol_version(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(client_cmds.poller, "send_heartbeat", lambda state, agent_version: None)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "frpc").touch()
    monkeypatch.setattr(
        client_cmds.poller,
        "fetch_server_version",
        lambda state: {
            "protocol_version": client_cmds.PROTOCOL_VERSION,
            "package_version": "0.3.3",
        },
    )

    result = runner.invoke(client_cmds.app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "protocol compatible" in result.output


def test_doctor_reports_a_protocol_mismatch(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(client_cmds.poller, "send_heartbeat", lambda state, agent_version: None)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "frpc").touch()
    monkeypatch.setattr(
        client_cmds.poller,
        "fetch_server_version",
        lambda state: {
            "protocol_version": client_cmds.PROTOCOL_VERSION + 1,
            "package_version": "9.9.9",
        },
    )

    result = runner.invoke(client_cmds.app, ["doctor"])

    assert result.exit_code == 1
    assert "protocol mismatch" in result.output


def test_run_uses_the_default_poll_interval_when_not_overridden(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(client_cmds, "_make_driver_with_retry", lambda settings, **kwargs: object())
    captured = {}
    monkeypatch.setattr(
        client_cmds.poller,
        "run_forever",
        lambda state, driver, **kwargs: captured.update(kwargs),
    )

    result = runner.invoke(client_cmds.app, ["run"])

    assert result.exit_code == 0, result.output
    assert captured["poll_interval_seconds"] == client_cmds.Settings().agent_poll_interval_seconds


def test_run_poll_interval_overrides_the_default(tmp_path, monkeypatch):
    _enrolled_state(tmp_path)
    monkeypatch.setattr(client_cmds, "_make_driver_with_retry", lambda settings, **kwargs: object())
    captured = {}
    monkeypatch.setattr(
        client_cmds.poller,
        "run_forever",
        lambda state, driver, **kwargs: captured.update(kwargs),
    )

    result = runner.invoke(client_cmds.app, ["run", "--poll-interval", "5"])

    assert result.exit_code == 0, result.output
    assert captured["poll_interval_seconds"] == 5.0


def test_commands_require_enrollment_first(tmp_path):
    commands = (
        ["devices", "list"],
        ["connect", "wb01:22"],
        ["disconnect", "wb01"],
        ["devices", "add-token"],
        ["set-key", "some.pub", "current.pub"],
        ["install-service"],
    )
    for args in commands:
        result = runner.invoke(client_cmds.app, args)
        assert result.exit_code == 1, args
        assert "not enrolled" in result.output, args


def test_install_service_finds_state_under_sudo_users_own_home(tmp_path, monkeypatch):
    """Regression test: enroll unprivileged (state under the real
    person's home), then `sudo frp-jump-client install-service` -- the
    pre-flight `_require_state` check must resolve the same sudo-aware
    home as `service_install.install` itself does, not root's."""
    monkeypatch.delenv("FRP_JUMP_DATA_DIR", raising=False)
    home = tmp_path / "home" / "alice"
    _enrolled_state(home / ".local" / "share" / "frp-jump")

    monkeypatch.setattr(client_cmds.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        client_cmds.service_install, "resolve_target_home", lambda: (home, "alice")
    )
    monkeypatch.setattr(
        client_cmds.service_install,
        "install",
        lambda *, user, system_user=None: Path("/etc/systemd/system/x"),
    )

    result = runner.invoke(client_cmds.app, ["install-service"])

    assert result.exit_code == 0, result.output
    assert "not enrolled" not in result.output
    assert "Installed and started" in result.output


def test_enroll_rejects_user_and_system_user_together():
    result = runner.invoke(
        client_cmds.app,
        ["enroll", "https://ctl.example.com", "sometoken", "--user", "--system-user", "x"],
    )
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output


def test_install_service_rejects_user_and_system_user_together():
    result = runner.invoke(
        client_cmds.app, ["install-service", "--user", "--system-user", "x"]
    )
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output


def test_install_service_system_user_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("FRP_JUMP_DATA_DIR", raising=False)
    state_dir = tmp_path / "var-lib" / "frp-jump-client"
    _enrolled_state(state_dir)

    monkeypatch.setattr(client_cmds.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        client_cmds.service_install, "ensure_system_user", lambda name: state_dir
    )
    monkeypatch.setattr(
        client_cmds.service_install,
        "install",
        lambda *, user, system_user=None: Path("/etc/systemd/system/x"),
    )

    result = runner.invoke(
        client_cmds.app, ["install-service", "--system-user", "frp-jump-client"]
    )

    assert result.exit_code == 0, result.output
    assert "Installed and started" in result.output


def test_disconnect_succeeds_and_keeps_the_profile_even_if_already_gone_server_side(
    tmp_path, monkeypatch
):
    """If the grant already disappeared server-side (device deleted, admin
    disabled it), disconnect is still a success (the desired end state --
    not connected -- is reached either way), and the profile is untouched."""
    _enrolled_state(tmp_path, profiles={"wb02": Profile(device_name="wb02", target_port=22)})

    def fake_disconnect(state, *, device_name, target_port, consumer_device_name=None):
        raise poller.NotConnectedError("not connected")

    monkeypatch.setattr(poller, "disconnect", fake_disconnect)

    result = runner.invoke(client_cmds.app, ["disconnect", "wb02"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).profiles == {"wb02": Profile(device_name="wb02", target_port=22)}


def test_devices_delete_prunes_profiles_pointing_at_the_deleted_device(tmp_path, monkeypatch):
    _enrolled_state(
        tmp_path,
        profiles={
            "old": Profile(device_name="old-laptop", target_port=22),
            "other": Profile(device_name="wb01", target_port=22),
        },
    )
    monkeypatch.setattr(poller, "delete_device", lambda state, name: None)

    result = runner.invoke(client_cmds.app, ["devices", "delete", "old-laptop", "--yes"])

    assert result.exit_code == 0, result.output
    assert list(load(tmp_path).profiles) == ["other"]


def test_set_p2p_disabled_persists_and_wakes_the_daemon(tmp_path):
    _enrolled_state(tmp_path)

    result = runner.invoke(client_cmds.app, ["set-p2p", "disabled"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).disable_p2p is True
    assert (tmp_path / "wake").exists()


def test_set_p2p_enabled_clears_a_previously_disabled_flag(tmp_path):
    _enrolled_state(tmp_path, disable_p2p=True)

    result = runner.invoke(client_cmds.app, ["set-p2p", "enabled"])

    assert result.exit_code == 0, result.output
    assert load(tmp_path).disable_p2p is False


def test_version_flag_prints_the_installed_version_and_exits():
    result = runner.invoke(client_cmds.app, ["--version"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == client_cmds._AGENT_VERSION


def test_bare_invocation_shows_help_instead_of_missing_command_error():
    """Click's own convention: `no_args_is_help` still exits non-zero (a
    UsageError, exit code 2) -- the point is that the full rich help text,
    including every subcommand, now shows instead of a bare "Missing
    command" one-liner with no further guidance."""
    result = runner.invoke(client_cmds.app, [])

    assert result.exit_code == 2
    assert "Missing command" not in result.output
    assert "enroll" in result.output
    assert "devices" in result.output


def test_bare_subcommand_group_shows_help_instead_of_missing_command_error():
    result = runner.invoke(client_cmds.app, ["devices"])

    assert result.exit_code == 2
    assert "Missing command" not in result.output
    assert "list" in result.output
    assert "add-token" in result.output
