import pwd
from pathlib import Path

import pytest

from frp_jump.agent import service_install


def test_resolve_target_home_is_own_home_when_not_root(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("SUDO_USER", raising=False)

    home, run_as_user = service_install.resolve_target_home()

    assert home == Path.home()
    assert run_as_user is None


def test_resolve_target_home_is_root_when_no_sudo_user(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_USER", raising=False)

    home, run_as_user = service_install.resolve_target_home()

    assert run_as_user is None
    assert home == Path.home()


def test_resolve_target_home_is_root_when_sudo_user_is_root(monkeypatch):
    """`sudo -u root ...` or a genuine root login where $SUDO_USER=root
    for some other reason -- either way, not a real person to redirect to."""
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "root")

    _home, run_as_user = service_install.resolve_target_home()

    assert run_as_user is None


def test_resolve_target_home_follows_sudo_user_when_present(monkeypatch):
    """The install/enroll-consistency fix for the reviewed bug: running
    as root via `sudo` from a real person's account must resolve to
    *their* home, not root's -- otherwise `install-service` looks for
    enrolled state in the wrong place and restart-loops forever."""
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: pwd.struct_passwd(
            ("alice", "x", 1001, 1001, "", "/home/alice", "/bin/bash")
        ),
    )

    home, run_as_user = service_install.resolve_target_home()

    assert home == Path("/home/alice")
    assert run_as_user == "alice"


def test_resolve_target_home_rejects_an_unknown_sudo_user(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "nosuchuser")

    with pytest.raises(service_install.ServiceInstallError, match="no such user"):
        service_install.resolve_target_home()


def test_require_enrolled_state_passes_when_override_set(tmp_path):
    # No state file exists anywhere under tmp_path -- but an explicit
    # FRP_JUMP_DATA_DIR override must short-circuit the check entirely.
    service_install._require_enrolled_state("/some/other/dir", tmp_path, as_user=None)


def test_require_enrolled_state_raises_when_no_state_file(tmp_path):
    with pytest.raises(service_install.ServiceInstallError, match="no enrollment found"):
        service_install._require_enrolled_state(None, tmp_path, as_user="alice")


def test_require_enrolled_state_passes_when_state_file_exists(tmp_path):
    state_dir = tmp_path / ".local" / "share" / "frp-jump"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")

    service_install._require_enrolled_state(None, state_dir, as_user=None)


def test_install_as_user_requires_no_root(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    state_dir = tmp_path / ".local" / "share" / "frp-jump"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)

    unit_path = service_install.install(user=True)

    assert unit_path == tmp_path / ".config" / "systemd" / "user" / "frp-jump-client.service"
    assert "User=" not in unit_path.read_text()


def test_install_system_wide_requires_root(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 1000)

    with pytest.raises(service_install.ServiceInstallError, match="requires root"):
        service_install.install(user=False)


def test_install_system_wide_sets_user_line_for_sudo_user(tmp_path, monkeypatch):
    home = tmp_path / "home" / "alice"
    state_dir = home / ".local" / "share" / "frp-jump"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: pwd.struct_passwd(("alice", "x", 1001, 1001, "", str(home), "/bin/bash")),
    )
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    unit_dir = tmp_path / "etc-systemd"
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)

    unit_path = service_install.install(user=False)

    assert unit_path == unit_dir / "frp-jump-client.service"
    assert "User=alice\n" in unit_path.read_text()


def test_install_defaults_to_auto_system_user_on_a_fresh_device(tmp_path, monkeypatch):
    # No state.json anywhere -- a genuinely fresh device, most likely
    # `sudo enroll ...` run as the very first command.
    home = tmp_path / "home" / "alice"
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: pwd.struct_passwd(("alice", "x", 1001, 1001, "", str(home), "/bin/bash")),
    )
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(service_install, "_world_traversable", lambda path: True)
    dedicated_dir = tmp_path / "var-lib" / "frp-jump-client"
    dedicated_dir.mkdir(parents=True)
    # `enroll` (run as root, no flags) would have already written state
    # here, into whatever `resolve_default_target` decided, before ever
    # calling `install()` -- simulate that having already happened.
    (dedicated_dir / "state.json").write_text("{}")
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: dedicated_dir)
    unit_dir = tmp_path / "etc-systemd"
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)

    unit_path = service_install.install(user=False)

    assert "User=frp-jump-client\n" in unit_path.read_text()
    assert f"Environment=FRP_JUMP_DATA_DIR={dedicated_dir}\n" in unit_path.read_text()


def test_install_falls_back_to_sudo_user_when_dedicated_account_cannot_reach_binary(
    tmp_path, monkeypatch
):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    # enroll would have written state here once install() falls back to
    # this location -- simulate that having already happened in the same
    # `sudo enroll` invocation this mirrors (enroll and install-service
    # must agree on this before install() ever runs, in the real CLI).
    state_dir = home / ".local" / "share" / "frp-jump"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: pwd.struct_passwd(("alice", "x", 1001, 1001, "", str(home), "/bin/bash")),
    )
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(service_install, "_world_traversable", lambda path: False)
    unit_dir = tmp_path / "etc-systemd"
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)

    unit_path = service_install.install(user=False)

    assert "User=alice\n" in unit_path.read_text()


def test_ensure_system_user_creates_a_missing_user(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: (_ for _ in ()).throw(KeyError(name)),
    )
    monkeypatch.setattr(service_install.subprocess, "run", lambda args, **k: calls.append(args))
    monkeypatch.setattr(service_install, "_VAR_LIB_DIR", tmp_path)
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)

    state_dir = service_install.ensure_system_user("frp-jump-client")

    assert calls[0][0] == "useradd"
    assert "frp-jump-client" in calls[0]
    assert state_dir == tmp_path / "frp-jump-client"
    assert state_dir.is_dir()
    assert (state_dir.stat().st_mode & 0o777) == 0o750


def test_ensure_system_user_skips_useradd_if_already_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: pwd.struct_passwd(
            (name, "x", 999, 999, "", "/nonexistent", "/usr/sbin/nologin")
        ),
    )
    called = []
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: called.append(a))
    monkeypatch.setattr(service_install, "_VAR_LIB_DIR", tmp_path)
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)

    service_install.ensure_system_user("frp-jump-client")

    assert called == []


def test_ensure_system_user_wraps_useradd_failure(monkeypatch):
    monkeypatch.setattr(
        service_install.pwd,
        "getpwnam",
        lambda name: (_ for _ in ()).throw(KeyError(name)),
    )

    def fake_run(args, **k):
        raise service_install.subprocess.CalledProcessError(1, args, stderr=b"boom")

    monkeypatch.setattr(service_install.subprocess, "run", fake_run)

    with pytest.raises(service_install.ServiceInstallError, match="could not create system user"):
        service_install.ensure_system_user("frp-jump-client")


def test_install_rejects_user_and_system_user_together():
    with pytest.raises(service_install.ServiceInstallError, match="mutually exclusive"):
        service_install.install(user=True, system_user="frp-jump-client")


def test_install_system_user_requires_root(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 1000)

    with pytest.raises(service_install.ServiceInstallError, match="requires root"):
        service_install.install(system_user="frp-jump-client")


def test_install_system_user_sets_user_line_and_env(tmp_path, monkeypatch):
    state_dir = tmp_path / "var-lib" / "frp-jump-client"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: state_dir)
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(service_install, "_world_traversable", lambda path: True)
    unit_dir = tmp_path / "etc-systemd"
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)

    unit_path = service_install.install(system_user="frp-jump-client")

    content = unit_path.read_text()
    assert "User=frp-jump-client\n" in content
    assert f"Environment=FRP_JUMP_DATA_DIR={state_dir}\n" in content


def test_install_system_user_respects_data_dir_override(tmp_path, monkeypatch):
    state_dir = tmp_path / "var-lib" / "frp-jump-client"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text("{}")

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setenv("FRP_JUMP_DATA_DIR", "/some/other/dir")
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: state_dir)
    monkeypatch.setattr(service_install.shutil, "which", lambda name: "/usr/bin/frp-jump-client")
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(service_install, "_world_traversable", lambda path: True)
    unit_dir = tmp_path / "etc-systemd"
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)

    unit_path = service_install.install(system_user="frp-jump-client")

    assert "Environment=FRP_JUMP_DATA_DIR=" not in unit_path.read_text()
