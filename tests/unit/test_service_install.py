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

    service_install._require_enrolled_state(None, tmp_path, as_user=None)


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
