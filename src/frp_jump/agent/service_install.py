"""Install and enable the `frp-jump-client` systemd unit for this device.

Used by `frp-jump-client install-service`, and automatically by `enroll`
when it's run as root -- see `cli/client_cmds.py`. Idempotent: safe to
rerun (e.g. after upgrading the binary, to refresh the unit's ExecStart
path).
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from pathlib import Path

from frp_jump.agent.state import state_path

#: A module attribute, not an inline literal, so tests can monkeypatch it
#: to a writable directory instead of touching the real system location.
_SYSTEM_UNIT_DIR = Path("/etc/systemd/system")

_UNIT_TEMPLATE = """\
[Unit]
Description=frp-jump tunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{user_line}ExecStart={exec_path} run
Restart=on-failure
RestartSec=5

[Install]
WantedBy={wanted_by}
"""


class ServiceInstallError(RuntimeError):
    pass


def _resolve_exec_path() -> str:
    """The absolute path to *this* `frp-jump-client` binary -- so the
    generated unit keeps working under a venv, a self-contained `.deb`
    install, or any other layout, without hardcoding one."""
    exe = shutil.which("frp-jump-client")
    if exe is None:
        raise ServiceInstallError(
            "could not find frp-jump-client on PATH -- is it installed properly?"
        )
    return str(Path(exe).resolve())


def _home_dir_for(username: str) -> Path:
    try:
        return Path(pwd.getpwnam(username).pw_dir)
    except KeyError as exc:
        raise ServiceInstallError(f"no such user {username!r} (from $SUDO_USER)") from exc


def resolve_target_home() -> tuple[Path, str | None]:
    """Where this device's state should live, and who should own the
    systemd unit that runs it. Not just ``Path.home()`` -- when running
    as root *via sudo* from a real person's own account, that person is
    the right owner, not root: `sudo` sets $HOME to `/root` (Debian/
    Ubuntu default), so a unit with no explicit `User=`, and a naive
    ``Settings()`` read during ``enroll`` itself, would otherwise both
    land on `/root` even though a human ran the whole thing from their
    own account -- `enroll` would write state one place and the
    installed service would look in another, restart-looping forever
    without ever finding it. `cli/client_cmds.py`'s `enroll` uses this to
    keep its own write consistent with what `install` below expects.

    Returns ``(Path.home(), None)`` when there's no sudo wrapper to
    unwind: not running as root at all, or a genuine root login/a
    dedicated root-only device (both valid -- e.g. this project's own
    WB7/WB8 deployments, which run as root with no other account)."""
    if os.geteuid() != 0:
        return Path.home(), None
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return _home_dir_for(sudo_user), sudo_user
    return Path.home(), None


def _require_enrolled_state(
    data_dir_override: str | None, home: Path, *, as_user: str | None
) -> None:
    if data_dir_override:
        # An explicit override applies regardless of which user runs the
        # unit -- trust it rather than second-guess a deliberate choice.
        return
    expected = state_path(home / ".local" / "share" / "frp-jump")
    if not expected.is_file():
        who = f"as {as_user!r}" if as_user else "as this user"
        raise ServiceInstallError(
            f"no enrollment found at {expected} -- run `frp-jump-client enroll` "
            f"{who} first, or set FRP_JUMP_DATA_DIR if you use a non-default data dir"
        )


def install(*, user: bool = False) -> Path:
    """Write the systemd unit and `enable --now` it. Returns the unit path.

    System-wide (default) requires root -- pass ``user=True`` to install a
    per-user unit under ``~/.config/systemd/user`` instead (no root
    needed, but only runs while that user has a lingering/logged-in
    session, unless `loginctl enable-linger` is also set up).
    """
    data_dir_override = os.environ.get("FRP_JUMP_DATA_DIR")

    if user:
        home = Path.home()
        run_as_user = None
        unit_dir = home / ".config" / "systemd" / "user"
        wanted_by = "default.target"
        systemctl = ["systemctl", "--user"]
    else:
        if os.geteuid() != 0:
            raise ServiceInstallError(
                "installing a system-wide service requires root -- rerun with sudo, "
                "or pass --user to install a per-user service under your own account"
            )
        home, run_as_user = resolve_target_home()
        unit_dir = _SYSTEM_UNIT_DIR
        wanted_by = "multi-user.target"
        systemctl = ["systemctl"]

    _require_enrolled_state(data_dir_override, home, as_user=run_as_user)

    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "frp-jump-client.service"
    user_line = f"User={run_as_user}\n" if run_as_user else ""
    unit_path.write_text(
        _UNIT_TEMPLATE.format(
            exec_path=_resolve_exec_path(), wanted_by=wanted_by, user_line=user_line
        )
    )
    unit_path.chmod(0o644)

    try:
        subprocess.run([*systemctl, "daemon-reload"], check=True, capture_output=True)
        subprocess.run(
            [*systemctl, "enable", "--now", "frp-jump-client"], check=True, capture_output=True
        )
    except subprocess.CalledProcessError as exc:
        raise ServiceInstallError(
            f"systemctl failed: {exc.stderr.decode(errors='replace').strip()}"
        ) from exc
    except FileNotFoundError as exc:
        raise ServiceInstallError("systemctl not found -- is this a systemd system?") from exc
    return unit_path
