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
import sys
from pathlib import Path

from frp_jump.agent.state import state_path

#: Module attributes, not inline literals, so tests can monkeypatch them
#: to a writable directory instead of touching the real system locations.
_SYSTEM_UNIT_DIR = Path("/etc/systemd/system")
_VAR_LIB_DIR = Path("/var/lib")

_UNIT_TEMPLATE = """\
[Unit]
Description=frp-jump tunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{user_line}{env_line}ExecStart={exec_path} run
Restart=on-failure
RestartSec=5

[Install]
WantedBy={wanted_by}
"""


class ServiceInstallError(RuntimeError):
    pass


def resolve_exec_path(binary_name: str = "frp-jump-client") -> str:
    """The absolute path to *this* binary (``frp-jump-client``, or
    ``frp-jump-server`` -- see ``server/service_install.py``, which
    reuses this) -- so the generated unit keeps working under a venv, a
    self-contained `.deb` install, or any other layout, without
    hardcoding one.

    Prefers ``sys.argv[0]`` (how *this exact running process* was
    invoked) over a fresh ``PATH`` search: someone running `sudo
    /path/to/frp-jump-client install-service` is very likely doing so
    specifically because sudo's own restricted PATH (`secure_path`)
    doesn't include a venv/`--user` install location -- re-searching
    that same restricted PATH here would fail even though we are
    demonstrably already running from a known-good path (this exact
    sequence broke a real install). Only falls back to a PATH search
    when invoked by a bare command name, where that search is what
    found us in the first place.
    """
    argv0 = sys.argv[0]
    if "/" in argv0:
        candidate = Path(argv0)
        if candidate.is_file():
            return str(candidate.resolve())
    exe = shutil.which(argv0) or shutil.which(binary_name)
    if exe is None:
        raise ServiceInstallError(
            f"could not find {binary_name} on PATH -- is it installed properly?"
        )
    return str(Path(exe).resolve())


def _home_dir_for(username: str) -> Path:
    try:
        return Path(pwd.getpwnam(username).pw_dir)
    except KeyError as exc:
        raise ServiceInstallError(f"no such user {username!r} (from $SUDO_USER)") from exc


def ensure_system_user(name: str) -> Path:
    """Create ``name`` as a dedicated, unprivileged system account (no
    login shell, no home directory of its own) if it doesn't already
    exist -- for running the agent under an isolated identity instead of
    root or a real person's own account, same as this project's own
    server-side deployments (see docs/architecture.md). Returns its state
    directory, ``/var/lib/<name>``, created and chowned to that account."""
    try:
        pwd.getpwnam(name)
    except KeyError:
        try:
            subprocess.run(
                ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            raise ServiceInstallError(
                f"could not create system user {name!r}: "
                f"{exc.stderr.decode(errors='replace').strip()}"
            ) from exc
        except FileNotFoundError as exc:
            raise ServiceInstallError(
                "useradd not found -- is this a systemd/Debian-family system?"
            ) from exc

    state_dir = _VAR_LIB_DIR / name
    state_dir.mkdir(parents=True, exist_ok=True)
    chown_tree(state_dir, name)
    state_dir.chmod(0o750)
    return state_dir


def chown_tree(path: Path, name: str) -> None:
    """`enroll`/`install-service` both run as root while setting this up,
    so files they create are root-owned by default regardless of the
    parent directory's ownership -- the dedicated account (running
    unprivileged once the service starts) needs to actually own them."""
    shutil.chown(path, user=name, group=name)
    for child in path.rglob("*"):
        shutil.chown(child, user=name, group=name)


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
    data_dir_override: str | None, data_dir: Path, *, as_user: str | None
) -> None:
    if data_dir_override:
        # An explicit override applies regardless of which user runs the
        # unit -- trust it rather than second-guess a deliberate choice.
        return
    expected = state_path(data_dir)
    if not expected.is_file():
        who = f"as {as_user!r}" if as_user else "as this user"
        raise ServiceInstallError(
            f"no enrollment found at {expected} -- run `frp-jump-client enroll` "
            f"{who} first, or set FRP_JUMP_DATA_DIR if you use a non-default data dir"
        )


def install(*, user: bool = False, system_user: str | None = None) -> Path:
    """Write the systemd unit and `enable --now` it. Returns the unit path.

    Three mutually exclusive modes:

    - Neither flag (default): system-wide, requires root, runs as the
      person who invoked `sudo` (or plain root, on a root-only device).
    - ``user=True``: a per-user unit under ``~/.config/systemd/user``, no
      root needed -- but only runs while that account has a lingering/
      logged-in session, unless `loginctl enable-linger` is also set up.
    - ``system_user=<name>``: requires root; creates (if missing) a
      dedicated, unprivileged system account with no login shell of its
      own and runs the unit as it, isolated from both root and any real
      person's account -- see ``ensure_system_user``.
    """
    if user and system_user:
        raise ServiceInstallError("--user and --system-user are mutually exclusive")
    data_dir_override = os.environ.get("FRP_JUMP_DATA_DIR")
    env_line = ""

    if system_user:
        if os.geteuid() != 0:
            raise ServiceInstallError("--system-user requires root -- rerun with sudo")
        data_dir = ensure_system_user(system_user)
        run_as_user = system_user
        unit_dir = _SYSTEM_UNIT_DIR
        wanted_by = "multi-user.target"
        systemctl = ["systemctl"]
        if not data_dir_override:
            env_line = f"Environment=FRP_JUMP_DATA_DIR={data_dir}\n"
    elif user:
        data_dir = Path.home() / ".local" / "share" / "frp-jump"
        run_as_user = None
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        wanted_by = "default.target"
        systemctl = ["systemctl", "--user"]
    else:
        if os.geteuid() != 0:
            raise ServiceInstallError(
                "installing a system-wide service requires root -- rerun with sudo, "
                "or pass --user to install a per-user service under your own account"
            )
        home, run_as_user = resolve_target_home()
        data_dir = home / ".local" / "share" / "frp-jump"
        unit_dir = _SYSTEM_UNIT_DIR
        wanted_by = "multi-user.target"
        systemctl = ["systemctl"]

    _require_enrolled_state(data_dir_override, data_dir, as_user=run_as_user)

    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "frp-jump-client.service"
    user_line = f"User={run_as_user}\n" if run_as_user else ""
    unit_path.write_text(
        _UNIT_TEMPLATE.format(
            exec_path=resolve_exec_path(),
            wanted_by=wanted_by,
            user_line=user_line,
            env_line=env_line,
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
