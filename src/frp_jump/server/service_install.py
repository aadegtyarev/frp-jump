"""Install and enable the `frp-jump-server` systemd unit.

Mirrors `agent/service_install.py`'s client-side pattern -- reuses its
generic `ensure_system_user`/`chown_tree`/`resolve_exec_path` helpers
(creating an isolated system account has nothing device-specific about
it), and generates a hardened unit matching this project's own real
deployment (see docs/architecture.md): a dedicated, unprivileged system
account, `ProtectSystem=strict` with a single writable data directory,
config in a separate `EnvironmentFile` the operator can keep editing
without ever touching the generated unit again. Also runs
`bootstrap.initialize` (idempotent) so this is the entire one-shot setup,
not just the unit file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from frp_jump.agent.service_install import (
    ServiceInstallError,
    chown_tree,
    ensure_system_user,
    resolve_exec_path,
)
from frp_jump.common.settings import Settings
from frp_jump.server import bootstrap

#: Module attributes, not inline literals, so tests can monkeypatch them
#: to a writable directory instead of touching the real system locations.
_SYSTEM_UNIT_DIR = Path("/etc/systemd/system")
_ENV_DIR = Path("/etc/frp-jump")

_UNIT_TEMPLATE = """\
[Unit]
Description=frp-jump server (control-plane + relay)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={system_user}
Group={system_user}
EnvironmentFile={env_path}
ExecStart={exec_path} run
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={data_dir}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""


def _read_env_value(env_path: Path, key: str) -> str | None:
    prefix = f"{key}="
    for line in env_path.read_text().splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return None


def install(*, system_user: str = "frp-jump", relay_public_addr: str | None = None) -> Path:
    """Create (if missing) a dedicated system account, its config file and
    data directory, bootstrap the CA/database in it, and a hardened
    systemd unit -- then `enable --now` it. Returns the unit path.
    Requires root. Safe to rerun (e.g. after upgrading the binary) -- an
    already-existing env file is left alone, so ``relay_public_addr`` is
    only required the first time.
    """
    if os.geteuid() != 0:
        raise ServiceInstallError("installing the service requires root -- rerun with sudo")

    data_dir = ensure_system_user(system_user)

    env_path = _ENV_DIR / f"{system_user}.env"
    if not env_path.is_file():
        if not relay_public_addr:
            raise ServiceInstallError(
                "--relay-public-addr is required the first time -- the address "
                "other devices will use to reach this server"
            )
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(
            f"FRP_JUMP_DATA_DIR={data_dir}\nFRP_JUMP_RELAY_PUBLIC_ADDR={relay_public_addr}\n"
        )
        env_path.chmod(0o640)
        shutil.chown(env_path, user=system_user, group=system_user)

    resolved_relay_addr = relay_public_addr or _read_env_value(
        env_path, "FRP_JUMP_RELAY_PUBLIC_ADDR"
    )
    settings = Settings(data_dir=data_dir, relay_public_addr=resolved_relay_addr)
    try:
        bootstrap.initialize(settings)
    except bootstrap.ConfigError as exc:
        raise ServiceInstallError(str(exc)) from exc
    chown_tree(data_dir, system_user)

    _SYSTEM_UNIT_DIR.mkdir(parents=True, exist_ok=True)
    unit_path = _SYSTEM_UNIT_DIR / "frp-jump-server.service"
    unit_path.write_text(
        _UNIT_TEMPLATE.format(
            system_user=system_user,
            env_path=env_path,
            data_dir=data_dir,
            exec_path=resolve_exec_path("frp-jump-server"),
        )
    )
    unit_path.chmod(0o644)

    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(
            ["systemctl", "enable", "--now", "frp-jump-server"], check=True, capture_output=True
        )
    except subprocess.CalledProcessError as exc:
        raise ServiceInstallError(
            f"systemctl failed: {exc.stderr.decode(errors='replace').strip()}"
        ) from exc
    except FileNotFoundError as exc:
        raise ServiceInstallError("systemctl not found -- is this a systemd system?") from exc
    return unit_path
