"""Make consumed SSH grants reachable via `ssh <service-name>`.

We never edit ``~/.ssh/config`` beyond ensuring a single ``Include`` line
at its top; every ``Host`` block frp-jump manages lives in its own file,
fully regenerated on every apply so it always matches the current grants.
"""

from __future__ import annotations

import re
from pathlib import Path

_MANAGED_HEADER = "# managed by frp-jump -- do not edit, changes are overwritten on the next sync\n"

# Same character class as server/registry.py's device/service name rule --
# whatever ends up as an ssh_config `Host` alias must be just as strict,
# whether it came from the server (already validated there) or from a
# purely local, never-server-validated `connect --as <name>` profile.
_SAFE_ALIAS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def is_safe_alias(name: str) -> bool:
    return bool(_SAFE_ALIAS_RE.match(name))


def managed_config_path(data_dir: Path) -> Path:
    return data_dir / "ssh_config"


def render_ssh_config(entries: list[tuple[str, int]]) -> str:
    """``entries``: (service_name, local_port) for each consumed SSH grant.

    Defense in depth: rejects an alias that isn't ``is_safe_alias`` rather
    than trust every caller upstream to have checked -- a stray newline or
    ssh_config keyword here is a path to config injection on this device.
    """
    lines = [_MANAGED_HEADER]
    for name, port in entries:
        if not is_safe_alias(name):
            raise ValueError(f"unsafe ssh_config Host alias: {name!r}")
        lines.append(f"\nHost {name}\n    HostName 127.0.0.1\n    Port {port}\n")
    return "".join(lines)


def write_ssh_config(data_dir: Path, entries: list[tuple[str, int]]) -> Path:
    path = managed_config_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_ssh_config(entries))
    return path


def ensure_include(ssh_config_path: Path, managed_path: Path) -> bool:
    """Idempotently prepend ``Include <managed_path>`` to ``ssh_config_path``.

    Prepended (not appended) so frp-jump's ``Host`` entries are matched
    before any conflicting ones the user already has -- ssh_config uses
    first-match-wins per keyword. Returns True if it had to add the line.
    """
    include_line = f"Include {managed_path}\n"
    ssh_config_path.parent.mkdir(parents=True, exist_ok=True)
    existing = ssh_config_path.read_text() if ssh_config_path.exists() else ""
    if str(managed_path) in existing:
        return False
    ssh_config_path.write_text(include_line + existing)
    return True
