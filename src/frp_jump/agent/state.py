"""Local agent state: this device's identity, connection info, and persisted
local port allocations for grants it consumes.

Stored as a single JSON file under the agent's data dir, including cert/key
material -- self-contained and easy to back up or inspect. Two different
"server" addresses are kept, deliberately: ``control_url`` is the
control-plane HTTP API (enroll/heartbeat/desired-state, whatever URL the
human passed to ``client enroll``); ``relay_addr``/``relay_port`` is the
frps relay's own address, learned from the enroll response, and is what the
frpc driver actually dials -- these are two different listeners on the
server and must not be conflated.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Profile:
    """A locally-named shortcut for a `connect` target -- purely client-side
    bookkeeping (this device's own memory of "what did I call that"), never
    sent to or known by the server. The server only ever sees
    (device_name, target_port); see ``registry.find_or_create_service``."""

    device_name: str
    target_port: int


@dataclass(slots=True)
class AgentState:
    device_id: str
    device_name: str
    control_url: str
    relay_addr: str
    relay_port: int
    api_token: str
    cert_pem: str
    key_pem: str
    ca_cert_pem: str
    local_ports: dict[str, int] = field(default_factory=dict)
    profiles: dict[str, Profile] = field(default_factory=dict)


def state_path(data_dir: Path) -> Path:
    return data_dir / "state.json"


def load(data_dir: Path) -> AgentState | None:
    path = state_path(data_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    data["local_ports"] = {k: int(v) for k, v in data.get("local_ports", {}).items()}
    data["profiles"] = {k: Profile(**v) for k, v in data.get("profiles", {}).items()}
    return AgentState(**data)


def save(data_dir: Path, state: AgentState) -> None:
    """Write state.json atomically: this file is the *only* copy of the
    device's private key, cert, and API token, and gets rewritten on every
    newly-seen grant -- a truncate-then-write here on power loss (an IoT
    controller's normal failure mode) makes the device unrecoverable
    without a physical re-enroll. Write-to-temp + fsync + rename instead.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    path = state_path(data_dir)
    payload = json.dumps(asdict(state), indent=2).encode("utf-8")

    fd, tmp_name = tempfile.mkstemp(dir=data_dir, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise

    dir_fd = os.open(data_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
