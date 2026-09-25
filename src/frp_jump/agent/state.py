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

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


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


def state_path(data_dir: Path) -> Path:
    return data_dir / "state.json"


def load(data_dir: Path) -> AgentState | None:
    path = state_path(data_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    data["local_ports"] = {k: int(v) for k, v in data.get("local_ports", {}).items()}
    return AgentState(**data)


def save(data_dir: Path, state: AgentState) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = state_path(data_dir)
    path.write_text(json.dumps(asdict(state), indent=2))
    path.chmod(0o600)
