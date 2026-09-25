"""Supervise a long-running frpc/frps subprocess.

Kept separate from ``driver.py`` and behind the ``ProcessSupervisor``
Protocol so the config-diffing / restart-on-change logic in ``FrpDriver``
can be unit-tested without spawning any real process.
"""

from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path
from typing import Protocol, runtime_checkable

_TERM_GRACE_PERIOD = 5.0


@runtime_checkable
class ProcessSupervisor(Protocol):
    def start(self, argv: list[str], *, cwd: Path | None = None) -> None: ...

    def stop(self) -> None: ...

    def is_running(self) -> bool: ...


class SubprocessSupervisor:
    """Runs one child process at a time; starting a new one stops the old one."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None

    def start(self, argv: list[str], *, cwd: Path | None = None) -> None:
        self.stop()
        self._proc = subprocess.Popen(argv, cwd=cwd)

    def stop(self) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            self._proc = None
            return
        proc.send_signal(signal.SIGTERM)
        deadline = time.monotonic() + _TERM_GRACE_PERIOD
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            proc.kill()
            proc.wait()
        self._proc = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
