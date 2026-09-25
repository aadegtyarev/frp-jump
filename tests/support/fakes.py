"""In-memory TunnelDriver/RelayDriver doubles, shared by tests across phases.

Real network/process behavior lives in ``driver.frp``; everything that only
needs to know "did apply() get called with the right desired state" should
depend on these instead of spinning up real frp binaries.
"""

from __future__ import annotations

from frp_jump.driver.base import DesiredState, DriverStatus, RelayState


class FakeDriver:
    """Records every ``apply`` call; reports a canned status."""

    def __init__(self) -> None:
        self.applied: list[DesiredState] = []
        self.stopped = False
        self.next_status = DriverStatus(running=False)

    def apply(self, desired: DesiredState) -> None:
        self.applied.append(desired)

    def status(self) -> DriverStatus:
        return self.next_status

    def stop(self) -> None:
        self.stopped = True

    @property
    def last_applied(self) -> DesiredState | None:
        return self.applied[-1] if self.applied else None


class FakeRelayDriver:
    """Records every ``apply`` call; reports a canned status."""

    def __init__(self) -> None:
        self.applied: list[RelayState] = []
        self.stopped = False
        self.next_status = DriverStatus(running=False)

    def apply(self, desired: RelayState) -> None:
        self.applied.append(desired)

    def status(self) -> DriverStatus:
        return self.next_status

    def stop(self) -> None:
        self.stopped = True

    @property
    def last_applied(self) -> RelayState | None:
        return self.applied[-1] if self.applied else None
