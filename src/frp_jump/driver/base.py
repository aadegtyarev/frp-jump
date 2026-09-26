"""Abstraction over the tunneling engine.

The rest of the codebase (agent poller, server bootstrap) talks only to
these Protocols, never to frp directly. Today the only implementation is
``driver.frp.FrpDriver`` / ``driver.frp.FrpsRelayDriver``, but nothing
outside ``driver/`` should assume that.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class ServiceProtocol(StrEnum):
    """The only functional difference between these is whether the
    consuming agent writes an ``ssh_config`` ``Host`` entry for it (see
    ``agent/poller.py``'s ``sync_ssh_config``) -- frp proxies the
    underlying bytes identically either way, regardless of what's
    actually running on the port (HTTP, MQTT, or anything else). A
    finer-grained label would be purely cosmetic, so there isn't one."""

    SSH = "ssh"
    TCP = "tcp"


class ProxyState(StrEnum):
    UNKNOWN = "unknown"
    P2P = "p2p"
    RELAY = "relay"
    DOWN = "down"


@dataclass(frozen=True, slots=True)
class ExposedService:
    """A service this device offers to one grantee, identified by grant id."""

    grant_id: str
    secret: str
    local_port: int


@dataclass(frozen=True, slots=True)
class ConsumedGrant:
    """A service this device is allowed to reach, and where to bind it locally."""

    grant_id: str
    secret: str
    local_bind_port: int


@dataclass(frozen=True, slots=True)
class DesiredState:
    """What a single device's tunnel client should be doing right now."""

    device_id: str
    server_addr: str
    server_port: int
    ca_cert_pem: bytes
    cert_pem: bytes
    key_pem: bytes
    exposed: tuple[ExposedService, ...] = ()
    consumed: tuple[ConsumedGrant, ...] = ()


@dataclass(frozen=True, slots=True)
class RelayState:
    """What the server-side relay should be doing right now."""

    bind_port: int
    ca_cert_pem: bytes
    cert_pem: bytes
    key_pem: bytes


@dataclass(frozen=True, slots=True)
class GrantStatus:
    grant_id: str
    state: ProxyState


@dataclass(frozen=True, slots=True)
class DriverStatus:
    running: bool
    grants: tuple[GrantStatus, ...] = ()


@runtime_checkable
class TunnelDriver(Protocol):
    """Device-side driver: exposes and/or consumes grants through the relay."""

    def apply(self, desired: DesiredState) -> None:
        """Converge the running tunnel client to match ``desired``."""
        ...

    def status(self) -> DriverStatus:
        """Report connectivity, and p2p/relay/down per grant."""
        ...

    def stop(self) -> None:
        """Tear down any running tunnel client process."""
        ...


@runtime_checkable
class RelayDriver(Protocol):
    """Server-side driver: runs the relay every device's tunnel client connects to."""

    def apply(self, desired: RelayState) -> None:
        """Converge the running relay process to match ``desired``."""
        ...

    def status(self) -> DriverStatus:
        """Report whether the relay is up."""
        ...

    def stop(self) -> None:
        """Tear down the relay process."""
        ...
