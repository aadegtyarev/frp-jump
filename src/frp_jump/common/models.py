"""Server-side database tables.

Auth boundaries in this system:

- frps <-> frpc traffic is authenticated by the private CA in ``pki.py``
  (mTLS) -- this is what actually carries tunneled data, so it gets the
  strongest mechanism.
- The control-plane API (this module's tables) is metadata only: enroll,
  heartbeat, "what should I be doing". A device authenticates to it with a
  per-device bearer token minted at enroll time (``Device.api_token_hash``),
  same hashed-at-rest pattern as everything else here. Simpler than running
  a second mTLS listener, and the actual traffic-carrying boundary doesn't
  depend on it.
- The WebUI is a human, authenticated by ``Session``, obtained by visiting
  a ``LoginToken`` link the admin generated and hand-delivered.

Revocation (``Device.revoked_at`` / ``Grant.revoked_at``) is enforced at
the control-plane only: a revoked device stops authenticating to the API
(``registry.get_device_by_api_token``), and a revoked grant drops out of
both sides' desired-state on their next poll, so the agent removes it from
its running frpc config. It is NOT enforced by frps/mTLS directly -- a
device whose frpc is already connected keeps that connection (and
whatever it was last configured to relay) until it reconnects or the
relay restarts. Hard revocation means rotating the CA. See
docs/architecture.md.
"""

from __future__ import annotations

import datetime
from enum import StrEnum

from sqlmodel import Field, SQLModel

from frp_jump.common.crypto import generate_id
from frp_jump.driver.base import ServiceProtocol

__all__ = [
    "Device",
    "EnrollToken",
    "Grant",
    "LoginToken",
    "Service",
    "Session",
    "TokenPurpose",
    "User",
]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class TokenPurpose(StrEnum):
    LOGIN = "login"
    INVITE = "invite"


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default_factory=generate_id, primary_key=True)
    email: str = Field(unique=True, index=True)
    is_admin: bool = False
    created_at: datetime.datetime = Field(default_factory=_now)


class Session(SQLModel, table=True):
    __tablename__ = "sessions"

    id: str = Field(default_factory=generate_id, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    user_id: str = Field(foreign_key="users.id", index=True)
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    revoked_at: datetime.datetime | None = None


class LoginToken(SQLModel, table=True):
    __tablename__ = "login_tokens"

    id: str = Field(default_factory=generate_id, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    email: str
    purpose: TokenPurpose
    created_by: str | None = Field(default=None, foreign_key="users.id")
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    used_at: datetime.datetime | None = None
    revoked_at: datetime.datetime | None = None


class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: str = Field(default_factory=generate_id, primary_key=True)
    name: str = Field(unique=True, index=True)
    owner_user_id: str = Field(foreign_key="users.id", index=True)
    cert_serial: str  # str: x509 serials can exceed SQLite's 64-bit INTEGER range
    api_token_hash: str = Field(unique=True, index=True)
    enrolled_at: datetime.datetime = Field(default_factory=_now)
    last_seen_at: datetime.datetime | None = None
    agent_version: str | None = None
    revoked_at: datetime.datetime | None = None


class EnrollToken(SQLModel, table=True):
    __tablename__ = "enroll_tokens"

    id: str = Field(default_factory=generate_id, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    device_name_hint: str
    created_by: str = Field(foreign_key="users.id")
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    used_at: datetime.datetime | None = None


class Service(SQLModel, table=True):
    __tablename__ = "services"

    id: str = Field(default_factory=generate_id, primary_key=True)
    device_id: str = Field(foreign_key="devices.id", index=True)
    name: str = Field(unique=True, index=True)
    protocol: ServiceProtocol
    target_port: int
    created_at: datetime.datetime = Field(default_factory=_now)


class Grant(SQLModel, table=True):
    __tablename__ = "grants"

    id: str = Field(default_factory=generate_id, primary_key=True)
    service_id: str = Field(foreign_key="services.id", index=True)
    consumer_device_id: str = Field(foreign_key="devices.id", index=True)
    secret: str
    created_at: datetime.datetime = Field(default_factory=_now)
    revoked_at: datetime.datetime | None = None
