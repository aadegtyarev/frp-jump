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
- A human is identified by an SSH keypair (``User.ssh_public_key`` /
  ``ssh_key_fingerprint``), enrolled once by an admin running
  ``frp-jump-server users add-key`` over SSH to the server box -- SSH
  access to that box *is* the admin authorization boundary, there is no
  separate web login. A device then self-enrolls by proving possession of
  the matching private key (``EnrollChallenge`` + ``common/ssh_signing.py``),
  or via a one-time ``EnrollToken`` when handing over a personal key isn't
  wanted for a given device.

Device/grant lifecycle is enforced at the control-plane only: a disabled
device (``Device.enabled = False``) still authenticates to the API
(``registry.get_device_by_api_token`` deliberately keeps accepting it, so
its agent keeps polling and can notice being re-enabled), but drops out
of both sides' desired-state on the next poll -- so the agent tears down
its running frpc config -- and every *mutating* self-service route
(connect, add/delete/enable/disable a device, rotate the owner's key)
rejects its token outright (``server/api.py``'s ``get_enabled_device``),
so a disabled device's still-valid token can't be used to re-enable
itself or otherwise act on the owner's account. Re-enabling it (from
another of the owner's still-enabled devices, or the admin CLI) lets it
reconnect. Deleting a device or grant is the only irreversible operation.
None of this is enforced by frps/mTLS directly -- a device whose frpc is
already connected keeps that connection (and whatever it was last
configured to relay) until it
reconnects or the relay restarts. Hard revocation means rotating the CA.
See docs/architecture.md.
"""

from __future__ import annotations

import datetime

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel

from frp_jump.common.crypto import generate_id
from frp_jump.driver.base import ServiceProtocol

__all__ = [
    "Device",
    "EnrollChallenge",
    "EnrollToken",
    "Grant",
    "KeyRotationChallenge",
    "Service",
    "User",
]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default_factory=generate_id, primary_key=True)
    label: str = Field(unique=True, index=True)
    ssh_public_key: str
    ssh_key_fingerprint: str = Field(unique=True, index=True)
    created_at: datetime.datetime = Field(default_factory=_now)


class EnrollChallenge(SQLModel, table=True):
    """A short-lived nonce issued to prove possession of a registered
    ``User.ssh_public_key`` before a device may enroll by key -- see
    ``common/ssh_signing.py`` and ``registry.create_enroll_challenge`` /
    ``redeem_enroll_challenge``."""

    __tablename__ = "enroll_challenges"

    id: str = Field(default_factory=generate_id, primary_key=True)
    fingerprint: str = Field(index=True)
    challenge: str
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    used_at: datetime.datetime | None = None


class KeyRotationChallenge(SQLModel, table=True):
    """A short-lived nonce a device must sign with a *candidate new* key's
    private half before ``/users/set-key`` will rotate the owner's key to
    it -- proof of possession, so a leaked/guessed bearer token alone
    can't hijack the account by pointing it at a key the caller doesn't
    actually hold. Scoped to the requesting device (``device_id``): only
    that same device's own follow-up call may redeem it."""

    __tablename__ = "key_rotation_challenges"

    id: str = Field(default_factory=generate_id, primary_key=True)
    device_id: str = Field(foreign_key="devices.id", index=True)
    public_key: str
    challenge: str
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    used_at: datetime.datetime | None = None


class Device(SQLModel, table=True):
    __tablename__ = "devices"
    # Names are only unique per-owner, not globally -- two different
    # people may each have a device named "laptop".
    __table_args__ = (UniqueConstraint("owner_user_id", "name", name="uq_devices_owner_name"),)

    id: str = Field(default_factory=generate_id, primary_key=True)
    name: str = Field(index=True)
    owner_user_id: str = Field(foreign_key="users.id", index=True)
    cert_serial: str  # str: x509 serials can exceed SQLite's 64-bit INTEGER range
    api_token_hash: str = Field(unique=True, index=True)
    enrolled_at: datetime.datetime = Field(default_factory=_now)
    last_seen_at: datetime.datetime | None = None
    agent_version: str | None = None
    enabled: bool = True


class EnrollToken(SQLModel, table=True):
    __tablename__ = "enroll_tokens"

    id: str = Field(default_factory=generate_id, primary_key=True)
    token_hash: str = Field(index=True, unique=True)
    # None means the issuer didn't fix a name -- whoever redeems it supplies
    # one at `client enroll --name` time instead (the self-service
    # `add-device <name>` path always fixes it up front, since the caller
    # already knows the name; the admin-issued "for a friend" path may not).
    device_name_hint: str | None = None
    created_by: str = Field(foreign_key="users.id")
    created_at: datetime.datetime = Field(default_factory=_now)
    expires_at: datetime.datetime
    used_at: datetime.datetime | None = None
    revoked_at: datetime.datetime | None = None


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
