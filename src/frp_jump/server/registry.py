"""CRUD and desired-state views over the control-plane database.

Kept framework-agnostic (plain SQLModel ``Session``, no FastAPI) so it can
be unit-tested directly and reused by both ``server/api.py`` and the
``frp-jump-server`` CLI.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re
import secrets
from dataclasses import dataclass

import sqlalchemy.exc
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.orm import aliased as _aliased
from sqlmodel import Session, select

from frp_jump.common import ssh_signing
from frp_jump.common.crypto import generate_id, generate_token, hash_token
from frp_jump.common.models import (
    Device,
    EnrollChallenge,
    EnrollToken,
    Grant,
    KeyRotationChallenge,
    Service,
    User,
)
from frp_jump.driver.base import ServiceProtocol

# Device and service names end up in places that trust them structurally:
# a device name becomes an x509 CN/SAN (common/pki.py), a service name
# becomes an frp proxy/visitor name AND an ssh_config `Host` alias
# (agent/hosts.py) -- a newline or shell metacharacter there is a path to
# ssh config injection on every consuming device. Keep this strict.
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")

# Same constraint for a user label -- it's just a friendlier alias for a
# fingerprint, never structurally trusted the way a device/service name is,
# but kept to the same safe character set for consistency and so it's
# always safe to embed in a CLI table or shell-completable argument.
_LABEL_RE = _NAME_RE


class NotFoundError(LookupError):
    pass


class ConflictError(ValueError):
    pass


class ValidationError(ValueError):
    pass


def validate_name(name: str, *, what: str) -> None:
    if not _NAME_RE.match(name):
        raise ValidationError(
            f"{what} {name!r} is invalid -- use 1-63 characters, "
            "letters/digits/underscore/hyphen, starting with a letter or digit"
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


# --- users ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserView:
    id: str
    label: str
    fingerprint: str
    device_count: int


def get_user_by_fingerprint(session: Session, fingerprint: str) -> User | None:
    return session.exec(select(User).where(User.ssh_key_fingerprint == fingerprint)).first()


def get_user_by_label(session: Session, label: str) -> User | None:
    return session.exec(select(User).where(User.label == label)).first()


def create_user(session: Session, *, public_key: str, label: str | None = None) -> User:
    """Register a person by their existing SSH public key. ``label`` is a
    human-friendly alias for the admin's own use (e.g. "alice") -- if
    omitted, a short unique one is generated so the record is still
    addressable."""
    try:
        public_key = ssh_signing.canonicalize(public_key)
        fingerprint = ssh_signing.fingerprint(public_key)
    except ssh_signing.SshSigningError as exc:
        raise ValidationError(str(exc)) from exc
    if get_user_by_fingerprint(session, fingerprint) is not None:
        raise ConflictError("this key is already registered to a user")
    if label is not None:
        validate_name(label, what="label")
        if get_user_by_label(session, label) is not None:
            raise ConflictError(f"label {label!r} already in use")
    else:
        label = f"user-{generate_id()[:8]}"
    user = User(label=label, ssh_public_key=public_key, ssh_key_fingerprint=fingerprint)
    session.add(user)
    try:
        session.commit()
    except sqlalchemy.exc.IntegrityError as exc:
        session.rollback()
        raise ConflictError("this key or label is already registered") from exc
    session.refresh(user)
    return user


def set_user_key(session: Session, user_id: str, *, public_key: str) -> User:
    """Rotate a user's key -- the trusted primitive behind both the admin's
    `users set-key` (an operator with shell access, trusted by
    construction) and the self-service `/users/set-key` HTTP endpoint,
    which must NOT call this directly with a caller-supplied key -- see
    ``create_key_rotation_challenge``/``redeem_key_rotation_challenge``,
    which prove possession of the new key first."""
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError(f"no such user {user_id!r}")
    try:
        public_key = ssh_signing.canonicalize(public_key)
        fingerprint = ssh_signing.fingerprint(public_key)
    except ssh_signing.SshSigningError as exc:
        raise ValidationError(str(exc)) from exc
    existing = get_user_by_fingerprint(session, fingerprint)
    if existing is not None and existing.id != user_id:
        raise ConflictError("this key is already registered to another user")
    user.ssh_public_key = public_key
    user.ssh_key_fingerprint = fingerprint
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def create_key_rotation_challenge(
    session: Session, *, device_id: str, public_key: str, ttl: datetime.timedelta
) -> KeyRotationChallenge:
    """Step 1 of self-service key rotation (`/users/set-key/challenge`):
    issue a nonce for the caller to sign with the *candidate new* key's
    private half, proving they actually hold it before
    ``redeem_key_rotation_challenge`` is allowed to switch the whole
    account over to it. Scoped to ``device_id`` -- only that same
    device's own follow-up call may redeem it."""
    try:
        public_key = ssh_signing.canonicalize(public_key)
    except ssh_signing.SshSigningError as exc:
        raise ValidationError(str(exc)) from exc
    # Opportunistic cleanup, same rationale as create_enroll_challenge's --
    # nothing else ever prunes this table.
    session.execute(sa_delete(KeyRotationChallenge).where(KeyRotationChallenge.expires_at < _now()))
    record = KeyRotationChallenge(
        device_id=device_id,
        public_key=public_key,
        challenge=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        expires_at=_now() + ttl,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def redeem_key_rotation_challenge(
    session: Session, challenge_id: str, signature_b64: str, *, device_id: str
) -> User:
    """Step 2: verify the signature over the challenge was made by the
    new key's private half, then actually rotate -- the key-rotation
    counterpart to ``redeem_enroll_challenge``."""
    claimed = session.execute(
        sa_update(KeyRotationChallenge)
        .where(
            KeyRotationChallenge.id == challenge_id,
            KeyRotationChallenge.device_id == device_id,
            KeyRotationChallenge.used_at.is_(None),
            KeyRotationChallenge.expires_at >= _now(),
        )
        .values(used_at=_now())
    )
    if claimed.rowcount == 0:
        session.rollback()
        raise NotFoundError("unknown, used, or expired challenge")
    record = session.get(KeyRotationChallenge, challenge_id)

    try:
        signature = base64.b64decode(signature_b64, validate=True)
        challenge_bytes = base64.b64decode(record.challenge, validate=True)
    except (ValueError, binascii.Error) as exc:
        session.rollback()
        raise ValidationError("malformed signature") from exc
    if not ssh_signing.verify(record.public_key, challenge_bytes, signature):
        session.rollback()
        raise ValidationError("signature verification failed")

    device = session.get(Device, device_id)
    return set_user_key(session, device.owner_user_id, public_key=record.public_key)


def list_users_view(session: Session) -> list[UserView]:
    users = session.exec(select(User)).all()
    devices = session.exec(select(Device)).all()
    counts: dict[str, int] = {}
    for device in devices:
        counts[device.owner_user_id] = counts.get(device.owner_user_id, 0) + 1
    return [
        UserView(
            id=u.id,
            label=u.label,
            fingerprint=u.ssh_key_fingerprint,
            device_count=counts.get(u.id, 0),
        )
        for u in users
    ]


def delete_user(session: Session, user_id: str) -> None:
    """Permanently removes a user: every device they own (see
    ``delete_device``) and every enroll token they created."""
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError(f"no such user {user_id!r}")

    for device in list_devices_for_owner(session, user_id):
        delete_device(session, device.id)
    for token in session.exec(select(EnrollToken).where(EnrollToken.created_by == user_id)):
        session.delete(token)
    session.flush()
    session.delete(user)
    session.commit()


# --- devices / enrollment -------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuedEnrollToken:
    token: str
    device_name_hint: str | None
    expires_at: datetime.datetime


def _check_name_free(session: Session, owner_user_id: str, name: str) -> None:
    validate_name(name, what="device name")
    existing = session.exec(
        select(Device).where(Device.owner_user_id == owner_user_id, Device.name == name)
    ).first()
    if existing is not None:
        raise ConflictError(f"you already have a device named {name!r}")
    pending = session.exec(
        select(EnrollToken).where(
            EnrollToken.created_by == owner_user_id,
            EnrollToken.device_name_hint == name,
            EnrollToken.used_at.is_(None),
            EnrollToken.revoked_at.is_(None),
            EnrollToken.expires_at >= _now(),
        )
    ).first()
    if pending is not None:
        raise ConflictError(f"an unredeemed enroll token for {name!r} already exists")


def create_enroll_token(
    session: Session,
    *,
    created_by: str,
    ttl: datetime.timedelta,
    device_name_hint: str | None = None,
) -> IssuedEnrollToken:
    """``device_name_hint=None`` defers naming to whoever redeems the token
    (``redeem_enroll_token``'s ``requested_name``) -- used when the issuer
    doesn't know what the recipient wants to call their device."""
    if device_name_hint is not None:
        _check_name_free(session, created_by, device_name_hint)
    token = generate_token()
    expires_at = _now() + ttl
    record = EnrollToken(
        token_hash=hash_token(token),
        device_name_hint=device_name_hint,
        created_by=created_by,
        expires_at=expires_at,
    )
    session.add(record)
    session.commit()
    return IssuedEnrollToken(token=token, device_name_hint=device_name_hint, expires_at=expires_at)


@dataclass(frozen=True, slots=True)
class EnrolledDevice:
    device: Device
    api_token: str


def _find_valid_enroll_token(session: Session, token: str) -> EnrollToken:
    record = session.exec(
        select(EnrollToken).where(EnrollToken.token_hash == hash_token(token))
    ).first()
    if record is None:
        raise NotFoundError("unknown or already-used enroll token")
    if record.used_at is not None:
        raise NotFoundError("enroll token already used")
    if record.revoked_at is not None:
        raise NotFoundError("enroll token revoked")
    if record.expires_at < _now():
        raise NotFoundError("enroll token expired")
    return record


def peek_enroll_token(session: Session, token: str) -> EnrollToken:
    """Validate a one-time enroll token without consuming it.

    Lets the caller learn ``device_name_hint`` (needed to issue the
    device's cert with a matching CN) before actually redeeming the token.
    """
    return _find_valid_enroll_token(session, token)


def _build_device_for_owner(
    session: Session,
    *,
    owner_user_id: str,
    cert_serial: str,
    agent_version: str | None,
    requested_name: str | None,
    device_name_hint: str | None = None,
) -> tuple[Device, str]:
    """Shared tail of both enrollment paths: pick/validate the device's
    name and stage (but do not commit) its row -- the caller commits
    together with marking its own token/challenge used, so both changes
    land atomically."""
    if device_name_hint is not None:
        name = device_name_hint
    else:
        if not requested_name:
            raise ValidationError("a device name is required (--name)")
        _check_name_free(session, owner_user_id, requested_name)
        name = requested_name
    api_token = generate_token()
    device = Device(
        name=name,
        owner_user_id=owner_user_id,
        cert_serial=cert_serial,
        api_token_hash=hash_token(api_token),
        agent_version=agent_version,
    )
    session.add(device)
    return device, api_token


def redeem_enroll_token(
    session: Session,
    token: str,
    *,
    cert_serial: str,
    agent_version: str | None = None,
    requested_name: str | None = None,
) -> EnrolledDevice:
    """Consume a one-time enroll token, creating the Device row it names.

    ``requested_name`` is required if (and only if) the token was issued
    without a fixed ``device_name_hint`` -- it's then validated/checked for
    uniqueness right here, at redemption time, same as at issuance.
    """
    record = _find_valid_enroll_token(session, token)
    device, api_token = _build_device_for_owner(
        session,
        owner_user_id=record.created_by,
        cert_serial=cert_serial,
        agent_version=agent_version,
        requested_name=requested_name,
        device_name_hint=record.device_name_hint,
    )
    # An atomic conditional UPDATE, not a plain attribute write: two
    # concurrent redemptions of the same token both pass
    # `_find_valid_enroll_token`'s plain SELECT before either commits, so a
    # read-then-write here would let both create a device (verified with a
    # PoC during review). `rowcount == 0` means someone else's redemption
    # already won the race between our read and now.
    try:
        # The UPDATE below autoflushes the pending device INSERT first --
        # a duplicate name surfaces here as an IntegrityError, not only at
        # the final commit, so both must go through the same handler.
        claimed = session.execute(
            sa_update(EnrollToken)
            .where(EnrollToken.id == record.id, EnrollToken.used_at.is_(None))
            .values(used_at=_now())
        )
        if claimed.rowcount == 0:
            session.rollback()
            raise NotFoundError("enroll token already used")
        session.commit()
    except sqlalchemy.exc.IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"device name {device.name!r} already in use") from exc
    session.refresh(device)
    return EnrolledDevice(device=device, api_token=api_token)


def revoke_enroll_token(session: Session, token_id: str) -> None:
    """Invalidate an unredeemed enroll token before anyone uses it -- e.g.
    it was sent to the wrong person, or leaked."""
    record = session.get(EnrollToken, token_id)
    if record is None:
        raise NotFoundError(f"no such enroll token {token_id!r}")
    if record.used_at is not None:
        raise ConflictError("already redeemed -- delete the resulting device instead")
    record.revoked_at = _now()
    session.add(record)
    session.commit()


@dataclass(frozen=True, slots=True)
class PendingEnrollTokenView:
    id: str
    device_name_hint: str | None
    owner_label: str
    created_at: datetime.datetime
    expires_at: datetime.datetime


def list_pending_enroll_tokens(session: Session) -> list[PendingEnrollTokenView]:
    """Unredeemed, unexpired, unrevoked tokens -- for `enroll-tokens list`."""
    rows = session.exec(
        select(EnrollToken, User)
        .join(User, EnrollToken.created_by == User.id)
        .where(
            EnrollToken.used_at.is_(None),
            EnrollToken.revoked_at.is_(None),
            EnrollToken.expires_at >= _now(),
        )
    ).all()
    return [
        PendingEnrollTokenView(
            id=token.id,
            device_name_hint=token.device_name_hint,
            owner_label=user.label,
            created_at=token.created_at,
            expires_at=token.expires_at,
        )
        for token, user in rows
    ]


# This endpoint is deliberately reachable by anyone with *any* public key
# text, unauthenticated -- proving possession of a registered key is the
# whole point of the flow, so there is no login to gate it behind. Cap
# how many still-pending challenges one fingerprint can accumulate, so
# repeatedly hitting it isn't a free way to grow this table without bound.
_MAX_PENDING_ENROLL_CHALLENGES_PER_FINGERPRINT = 5


def create_enroll_challenge(
    session: Session, *, fingerprint: str, ttl: datetime.timedelta
) -> EnrollChallenge:
    """Issue a one-time nonce to sign over, tied to ``fingerprint`` --
    *regardless* of whether that fingerprint is actually registered to a
    user. Whether it is stays hidden until redemption
    (``redeem_enroll_challenge``), where an unknown fingerprint fails
    exactly like a bad signature -- otherwise this endpoint's mere
    200-vs-404 split would itself be an oracle for which keys the server
    knows about, no matter how the error text reads (this used to raise
    ``NotFoundError`` here for that reason; it was still an oracle)."""
    now = _now()
    # Opportunistic cleanup: nothing else ever prunes this table, since
    # nothing authenticates the caller here.
    session.execute(sa_delete(EnrollChallenge).where(EnrollChallenge.expires_at < now))
    pending = session.exec(
        select(EnrollChallenge)
        .where(EnrollChallenge.fingerprint == fingerprint, EnrollChallenge.used_at.is_(None))
        .order_by(EnrollChallenge.created_at)
    ).all()
    if len(pending) >= _MAX_PENDING_ENROLL_CHALLENGES_PER_FINGERPRINT:
        for stale in pending[: len(pending) - _MAX_PENDING_ENROLL_CHALLENGES_PER_FINGERPRINT + 1]:
            session.delete(stale)
    record = EnrollChallenge(
        fingerprint=fingerprint,
        challenge=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        expires_at=now + ttl,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


def _verify_enroll_challenge(
    session: Session, challenge_id: str, signature_b64: str
) -> tuple[EnrollChallenge, User]:
    record = session.get(EnrollChallenge, challenge_id)
    if record is None or record.used_at is not None or record.expires_at < _now():
        raise NotFoundError("unknown, used, or expired challenge")
    # A missing user (the fingerprint was deleted after the challenge was
    # issued -- rare, but possible) fails the exact same way as a bad
    # signature: `create_enroll_challenge` already tries not to hand out a
    # challenge for an unregistered key, but if this branch used a
    # distinctly-worded error, redemption itself would become the oracle
    # that step was meant to avoid.
    user = get_user_by_fingerprint(session, record.fingerprint)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        challenge_bytes = base64.b64decode(record.challenge, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("signature verification failed") from exc
    if user is None or not ssh_signing.verify(user.ssh_public_key, challenge_bytes, signature):
        raise ValidationError("signature verification failed")
    return record, user


def peek_enroll_challenge(session: Session, challenge_id: str, signature_b64: str) -> User:
    """Validate a signed enroll challenge without consuming it -- lets the
    caller learn which user it belongs to (to validate a requested device
    name) before asking the CA to issue anything. See ``peek_enroll_token``."""
    _, user = _verify_enroll_challenge(session, challenge_id, signature_b64)
    return user


def redeem_enroll_challenge(
    session: Session,
    challenge_id: str,
    signature_b64: str,
    *,
    cert_serial: str,
    agent_version: str | None = None,
    requested_name: str | None = None,
) -> EnrolledDevice:
    """Verify a signed enroll challenge and create the device it names --
    the key-based counterpart to ``redeem_enroll_token``."""
    record, user = _verify_enroll_challenge(session, challenge_id, signature_b64)
    device, api_token = _build_device_for_owner(
        session,
        owner_user_id=user.id,
        cert_serial=cert_serial,
        agent_version=agent_version,
        requested_name=requested_name,
    )
    try:
        # Atomic conditional UPDATE, same rationale as redeem_enroll_token's
        # -- and the same reason its autoflush must share this handler.
        claimed = session.execute(
            sa_update(EnrollChallenge)
            .where(EnrollChallenge.id == record.id, EnrollChallenge.used_at.is_(None))
            .values(used_at=_now())
        )
        if claimed.rowcount == 0:
            session.rollback()
            raise NotFoundError("challenge already used")
        session.commit()
    except sqlalchemy.exc.IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"device name {device.name!r} already in use") from exc
    session.refresh(device)
    return EnrolledDevice(device=device, api_token=api_token)


def get_device_by_api_token(session: Session, api_token: str) -> Device | None:
    """None only for an unknown token -- a *disabled* device still
    authenticates, so its agent keeps polling and can pick up being
    re-enabled (see ``Device.enabled`` / module docstring in
    common/models.py). Only a deleted device stops authenticating."""
    token_hash = hash_token(api_token)
    return session.exec(select(Device).where(Device.api_token_hash == token_hash)).first()


def get_device(session: Session, device_id: str) -> Device | None:
    return session.get(Device, device_id)


def list_devices(session: Session) -> list[Device]:
    return list(session.exec(select(Device)))


def list_devices_for_owner(session: Session, owner_user_id: str) -> list[Device]:
    """Self-service `client devices list` -- every device owned by the
    same person as the calling device."""
    return list(session.exec(select(Device).where(Device.owner_user_id == owner_user_id)))


def get_device_by_name(session: Session, owner_user_id: str, name: str) -> Device | None:
    """Names are unique only per-owner -- always scope the lookup."""
    return session.exec(
        select(Device).where(Device.owner_user_id == owner_user_id, Device.name == name)
    ).first()


def disable_device(session: Session, device_id: str) -> None:
    """Tear down and forbid new connections for this device, without
    losing its identity/enrollment -- reversible via ``enable_device``.
    The device's agent keeps authenticating and polling; its desired
    state (both what it exposes and what it consumes) just goes empty
    until re-enabled."""
    device = session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"no such device {device_id!r}")
    device.enabled = False
    session.add(device)
    session.commit()


def enable_device(session: Session, device_id: str) -> None:
    device = session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"no such device {device_id!r}")
    device.enabled = True
    session.add(device)
    session.commit()


def delete_device(session: Session, device_id: str) -> None:
    """Permanently remove a device (and its services/grants), freeing its
    name for reuse -- e.g. the device was wiped/replaced and you want to
    re-enroll a new one under the same name. Not reversible."""
    device = session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"no such device {device_id!r}")

    # No SQLModel `Relationship()`s are declared between these tables (kept
    # deliberately flat/simple), so SQLAlchemy's unit-of-work has no FK
    # graph to auto-order these deletes by -- without explicit flushes
    # between stages it can (and did, see the test that caught this) try to
    # delete a row before what still references it, and SQLite's now-
    # enforced FOREIGN KEY constraint (server/db.py) rejects that.
    #
    # KeyRotationChallenge.device_id is one such FK -- any device that
    # ever called `set-key` (successfully or not; redemption only marks
    # used_at, it never deletes) would otherwise leave a dangling
    # reference and turn this into an IntegrityError instead of a delete.
    session.execute(
        sa_delete(KeyRotationChallenge).where(KeyRotationChallenge.device_id == device_id)
    )
    owned_service_ids = [
        s.id for s in session.exec(select(Service).where(Service.device_id == device_id))
    ]
    if owned_service_ids:
        for grant in session.exec(select(Grant).where(Grant.service_id.in_(owned_service_ids))):
            session.delete(grant)
    for grant in session.exec(select(Grant).where(Grant.consumer_device_id == device_id)):
        session.delete(grant)
    session.flush()

    for service in session.exec(select(Service).where(Service.device_id == device_id)):
        session.delete(service)
    session.flush()

    session.delete(device)
    session.commit()


def record_heartbeat(session: Session, device: Device, *, agent_version: str | None = None) -> None:
    device.last_seen_at = _now()
    if agent_version is not None:
        device.agent_version = agent_version
    session.add(device)
    session.commit()


# --- services / grants ---------------------------------------------------


def create_service(
    session: Session, *, device_id: str, name: str, protocol: ServiceProtocol, target_port: int
) -> Service:
    validate_name(name, what="service name")
    if session.get(Device, device_id) is None:
        raise NotFoundError(f"no such device {device_id!r}")
    if session.exec(select(Service).where(Service.name == name)).first() is not None:
        raise ConflictError(f"service name {name!r} already in use")
    service = Service(device_id=device_id, name=name, protocol=protocol, target_port=target_port)
    session.add(service)
    session.commit()
    session.refresh(service)
    return service


def list_services_for_device(session: Session, device_id: str) -> list[Service]:
    return list(session.exec(select(Service).where(Service.device_id == device_id)))


def find_or_create_service(
    session: Session, *, device_id: str, target_port: int, protocol: ServiceProtocol
) -> Service:
    """Self-service `client connect`: reuse the service for (device,
    port) if one already exists (e.g. a different device already connected
    to it first), otherwise create one with a private, auto-generated name
    -- `svc-<device_id>-<port>` -- that's an internal implementation detail,
    never shown to or typed by a user (they use local profile names
    instead, see agent/state.py).

    Raises ``ValidationError`` for a port outside 1-65535 (the API layer
    also validates this, but the registry must not trust callers to have
    done so), and ``ConflictError`` if the port is already exposed with a
    different protocol, or if `svc-<device_id>-<port>` collides with a
    manually-named ``Service`` an admin created directly (rare, but the
    name is not reserved from that path)."""
    if not (1 <= target_port <= 65535):
        raise ValidationError(f"target_port {target_port} is out of range (1-65535)")
    existing = session.exec(
        select(Service).where(Service.device_id == device_id, Service.target_port == target_port)
    ).first()
    if existing is not None:
        if existing.protocol != protocol:
            raise ConflictError(
                f"port {target_port} on this device is already exposed as "
                f"{existing.protocol.value}, not {protocol.value}"
            )
        return existing
    service = Service(
        device_id=device_id,
        name=f"svc-{device_id}-{target_port}",
        protocol=protocol,
        target_port=target_port,
    )
    session.add(service)
    try:
        session.commit()
    except sqlalchemy.exc.IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"could not create a service for port {target_port}") from exc
    session.refresh(service)
    return service


def create_grant(session: Session, *, service_id: str, consumer_device_id: str) -> Grant:
    """No ownership check here by design -- this registry module trusts
    its callers, same as the rest of it (see the module docstring). The
    only caller today is an admin action (there is no self-service
    equivalent; self-service goes through ``find_or_create_grant`` via
    `client connect`, which api.py scopes to the caller's own owner
    first). A cross-owner grant an admin creates directly is not a
    security issue -- both owners already trust the admin -- but note
    that ``ConsumedGrantView.exposer_device_name`` becomes the consumer's
    ssh_config alias, so a name collision across two different owners'
    devices is possible in that admin-only path."""
    if session.get(Service, service_id) is None:
        raise NotFoundError(f"no such service {service_id!r}")
    if session.get(Device, consumer_device_id) is None:
        raise NotFoundError(f"no such device {consumer_device_id!r}")
    existing = session.exec(
        select(Grant).where(
            Grant.service_id == service_id, Grant.consumer_device_id == consumer_device_id
        )
    ).first()
    if existing is not None:
        raise ConflictError("this device already has a grant for this service")
    grant = Grant(
        service_id=service_id, consumer_device_id=consumer_device_id, secret=generate_token()
    )
    session.add(grant)
    session.commit()
    session.refresh(grant)
    return grant


def list_grants_for_service(session: Session, service_id: str) -> list[Grant]:
    return list(session.exec(select(Grant).where(Grant.service_id == service_id)))


def find_or_create_grant(session: Session, *, service_id: str, consumer_device_id: str) -> Grant:
    """Self-service `client connect`: idempotent ``create_grant`` -- reuses
    an existing grant for this (service, consumer) pair instead of raising
    ``ConflictError``, so re-running `connect` is always safe."""
    existing = session.exec(
        select(Grant).where(
            Grant.service_id == service_id, Grant.consumer_device_id == consumer_device_id
        )
    ).first()
    if existing is not None:
        return existing
    grant = Grant(
        service_id=service_id, consumer_device_id=consumer_device_id, secret=generate_token()
    )
    session.add(grant)
    session.commit()
    session.refresh(grant)
    return grant


def find_grant_for_connection(
    session: Session, *, device_id: str, target_port: int, consumer_device_id: str
) -> Grant | None:
    """`client disconnect`: find the grant matching (target device, port,
    consumer) without the caller needing to know internal service/grant
    ids. ``consumer_device_id`` may be any device -- not necessarily the
    caller's own -- which is what lets self-service disconnect tear down a
    forgotten connection from one of the user's *other* devices (see
    `--from` in `client_cmds.disconnect`)."""
    service = session.exec(
        select(Service).where(Service.device_id == device_id, Service.target_port == target_port)
    ).first()
    if service is None:
        return None
    return session.exec(
        select(Grant).where(
            Grant.service_id == service.id, Grant.consumer_device_id == consumer_device_id
        )
    ).first()


def delete_grant(session: Session, grant_id: str) -> None:
    """`client disconnect`: permanently drops the wiring -- not just revoke;
    reconnecting is a trivial `connect` away, no reason to keep a dead row
    (unlike a device, a grant has no other identity worth preserving)."""
    grant = session.get(Grant, grant_id)
    if grant is None:
        raise NotFoundError(f"no such grant {grant_id!r}")
    session.delete(grant)
    session.commit()


# --- admin views (for `frp-jump-server`/self-service listing commands) ----


@dataclass(frozen=True, slots=True)
class DeviceView:
    id: str
    name: str
    owner_label: str
    enrolled_at: datetime.datetime
    last_seen_at: datetime.datetime | None
    agent_version: str | None
    enabled: bool


def list_devices_view(session: Session) -> list[DeviceView]:
    rows = session.exec(select(Device, User).join(User, Device.owner_user_id == User.id)).all()
    return [
        DeviceView(
            id=d.id,
            name=d.name,
            owner_label=u.label,
            enrolled_at=d.enrolled_at,
            last_seen_at=d.last_seen_at,
            agent_version=d.agent_version,
            enabled=d.enabled,
        )
        for d, u in rows
    ]


@dataclass(frozen=True, slots=True)
class ServiceView:
    id: str
    name: str
    protocol: ServiceProtocol
    target_port: int
    device_id: str
    device_name: str


@dataclass(frozen=True, slots=True)
class GrantView:
    id: str
    service_id: str
    service_name: str
    exposer_device_name: str
    consumer_device_id: str
    consumer_device_name: str


def list_services_view(session: Session) -> list[ServiceView]:
    rows = session.exec(select(Service, Device).join(Device, Service.device_id == Device.id)).all()
    return [
        ServiceView(
            id=service.id,
            name=service.name,
            protocol=service.protocol,
            target_port=service.target_port,
            device_id=device.id,
            device_name=device.name,
        )
        for service, device in rows
    ]


def list_grants_view(session: Session) -> list[GrantView]:
    rows = session.exec(
        select(Grant, Service, Device)
        .join(Service, Grant.service_id == Service.id)
        .join(Device, Service.device_id == Device.id)
    ).all()
    consumer_names = {d.id: d.name for d in session.exec(select(Device))}
    return [
        GrantView(
            id=grant.id,
            service_id=service.id,
            service_name=service.name,
            exposer_device_name=exposer_device.name,
            consumer_device_id=grant.consumer_device_id,
            consumer_device_name=consumer_names.get(grant.consumer_device_id, "?"),
        )
        for grant, service, exposer_device in rows
    ]


# --- desired-state views (what an agent should be doing) -----------------


@dataclass(frozen=True, slots=True)
class ExposedGrantView:
    grant_id: str
    secret: str
    service_name: str
    target_port: int


@dataclass(frozen=True, slots=True)
class ConsumedGrantView:
    grant_id: str
    secret: str
    service_name: str
    protocol: ServiceProtocol
    exposer_device_name: str
    target_port: int


def exposed_grants_for_device(session: Session, device_id: str) -> list[ExposedGrantView]:
    """Grants for services this device exposes. Excludes grants held by a
    disabled consumer device (see ``Device.enabled`` note in
    common/models.py) -- the caller is also responsible for returning none
    of these at all when the exposing device itself is disabled."""
    consumer = _aliased(Device)
    rows = session.exec(
        select(Grant, Service)
        .join(Service, Grant.service_id == Service.id)
        .join(consumer, Grant.consumer_device_id == consumer.id)
        .where(Service.device_id == device_id, consumer.enabled.is_(True))
    ).all()
    return [
        ExposedGrantView(
            grant_id=grant.id,
            secret=grant.secret,
            service_name=service.name,
            target_port=service.target_port,
        )
        for grant, service in rows
    ]


def consumed_grants_for_device(session: Session, device_id: str) -> list[ConsumedGrantView]:
    """Grants this device may consume. Excludes grants exposed by a
    disabled device (see ``Device.enabled`` note in common/models.py) --
    the caller is also responsible for returning none of these at all when
    the consuming device itself is disabled."""
    rows = session.exec(
        select(Grant, Service, Device)
        .join(Service, Grant.service_id == Service.id)
        .join(Device, Service.device_id == Device.id)
        .where(Grant.consumer_device_id == device_id, Device.enabled.is_(True))
    ).all()
    return [
        ConsumedGrantView(
            grant_id=grant.id,
            secret=grant.secret,
            service_name=service.name,
            protocol=service.protocol,
            exposer_device_name=exposer.name,
            target_port=service.target_port,
        )
        for grant, service, exposer in rows
    ]
