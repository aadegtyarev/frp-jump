"""CRUD and desired-state views over the control-plane database.

Kept framework-agnostic (plain SQLModel ``Session``, no FastAPI) so it can
be unit-tested directly and reused by both the API and the WebUI.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

import sqlalchemy.exc
from sqlalchemy.orm import aliased as _aliased
from sqlmodel import Session, select

from frp_jump.common.crypto import generate_token, hash_token
from frp_jump.common.models import Device, EnrollToken, Grant, LoginToken, Service, User
from frp_jump.common.models import Session as SessionRow
from frp_jump.driver.base import ServiceProtocol

# Device and service names end up in places that trust them structurally:
# a device name becomes an x509 CN/SAN (common/pki.py), a service name
# becomes an frp proxy/visitor name AND an ssh_config `Host` alias
# (agent/hosts.py) -- a newline or shell metacharacter there is a path to
# ssh config injection on every consuming device. Keep this strict.
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


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


# --- users -------------------------------------------------------------


def get_or_create_user(session: Session, email: str, *, is_admin: bool = False) -> User:
    user = session.exec(select(User).where(User.email == email)).first()
    if user is not None:
        return user
    user = User(email=email, is_admin=is_admin)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@dataclass(frozen=True, slots=True)
class UserView:
    id: str
    email: str
    is_admin: bool
    device_count: int


def list_users_view(session: Session) -> list[UserView]:
    users = session.exec(select(User)).all()
    devices = session.exec(select(Device)).all()
    counts: dict[str, int] = {}
    for device in devices:
        counts[device.owner_user_id] = counts.get(device.owner_user_id, 0) + 1
    return [
        UserView(id=u.id, email=u.email, is_admin=u.is_admin, device_count=counts.get(u.id, 0))
        for u in users
    ]


def delete_user(session: Session, user_id: str) -> None:
    """Permanently removes a user: every device they own (see
    ``delete_device``), every enroll/login token they created or that would
    redeem to their email (an unredeemed login link left behind would
    silently recreate the account), and every WebUI session of theirs.
    Refuses to delete the only remaining admin, so you can't lock yourself
    out."""
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError(f"no such user {user_id!r}")
    if user.is_admin:
        admin_count = len(session.exec(select(User).where(User.is_admin == True)).all())  # noqa: E712
        if admin_count <= 1:
            raise ConflictError("cannot delete the only remaining admin")

    for device in list_devices_for_owner(session, user_id):
        delete_device(session, device.id)
    for token in session.exec(select(EnrollToken).where(EnrollToken.created_by == user_id)):
        session.delete(token)
    for login_token in session.exec(
        select(LoginToken).where(
            (LoginToken.created_by == user_id) | (LoginToken.email == user.email)
        )
    ):
        session.delete(login_token)
    for session_row in session.exec(select(SessionRow).where(SessionRow.user_id == user_id)):
        session.delete(session_row)
    session.flush()
    session.delete(user)
    session.commit()


# --- devices / enrollment ----------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuedEnrollToken:
    token: str
    device_name_hint: str | None
    expires_at: datetime.datetime


def _check_name_free(session: Session, name: str) -> None:
    validate_name(name, what="device name")
    if session.exec(select(Device).where(Device.name == name)).first() is not None:
        raise ConflictError(f"device name {name!r} already in use")
    pending = session.exec(
        select(EnrollToken).where(
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
        _check_name_free(session, device_name_hint)
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
    if record.device_name_hint is not None:
        name = record.device_name_hint
    else:
        if not requested_name:
            raise ValidationError("this token has no fixed name -- a device name is required")
        _check_name_free(session, requested_name)
        name = requested_name

    api_token = generate_token()
    device = Device(
        name=name,
        owner_user_id=record.created_by,
        cert_serial=cert_serial,
        api_token_hash=hash_token(api_token),
        agent_version=agent_version,
    )
    session.add(device)
    record.used_at = _now()
    session.add(record)
    try:
        session.commit()
    except sqlalchemy.exc.IntegrityError as exc:
        session.rollback()
        raise ConflictError(f"device name {name!r} already in use") from exc
    session.refresh(device)
    return EnrolledDevice(device=device, api_token=api_token)


def revoke_enroll_token(session: Session, token_id: str) -> None:
    """Invalidate an unredeemed enroll token before anyone uses it -- e.g.
    it was sent to the wrong person, or leaked."""
    record = session.get(EnrollToken, token_id)
    if record is None:
        raise NotFoundError(f"no such enroll token {token_id!r}")
    if record.used_at is not None:
        raise ConflictError("already redeemed -- revoke the resulting device instead")
    record.revoked_at = _now()
    session.add(record)
    session.commit()


@dataclass(frozen=True, slots=True)
class PendingEnrollTokenView:
    id: str
    device_name_hint: str | None
    owner_email: str
    created_at: datetime.datetime
    expires_at: datetime.datetime


def list_pending_enroll_tokens(session: Session) -> list[PendingEnrollTokenView]:
    """Unredeemed, unexpired, unrevoked tokens -- for the admin dashboard's
    "revoke an issued token before it's used" list."""
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
            owner_email=user.email,
            created_at=token.created_at,
            expires_at=token.expires_at,
        )
        for token, user in rows
    ]


def get_device_by_api_token(session: Session, api_token: str) -> Device | None:
    """None for an unknown token OR a revoked device -- this is the control-plane
    enforcement point for revocation (see common/models.py's module docstring
    for what revocation does and does not cover)."""
    token_hash = hash_token(api_token)
    device = session.exec(select(Device).where(Device.api_token_hash == token_hash)).first()
    if device is None or device.revoked_at is not None:
        return None
    return device


def get_device(session: Session, device_id: str) -> Device | None:
    return session.get(Device, device_id)


def list_devices(session: Session) -> list[Device]:
    return list(session.exec(select(Device)))


def list_devices_for_owner(session: Session, owner_user_id: str) -> list[Device]:
    """Self-service `client list` -- every device owned by the same person
    as the calling device."""
    return list(session.exec(select(Device).where(Device.owner_user_id == owner_user_id)))


def get_device_by_name(session: Session, name: str) -> Device | None:
    return session.exec(select(Device).where(Device.name == name)).first()


def revoke_device(session: Session, device_id: str) -> None:
    device = session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"no such device {device_id!r}")
    device.revoked_at = _now()
    session.add(device)
    session.commit()


def delete_device(session: Session, device_id: str) -> None:
    """Permanently remove a device (and its services/grants), freeing its
    name for reuse -- e.g. the device was wiped/replaced and you want to
    re-enroll a new one under the same name.

    Unlike ``revoke_device``, this is not reversible and drops history.
    ``create_enroll_token`` blocks a name for as long as *any* Device row
    with it exists, revoked or not -- this is the only way to free one up.
    """
    device = session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"no such device {device_id!r}")

    # No SQLModel `Relationship()`s are declared between these tables (kept
    # deliberately flat/simple), so SQLAlchemy's unit-of-work has no FK
    # graph to auto-order these deletes by -- without explicit flushes
    # between stages it can (and did, see the test that caught this) try to
    # delete a row before what still references it, and SQLite's now-
    # enforced FOREIGN KEY constraint (server/db.py) rejects that.
    owned_service_ids = [
        s.id for s in session.exec(select(Service).where(Service.device_id == device_id))
    ]
    if owned_service_ids:
        for grant in session.exec(
            select(Grant).where(Grant.service_id.in_(owned_service_ids))
        ):
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


def revoke_grant(session: Session, grant_id: str) -> None:
    grant = session.get(Grant, grant_id)
    if grant is None:
        raise NotFoundError(f"no such grant {grant_id!r}")
    grant.revoked_at = _now()
    session.add(grant)
    session.commit()


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
    consumer) without the caller needing to know internal service/grant ids."""
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


# --- dashboard views (for the WebUI) --------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceView:
    id: str
    name: str
    owner_email: str
    enrolled_at: datetime.datetime
    last_seen_at: datetime.datetime | None
    agent_version: str | None
    revoked: bool


def list_devices_view(session: Session) -> list[DeviceView]:
    rows = session.exec(select(Device, User).join(User, Device.owner_user_id == User.id)).all()
    return [
        DeviceView(
            id=d.id,
            name=d.name,
            owner_email=u.email,
            enrolled_at=d.enrolled_at,
            last_seen_at=d.last_seen_at,
            agent_version=d.agent_version,
            revoked=d.revoked_at is not None,
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
    revoked: bool


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
            revoked=grant.revoked_at is not None,
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
    """Grants for services this device exposes. Excludes revoked grants and
    grants held by a since-revoked consumer device (see revocation note in
    common/models.py)."""
    consumer = _aliased(Device)
    rows = session.exec(
        select(Grant, Service)
        .join(Service, Grant.service_id == Service.id)
        .join(consumer, Grant.consumer_device_id == consumer.id)
        .where(
            Service.device_id == device_id,
            Grant.revoked_at.is_(None),
            consumer.revoked_at.is_(None),
        )
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
    """Grants this device may consume. Excludes revoked grants and grants
    exposed by a since-revoked device (see revocation note in
    common/models.py)."""
    rows = session.exec(
        select(Grant, Service, Device)
        .join(Service, Grant.service_id == Service.id)
        .join(Device, Service.device_id == Device.id)
        .where(
            Grant.consumer_device_id == device_id,
            Grant.revoked_at.is_(None),
            Device.revoked_at.is_(None),
        )
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
