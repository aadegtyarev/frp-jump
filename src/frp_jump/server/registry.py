"""CRUD and desired-state views over the control-plane database.

Kept framework-agnostic (plain SQLModel ``Session``, no FastAPI) so it can
be unit-tested directly and reused by both the API and the WebUI.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from sqlmodel import Session, select

from frp_jump.common.crypto import generate_token, hash_token
from frp_jump.common.models import Device, EnrollToken, Grant, Service, User
from frp_jump.driver.base import ServiceProtocol


class NotFoundError(LookupError):
    pass


class ConflictError(ValueError):
    pass


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


# --- devices / enrollment ----------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuedEnrollToken:
    token: str
    device_name_hint: str
    expires_at: datetime.datetime


def create_enroll_token(
    session: Session, *, device_name_hint: str, created_by: str, ttl: datetime.timedelta
) -> IssuedEnrollToken:
    if session.exec(select(Device).where(Device.name == device_name_hint)).first() is not None:
        raise ConflictError(f"device name {device_name_hint!r} already in use")
    pending = session.exec(
        select(EnrollToken).where(
            EnrollToken.device_name_hint == device_name_hint,
            EnrollToken.used_at.is_(None),
            EnrollToken.expires_at >= _now(),
        )
    ).first()
    if pending is not None:
        raise ConflictError(f"an unredeemed enroll token for {device_name_hint!r} already exists")
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
    session: Session, token: str, *, cert_serial: str, agent_version: str | None = None
) -> EnrolledDevice:
    """Consume a one-time enroll token, creating the Device row it names."""
    record = _find_valid_enroll_token(session, token)
    api_token = generate_token()
    device = Device(
        name=record.device_name_hint,
        owner_user_id=record.created_by,
        cert_serial=cert_serial,
        api_token_hash=hash_token(api_token),
        agent_version=agent_version,
    )
    session.add(device)
    record.used_at = _now()
    session.add(record)
    session.commit()
    session.refresh(device)
    return EnrolledDevice(device=device, api_token=api_token)


def get_device_by_api_token(session: Session, api_token: str) -> Device | None:
    token_hash = hash_token(api_token)
    return session.exec(select(Device).where(Device.api_token_hash == token_hash)).first()


def get_device(session: Session, device_id: str) -> Device | None:
    return session.get(Device, device_id)


def list_devices(session: Session) -> list[Device]:
    return list(session.exec(select(Device)))


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
    if session.exec(select(Service).where(Service.name == name)).first() is not None:
        raise ConflictError(f"service name {name!r} already in use")
    service = Service(device_id=device_id, name=name, protocol=protocol, target_port=target_port)
    session.add(service)
    session.commit()
    session.refresh(service)
    return service


def list_services_for_device(session: Session, device_id: str) -> list[Service]:
    return list(session.exec(select(Service).where(Service.device_id == device_id)))


def create_grant(session: Session, *, service_id: str, consumer_device_id: str) -> Grant:
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


# --- dashboard views (for the WebUI) --------------------------------------


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


def exposed_grants_for_device(session: Session, device_id: str) -> list[ExposedGrantView]:
    rows = session.exec(
        select(Grant, Service).join(Service, Grant.service_id == Service.id).where(
            Service.device_id == device_id
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
    rows = session.exec(
        select(Grant, Service, Device)
        .join(Service, Grant.service_id == Service.id)
        .join(Device, Service.device_id == Device.id)
        .where(Grant.consumer_device_id == device_id)
    ).all()
    return [
        ConsumedGrantView(
            grant_id=grant.id,
            secret=grant.secret,
            service_name=service.name,
            protocol=service.protocol,
            exposer_device_name=exposer.name,
        )
        for grant, service, exposer in rows
    ]
