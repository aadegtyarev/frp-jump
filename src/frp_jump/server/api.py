"""FastAPI routes the agent talks to: enroll, heartbeat, desired-state pull.

Auth here is a per-device bearer token minted at enroll time -- see
``common/models.py``'s module docstring for why this API doesn't need mTLS
itself (the relay does, and that's the boundary that actually carries
tunneled traffic).
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlmodel import Session as DbSession

from frp_jump.common.models import Device
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry

router = APIRouter()


def get_db(request: Request) -> DbSession:
    with DbSession(request.app.state.engine) as db:
        yield db


def get_current_device(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> Device:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    api_token = authorization.removeprefix("Bearer ").strip()
    device = registry.get_device_by_api_token(db, api_token)
    if device is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid device token")
    return device


class EnrollRequest(BaseModel):
    token: str
    agent_version: str | None = None
    # Only used (and required) when the token was issued without a fixed
    # name -- see EnrollToken.device_name_hint's docstring in common/models.py.
    requested_name: str | None = None


class EnrollResponse(BaseModel):
    device_id: str
    device_name: str
    api_token: str
    cert_pem: str
    key_pem: str
    ca_cert_pem: str
    server_addr: str
    server_port: int


@router.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: Annotated[DbSession, Depends(get_db)]):
    settings = request.app.state.settings
    ca = request.app.state.ca

    try:
        pending = registry.peek_enroll_token(db, body.token)
    except registry.NotFoundError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    name = pending.device_name_hint or body.requested_name
    if not name:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "this token has no fixed name -- pass requested_name",
        )
    # Validate *before* asking the CA to sign anything -- requested_name is
    # attacker-controlled when the token has no fixed device_name_hint, and
    # registry.redeem_enroll_token only re-validates it after the cert
    # already exists.
    try:
        registry.validate_name(name, what="device name")
    except registry.ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    leaf = ca.issue(name, san_names=[name])

    try:
        enrolled = registry.redeem_enroll_token(
            db,
            body.token,
            cert_serial=str(leaf.serial_number),
            agent_version=body.agent_version,
            requested_name=body.requested_name,
        )
    except (registry.NotFoundError, registry.ValidationError, registry.ConflictError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return EnrollResponse(
        device_id=enrolled.device.id,
        device_name=enrolled.device.name,
        api_token=enrolled.api_token,
        cert_pem=leaf.cert_pem.decode("ascii"),
        key_pem=leaf.key_pem.decode("ascii"),
        ca_cert_pem=ca.cert_pem.decode("ascii"),
        server_addr=settings.relay_public_addr,
        server_port=settings.relay_bind_port,
    )


class HeartbeatRequest(BaseModel):
    agent_version: str | None = None


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
def heartbeat(
    body: HeartbeatRequest,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> None:
    registry.record_heartbeat(db, device, agent_version=body.agent_version)


class ExposedGrantOut(BaseModel):
    grant_id: str
    secret: str
    service_name: str
    target_port: int


class ConsumedGrantOut(BaseModel):
    grant_id: str
    secret: str
    service_name: str
    protocol: ServiceProtocol
    exposer_device_name: str
    target_port: int


class DesiredStateResponse(BaseModel):
    device_id: str
    server_addr: str
    server_port: int
    exposed: list[ExposedGrantOut]
    consumed: list[ConsumedGrantOut]


@router.get("/desired-state", response_model=DesiredStateResponse)
def desired_state(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> DesiredStateResponse:
    settings = request.app.state.settings
    exposed = registry.exposed_grants_for_device(db, device.id)
    consumed = registry.consumed_grants_for_device(db, device.id)
    return DesiredStateResponse(
        device_id=device.id,
        server_addr=settings.relay_public_addr,
        server_port=settings.relay_bind_port,
        exposed=[ExposedGrantOut(**dataclasses.asdict(g)) for g in exposed],
        consumed=[ConsumedGrantOut(**dataclasses.asdict(g)) for g in consumed],
    )


# --- self-service device/connection management ----------------------------
#
# Everything below is scoped to the calling device's owner: a device can only
# see, add, or delete devices owned by the same user, and can only connect to
# / disconnect from devices owned by the same user. There is no cross-user
# self-service -- an admin invite (a token with created_by = the new user)
# is what starts a *different* owner's device tree. See docs/architecture.md.


class AddDeviceRequest(BaseModel):
    device_name_hint: str | None = None


class AddDeviceResponse(BaseModel):
    token: str
    device_name_hint: str | None
    expires_at: str


@router.post("/devices/enroll-tokens", response_model=AddDeviceResponse)
def add_device(
    body: AddDeviceRequest,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> AddDeviceResponse:
    """`client add-device`: mint a new enroll token for one more device owned
    by the same person as the calling device -- self-service chaining, no
    admin action needed."""
    settings = request.app.state.settings
    try:
        issued = registry.create_enroll_token(
            db,
            created_by=device.owner_user_id,
            ttl=datetime.timedelta(hours=settings.enroll_token_ttl_hours),
            device_name_hint=body.device_name_hint,
        )
    except (registry.ValidationError, registry.ConflictError) as exc:
        # Deliberately generic: device names are a single global namespace
        # (see docs/architecture.md), so echoing registry's real message
        # ("already in use" vs. a charset complaint) would let one owner
        # probe whether a name belongs to a device they don't own -- the
        # same leak _get_owned_device_by_name's 404-not-403 exists to close.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "that name is not available -- pick a different one, or leave it unset",
        ) from exc
    return AddDeviceResponse(
        token=issued.token,
        device_name_hint=issued.device_name_hint,
        expires_at=issued.expires_at.isoformat(),
    )


class OwnedDeviceOut(BaseModel):
    name: str
    enrolled_at: str
    last_seen_at: str | None
    revoked: bool


@router.get("/devices", response_model=list[OwnedDeviceOut])
def list_my_devices(
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> list[OwnedDeviceOut]:
    """`client list`: every device owned by the same person as the caller."""
    return [
        OwnedDeviceOut(
            name=d.name,
            enrolled_at=d.enrolled_at.isoformat(),
            last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else None,
            revoked=d.revoked_at is not None,
        )
        for d in registry.list_devices_for_owner(db, device.owner_user_id)
    ]


def _get_owned_device_by_name(db: DbSession, device: Device, name: str) -> Device:
    """Resolve `name` to a Device the caller may act on -- same owner as the
    caller, otherwise a 404 (not 403: don't reveal whether the name belongs
    to someone else)."""
    target = registry.get_device_by_name(db, name)
    if target is None or target.owner_user_id != device.owner_user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such device {name!r}")
    return target


@router.post("/devices/{name}/delete", status_code=status.HTTP_204_NO_CONTENT)
def delete_my_device(
    name: str,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> None:
    """`client delete-device`: permanently remove one of your own devices."""
    target = _get_owned_device_by_name(db, device, name)
    registry.delete_device(db, target.id)


class ConnectRequest(BaseModel):
    device_name: str
    target_port: int = Field(ge=1, le=65535)
    protocol: ServiceProtocol


class ConnectResponse(BaseModel):
    grant_id: str
    exposer_device_name: str
    target_port: int
    protocol: ServiceProtocol


@router.post("/connect", response_model=ConnectResponse)
def connect(
    body: ConnectRequest,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> ConnectResponse:
    """`client connect`: wire this device up to consume a port on another
    device you own. Idempotent -- connecting again reuses the existing
    grant. Takes effect on both sides' next poll cycle, not instantly."""
    target = _get_owned_device_by_name(db, device, body.device_name)
    if target.revoked_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such device {body.device_name!r}")
    if target.id == device.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot connect a device to itself")

    try:
        service = registry.find_or_create_service(
            db, device_id=target.id, target_port=body.target_port, protocol=body.protocol
        )
    except (registry.ValidationError, registry.ConflictError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    grant = registry.find_or_create_grant(db, service_id=service.id, consumer_device_id=device.id)
    return ConnectResponse(
        grant_id=grant.id,
        exposer_device_name=target.name,
        target_port=body.target_port,
        # The service's actual protocol, not necessarily body.protocol --
        # `find_or_create_service` raises above if they'd conflict, but on
        # the reuse path they're always equal anyway; this is just the
        # single source of truth so the two can never silently drift.
        protocol=service.protocol,
    )


class DisconnectRequest(BaseModel):
    device_name: str
    target_port: int = Field(ge=1, le=65535)


@router.post("/disconnect", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(
    body: DisconnectRequest,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> None:
    """`client disconnect`: drop a connection this device made with `connect`."""
    target = _get_owned_device_by_name(db, device, body.device_name)
    grant = registry.find_grant_for_connection(
        db, device_id=target.id, target_port=body.target_port, consumer_device_id=device.id
    )
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not connected")
    registry.delete_grant(db, grant.id)
