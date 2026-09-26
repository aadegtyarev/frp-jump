"""FastAPI routes the agent talks to: enroll, heartbeat, desired-state pull,
plus every self-service device/connection-management endpoint.

Auth here is a per-device bearer token minted at enroll time -- see
``common/models.py``'s module docstring for why this API doesn't need mTLS
itself (the relay does, and that's the boundary that actually carries
tunneled traffic).
"""

from __future__ import annotations

import dataclasses
import datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlmodel import Session as DbSession

from frp_jump.common import ssh_signing
from frp_jump.common.api import PROTOCOL_VERSION
from frp_jump.common.models import Device
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry

router = APIRouter()

try:
    _PACKAGE_VERSION = _pkg_version("frp-jump")
except PackageNotFoundError:
    _PACKAGE_VERSION = "dev"


class VersionResponse(BaseModel):
    protocol_version: int
    package_version: str


@router.get("/version", response_model=VersionResponse)
def version() -> VersionResponse:
    """Unauthenticated, reachable before enrolling -- lets a client sanity-
    check it's actually talking to an frp-jump server, and at what
    protocol version, before doing anything else (`client doctor`/
    `enroll` use this). See ``common/api.PROTOCOL_VERSION``'s docstring
    for what this number means and doesn't."""
    return VersionResponse(protocol_version=PROTOCOL_VERSION, package_version=_PACKAGE_VERSION)


def get_db(request: Request) -> DbSession:
    with DbSession(request.app.state.engine) as db:
        yield db


def get_current_device(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> Device:
    """A *disabled* device still authenticates here -- see
    ``registry.get_device_by_api_token``'s docstring -- so its agent keeps
    polling and can notice being re-enabled. Only a route that actually
    changes something should reject it; use ``get_enabled_device`` for
    those instead of this directly."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    api_token = authorization.removeprefix("Bearer ").strip()
    device = registry.get_device_by_api_token(db, api_token)
    if device is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid device token")
    return device


def get_enabled_device(device: Annotated[Device, Depends(get_current_device)]) -> Device:
    """Same as ``get_current_device``, but also rejects a disabled device.

    Required by every *mutating* self-service route (connect/disconnect,
    add/delete/enable/disable a device, rotate the owner's key) -- a
    disabled device's bearer token must not be usable to re-enable itself
    or otherwise act on the owner's account. Every read-only route
    (heartbeat, desired-state, listing your own devices) stays reachable
    with it regardless -- desired-state already goes empty while
    disabled, and seeing your own device list (including your own
    disabled status) carries no such risk."""
    if not device.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this device is disabled")
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
    protocol_version: int = PROTOCOL_VERSION


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


class EnrollChallengeRequest(BaseModel):
    public_key: str


class EnrollChallengeResponse(BaseModel):
    challenge_id: str
    challenge: str  # base64, sign this with the matching private key


@router.post("/enroll/challenge", response_model=EnrollChallengeResponse)
def enroll_challenge(
    body: EnrollChallengeRequest, request: Request, db: Annotated[DbSession, Depends(get_db)]
) -> EnrollChallengeResponse:
    """Step 1 of key-based enrollment: prove you know a *registered* key by
    signing back a one-time nonce (see ``/enroll/by-key`` and
    ``common/ssh_signing.py``).

    Always succeeds with a syntactically valid challenge, whether or not
    this key is actually registered -- whether it is only becomes visible
    at ``/enroll/by-key``, where an unknown key fails exactly like a bad
    signature. A 404-vs-200 split here, however the error is worded, would
    itself be an oracle for which keys the server knows about; see
    ``registry.create_enroll_challenge``'s docstring."""
    settings = request.app.state.settings
    try:
        fingerprint = ssh_signing.fingerprint(body.public_key)
    except ssh_signing.SshSigningError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "malformed public key") from exc
    record = registry.create_enroll_challenge(
        db,
        fingerprint=fingerprint,
        ttl=datetime.timedelta(seconds=settings.enroll_challenge_ttl_seconds),
    )
    return EnrollChallengeResponse(challenge_id=record.id, challenge=record.challenge)


class EnrollByKeyRequest(BaseModel):
    challenge_id: str
    signature: str  # base64, over the challenge bytes, namespace ssh_signing.NAMESPACE
    agent_version: str | None = None
    requested_name: str


@router.post("/enroll/by-key", response_model=EnrollResponse)
def enroll_by_key(
    body: EnrollByKeyRequest, request: Request, db: Annotated[DbSession, Depends(get_db)]
) -> EnrollResponse:
    """Step 2: redeem the signed challenge, creating the named device under
    whichever user registered the matching key."""
    settings = request.app.state.settings
    ca = request.app.state.ca

    try:
        registry.peek_enroll_challenge(db, body.challenge_id, body.signature)
    except (registry.NotFoundError, registry.ValidationError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    # Same ordering rationale as /enroll: validate the name *before* the CA
    # signs anything.
    try:
        registry.validate_name(body.requested_name, what="device name")
    except registry.ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    leaf = ca.issue(body.requested_name, san_names=[body.requested_name])

    try:
        enrolled = registry.redeem_enroll_challenge(
            db,
            body.challenge_id,
            body.signature,
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
    protocol_version: int = PROTOCOL_VERSION


@router.get("/desired-state", response_model=DesiredStateResponse)
def desired_state(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> DesiredStateResponse:
    settings = request.app.state.settings
    # A disabled device tears down entirely -- both what it exposes and
    # what it consumes -- regardless of what grants still exist for it in
    # the database; it keeps polling so it notices being re-enabled.
    if not device.enabled:
        exposed: list = []
        consumed: list = []
    else:
        exposed = registry.exposed_grants_for_device(db, device.id)
        consumed = registry.consumed_grants_for_device(db, device.id)
    return DesiredStateResponse(
        device_id=device.id,
        server_addr=settings.relay_public_addr,
        server_port=settings.relay_bind_port,
        exposed=[ExposedGrantOut(**dataclasses.asdict(g)) for g in exposed],
        consumed=[ConsumedGrantOut(**dataclasses.asdict(g)) for g in consumed],
    )


# --- self-service user/device/connection management -----------------------
#
# Everything below is scoped to the calling device's owner: a device can only
# see, add, or delete devices owned by the same user, and can only connect to
# / disconnect from devices owned by the same user (or, for disconnect, any
# other device of its own owner -- see DisconnectRequest.consumer_device_name).
# There is no cross-user self-service -- only an admin (`frp-jump-server
# users add-key` / `enroll-tokens create`) starts a *different* owner's
# device tree. See docs/architecture.md.


class SetKeyChallengeRequest(BaseModel):
    public_key: str


class SetKeyChallengeResponse(BaseModel):
    challenge_id: str
    challenge: str  # base64, sign this with the NEW key's private half


@router.post("/users/set-key/challenge", response_model=SetKeyChallengeResponse)
def set_my_key_challenge(
    body: SetKeyChallengeRequest,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> SetKeyChallengeResponse:
    """Step 1 of `client set-key`: request a nonce to sign with the *new*
    key before rotating to it -- a bearer token alone must not be enough
    to repoint the account at an attacker-chosen key nobody has proven
    they hold."""
    settings = request.app.state.settings
    try:
        record = registry.create_key_rotation_challenge(
            db,
            device_id=device.id,
            public_key=body.public_key,
            ttl=datetime.timedelta(seconds=settings.enroll_challenge_ttl_seconds),
        )
    except registry.ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return SetKeyChallengeResponse(challenge_id=record.id, challenge=record.challenge)


class SetKeyRequest(BaseModel):
    challenge_id: str
    signature: str  # base64, over the challenge bytes, made with the NEW key


@router.post("/users/set-key", status_code=status.HTTP_204_NO_CONTENT)
def set_my_key(
    body: SetKeyRequest,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> None:
    """Step 2: redeem the signed challenge and rotate the calling device
    owner's SSH key to it."""
    try:
        registry.redeem_key_rotation_challenge(
            db, body.challenge_id, body.signature, device_id=device.id
        )
    except (registry.NotFoundError, registry.ValidationError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except registry.ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


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
    device: Annotated[Device, Depends(get_enabled_device)],
) -> AddDeviceResponse:
    """`client devices add-token`: mint a new enroll token for one more
    device owned by the same person as the calling device -- self-service
    chaining, no admin action needed."""
    settings = request.app.state.settings
    try:
        issued = registry.create_enroll_token(
            db,
            created_by=device.owner_user_id,
            ttl=datetime.timedelta(hours=settings.enroll_token_ttl_hours),
            device_name_hint=body.device_name_hint,
        )
    except (registry.ValidationError, registry.ConflictError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return AddDeviceResponse(
        token=issued.token,
        device_name_hint=issued.device_name_hint,
        expires_at=issued.expires_at.isoformat(),
    )


class OwnedDeviceOut(BaseModel):
    name: str
    enrolled_at: str
    last_seen_at: str | None
    enabled: bool


@router.get("/devices", response_model=list[OwnedDeviceOut])
def list_my_devices(
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_current_device)],
) -> list[OwnedDeviceOut]:
    """`client devices list`: every device owned by the same person as the
    caller."""
    return [
        OwnedDeviceOut(
            name=d.name,
            enrolled_at=d.enrolled_at.isoformat(),
            last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else None,
            enabled=d.enabled,
        )
        for d in registry.list_devices_for_owner(db, device.owner_user_id)
    ]


def _get_owned_device_by_name(db: DbSession, device: Device, name: str) -> Device:
    """Resolve `name` to a Device the caller may act on -- same owner as the
    caller, otherwise a 404 (device names are only unique per-owner, so this
    lookup is already scoped; a 404 here just means "you have no device by
    that name")."""
    target = registry.get_device_by_name(db, device.owner_user_id, name)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no such device {name!r}")
    return target


@router.post("/devices/{name}/delete", status_code=status.HTTP_204_NO_CONTENT)
def delete_my_device(
    name: str,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> None:
    """`client devices delete`: permanently remove one of your own devices."""
    target = _get_owned_device_by_name(db, device, name)
    registry.delete_device(db, target.id)


@router.post("/devices/{name}/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_my_device(
    name: str,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> None:
    """`client devices disable`: tear down and block one of your own
    devices' connections, without losing its enrollment."""
    target = _get_owned_device_by_name(db, device, name)
    registry.disable_device(db, target.id)


@router.post("/devices/{name}/enable", status_code=status.HTTP_204_NO_CONTENT)
def enable_my_device(
    name: str,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> None:
    """`client devices enable`: undo `disable`."""
    target = _get_owned_device_by_name(db, device, name)
    registry.enable_device(db, target.id)


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
    device: Annotated[Device, Depends(get_enabled_device)],
) -> ConnectResponse:
    """`client connect`: wire this device up to consume a port on another
    device you own. Idempotent -- connecting again reuses the existing
    grant. Takes effect on both sides' next poll cycle, not instantly."""
    target = _get_owned_device_by_name(db, device, body.device_name)
    if target.id == device.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot connect a device to itself")
    if not target.enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"device {body.device_name!r} is disabled"
        )

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
    # Which of your own devices to disconnect -- defaults to the caller
    # itself. Set this to tear down a connection made *from a different one
    # of your own devices* (e.g. you forgot you left something connected
    # elsewhere) -- see `--from` in `client_cmds.disconnect`.
    consumer_device_name: str | None = None


@router.post("/disconnect", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(
    body: DisconnectRequest,
    db: Annotated[DbSession, Depends(get_db)],
    device: Annotated[Device, Depends(get_enabled_device)],
) -> None:
    """`client disconnect`: drop a connection made with `connect`, from this
    device or (via `consumer_device_name`) any other device you own."""
    target = _get_owned_device_by_name(db, device, body.device_name)
    if body.consumer_device_name is not None:
        consumer = _get_owned_device_by_name(db, device, body.consumer_device_name)
    else:
        consumer = device
    grant = registry.find_grant_for_connection(
        db, device_id=target.id, target_port=body.target_port, consumer_device_id=consumer.id
    )
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not connected")
    registry.delete_grant(db, grant.id)
