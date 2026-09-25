"""FastAPI routes the agent talks to: enroll, heartbeat, desired-state pull.

Auth here is a per-device bearer token minted at enroll time -- see
``common/models.py``'s module docstring for why this API doesn't need mTLS
itself (the relay does, and that's the boundary that actually carries
tunneled traffic).
"""

from __future__ import annotations

import dataclasses
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
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

    leaf = ca.issue(pending.device_name_hint, san_names=[pending.device_name_hint])

    try:
        enrolled = registry.redeem_enroll_token(
            db, body.token, cert_serial=str(leaf.serial_number), agent_version=body.agent_version
        )
    except registry.NotFoundError as exc:
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
