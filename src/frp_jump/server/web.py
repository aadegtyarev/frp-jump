"""WebUI: passwordless magic-link login, dashboard for devices/services/grants/invites.

No self-service signup: a session only ever starts by visiting a
``LoginToken`` link an admin generated (``server login-link``/the "Add
device"/"Invite" forms below) and hand-delivered out of band.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session as DbSession

from frp_jump.common.models import TokenPurpose, User
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import auth, registry
from frp_jump.server.api import get_db
from frp_jump.server.bootstrap import build_url

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

SESSION_COOKIE = "frp_jump_session"


class RequireLogin(Exception):
    """No valid session; the app-level exception handler redirects to /login."""


class Forbidden(Exception):
    """Logged in, but not allowed to do this; the app-level handler shows an error page."""


def current_user(request: Request, db: Annotated[DbSession, Depends(get_db)]) -> User:
    user = auth.get_current_user(db, request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise RequireLogin()
    return user


def require_admin(user: Annotated[User, Depends(current_user)]) -> User:
    """Fleet-mutating actions (add device, add service, grant access) are
    admin-only -- a non-admin invited user can view the dashboard but not
    reach into devices they don't own."""
    if not user.is_admin:
        raise Forbidden()
    return user


def _page(request: Request, name: str, **context: object) -> HTMLResponse:
    return templates.TemplateResponse(request, name, context)


def _cookie_is_secure(request: Request) -> bool:
    """Whether to set the session cookie's `Secure` flag.

    ``request.url.scheme`` alone is wrong for the documented deployment
    (TLS-terminating reverse proxy -> plain HTTP to uvicorn): uvicorn only
    ever sees "http" there, so the cookie would silently lose `Secure` and
    ride along any plaintext request to the same host. Trust
    ``public_base_url`` (the actual externally-visible URL) too.
    """
    settings = request.app.state.settings
    if request.url.scheme == "https":
        return True
    return bool(settings.public_base_url) and settings.public_base_url.startswith("https://")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return _page(request, "login.html")


@router.get("/auth/{token}")
def redeem_login(token: str, request: Request, db: Annotated[DbSession, Depends(get_db)]):
    settings = request.app.state.settings
    try:
        user = auth.redeem_login_token(db, token)
    except auth.InvalidTokenError as exc:
        return _page(request, "login.html", error=str(exc))

    ttl = datetime.timedelta(days=settings.session_ttl_days)
    session_token = auth.create_session(db, user, ttl=ttl)
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        httponly=True,
        secure=_cookie_is_secure(request),
        samesite="lax",
        max_age=int(ttl.total_seconds()),
    )
    return response


@router.post("/logout")
def logout(request: Request, db: Annotated[DbSession, Depends(get_db)]):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth.revoke_session(db, token)
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(current_user)],
) -> HTMLResponse:
    return _page(
        request,
        "dashboard.html",
        user=user,
        devices=registry.list_devices(db),
        services=registry.list_services_view(db),
        grants=registry.list_grants_view(db),
        service_protocols=list(ServiceProtocol),
    )


@router.post("/devices/enroll-token", response_class=HTMLResponse)
def create_enroll_token(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
    device_name: Annotated[str, Form()],
):
    settings = request.app.state.settings
    try:
        issued = registry.create_enroll_token(
            db,
            device_name_hint=device_name,
            created_by=user.id,
            ttl=datetime.timedelta(hours=settings.enroll_token_ttl_hours),
        )
    except (registry.ConflictError, registry.ValidationError) as exc:
        return _page(request, "result.html", title="Add device", error=str(exc))

    control_url = settings.public_base_url or (
        f"http://{settings.relay_public_addr}:{settings.webui_port}"
    )
    command = f"frp-jump client enroll {control_url} {issued.token}"
    return _page(
        request,
        "result.html",
        title="Add device",
        label=f"Run this on {device_name} to enroll it (shown once)",
        value=command,
    )


@router.post("/users/invite", response_class=HTMLResponse)
def invite_user(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
    email: Annotated[str, Form()],
):
    settings = request.app.state.settings
    token = auth.issue_login_token(
        db,
        email=email,
        purpose=TokenPurpose.INVITE,
        created_by=user.id,
        ttl=datetime.timedelta(days=settings.invite_token_ttl_days),
    )
    link = build_url(settings, f"/auth/{token}")
    return _page(
        request,
        "result.html",
        title="Invite",
        label=f"Send this link to {email} yourself (shown once)",
        value=link,
    )


@router.post("/services", response_class=HTMLResponse)
def create_service(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
    device_id: Annotated[str, Form()],
    name: Annotated[str, Form()],
    protocol: Annotated[str, Form()],
    target_port: Annotated[int, Form()],
):
    try:
        service_protocol = ServiceProtocol(protocol)
    except ValueError:
        error = f"unknown protocol {protocol!r}"
        return _page(request, "result.html", title="Add service", error=error)
    try:
        registry.create_service(
            db, device_id=device_id, name=name, protocol=service_protocol, target_port=target_port
        )
    except (registry.ConflictError, registry.ValidationError, registry.NotFoundError) as exc:
        return _page(request, "result.html", title="Add service", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/grants", response_class=HTMLResponse)
def create_grant(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
    service_id: Annotated[str, Form()],
    consumer_device_id: Annotated[str, Form()],
):
    try:
        registry.create_grant(db, service_id=service_id, consumer_device_id=consumer_device_id)
    except (registry.ConflictError, registry.NotFoundError) as exc:
        return _page(request, "result.html", title="Grant access", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/revoke", response_class=HTMLResponse)
def revoke_device(
    device_id: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
):
    """Stops the device authenticating to the control-plane API (heartbeat,
    desired-state) from its next attempt on. Does NOT tear down a
    connection it already has to the relay -- see the revocation note in
    common/models.py."""
    try:
        registry.revoke_device(db, device_id)
    except registry.NotFoundError as exc:
        return _page(request, "result.html", title="Revoke device", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/grants/{grant_id}/revoke", response_class=HTMLResponse)
def revoke_grant(
    grant_id: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
):
    """Drops out of both sides' desired-state on their next poll -- not
    instant, see the revocation note in common/models.py."""
    try:
        registry.revoke_grant(db, grant_id)
    except registry.NotFoundError as exc:
        return _page(request, "result.html", title="Revoke grant", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
