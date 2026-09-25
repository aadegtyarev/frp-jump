"""WebUI: passwordless magic-link login, admin-only dashboard.

There is no self-service signup, and regular (non-admin) users never see
this UI at all -- a session only ever starts by visiting a ``LoginToken``
link the admin generated (``server login-link``) and hand-delivered out of
band, and every route below other than /login and /auth/{token} requires
that session to belong to an admin. Everyone else (friends, their devices)
is onboarded and self-serves entirely through the CLI -- see
docs/architecture.md for the full design and why.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session as DbSession

from frp_jump.common.models import User
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import auth, registry
from frp_jump.server.api import get_db

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
    """The entire dashboard is admin-only -- see the module docstring for why."""
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


# A device that hasn't heartbeat-ed in this many poll intervals is shown as
# offline. Pure display heuristic (not a protocol/security parameter), so a
# plain constant rather than another Settings knob -- 3x the poll interval
# gives normal network jitter room without a missed heartbeat instantly
# flipping a healthy device to "offline".
_ONLINE_THRESHOLD_POLLS = 3


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
) -> HTMLResponse:
    settings = request.app.state.settings
    online_threshold = datetime.timedelta(
        seconds=_ONLINE_THRESHOLD_POLLS * settings.agent_poll_interval_seconds
    )
    now = datetime.datetime.now(datetime.UTC)
    devices = registry.list_devices_view(db)
    online = {
        d.id: d.last_seen_at is not None and (now - d.last_seen_at) < online_threshold
        for d in devices
    }
    return _page(
        request,
        "dashboard.html",
        user=admin,
        devices=devices,
        online=online,
        users=registry.list_users_view(db),
        pending_tokens=registry.list_pending_enroll_tokens(db),
        services=registry.list_services_view(db),
        grants=registry.list_grants_view(db),
        service_protocols=list(ServiceProtocol),
    )


@router.post("/devices/enroll-token", response_class=HTMLResponse)
def create_enroll_token(
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
    device_name: Annotated[str, Form()] = "",
    owner_email: Annotated[str, Form()] = "",
):
    """Issue a one-time enroll command. Leave `device_name` blank to let
    whoever redeems it pick their own name (`client enroll ... --name`);
    set `owner_email` to onboard a friend's first device under their own
    account instead of yours -- every device after that one is theirs to
    add/remove/connect via their own CLI (`client add-device`), no further
    admin action needed."""
    settings = request.app.state.settings
    owner = registry.get_or_create_user(db, owner_email) if owner_email else user
    try:
        issued = registry.create_enroll_token(
            db,
            device_name_hint=device_name or None,
            created_by=owner.id,
            ttl=datetime.timedelta(hours=settings.enroll_token_ttl_hours),
        )
    except (registry.ConflictError, registry.ValidationError) as exc:
        return _page(request, "result.html", title="Add device", error=str(exc))

    control_url = settings.public_base_url or (
        f"http://{settings.relay_public_addr}:{settings.webui_port}"
    )
    command = f"frp-jump-client enroll {control_url} {issued.token}"
    target = device_name or "<pick-a-name>"
    if not device_name:
        command += " --name <pick-a-name>"
    return _page(
        request,
        "result.html",
        title="Add device",
        label=f"Run this on {target} (owner: {owner.email}) to enroll it (shown once)",
        value=command,
    )


@router.post("/users/{user_id}/delete", response_class=HTMLResponse)
def delete_user(
    user_id: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    """Permanently removes the user and every device they own (see
    ``registry.delete_user``). Refuses to delete the last remaining admin."""
    try:
        registry.delete_user(db, user_id)
    except (registry.NotFoundError, registry.ConflictError) as exc:
        return _page(request, "result.html", title="Delete user", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/enroll-tokens/{token_id}/revoke", response_class=HTMLResponse)
def revoke_enroll_token(
    token_id: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_admin)],
):
    """Invalidate an issued-but-not-yet-redeemed enroll token."""
    try:
        registry.revoke_enroll_token(db, token_id)
    except (registry.NotFoundError, registry.ConflictError) as exc:
        return _page(request, "result.html", title="Revoke enroll token", error=str(exc))
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


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


@router.post("/devices/{device_id}/delete", response_class=HTMLResponse)
def delete_device(
    device_id: str,
    request: Request,
    db: Annotated[DbSession, Depends(get_db)],
    user: Annotated[User, Depends(require_admin)],
):
    """Permanently removes the device and its services/grants, freeing its
    name for a new enroll token -- e.g. it was wiped/replaced. Not
    reversible; unlike revoke, this drops history."""
    try:
        registry.delete_device(db, device_id)
    except registry.NotFoundError as exc:
        return _page(request, "result.html", title="Delete device", error=str(exc))
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
