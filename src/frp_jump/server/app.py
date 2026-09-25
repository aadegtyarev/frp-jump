"""FastAPI application factory: wires settings/db/CA into app.state."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Engine

from frp_jump.common.api import AGENT_API_PREFIX
from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.server import api as agent_api
from frp_jump.server import web
from frp_jump.server.web import Forbidden, RequireLogin


def create_app(*, settings: Settings, engine: Engine, ca: CertificateAuthority) -> FastAPI:
    app = FastAPI(title="frp-jump")
    app.state.settings = settings
    app.state.engine = engine
    app.state.ca = ca
    app.include_router(agent_api.router, prefix=AGENT_API_PREFIX, tags=["agent"])
    app.include_router(web.router, tags=["webui"])

    @app.exception_handler(RequireLogin)
    def _redirect_to_login(request: Request, exc: RequireLogin) -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(Forbidden)
    def _forbidden(request: Request, exc: Forbidden) -> HTMLResponse:
        return web.templates.TemplateResponse(
            request,
            "result.html",
            {"title": "Not allowed", "error": "only an admin can do this"},
            status_code=403,
        )

    return app
