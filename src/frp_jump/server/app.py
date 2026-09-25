"""FastAPI application factory: wires settings/db/CA into app.state.

WebUI routes (``server.web``) are mounted here too once Phase 4 lands;
for now this only carries the agent-facing API.
"""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import Engine

from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.server import api as agent_api


def create_app(*, settings: Settings, engine: Engine, ca: CertificateAuthority) -> FastAPI:
    app = FastAPI(title="frp-jump")
    app.state.settings = settings
    app.state.engine = engine
    app.state.ca = ca
    app.include_router(agent_api.router, prefix="/api/agent", tags=["agent"])
    return app
