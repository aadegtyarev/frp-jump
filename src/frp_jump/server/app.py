"""FastAPI application factory: wires settings/db/CA into app.state.

No WebUI is mounted here -- administration is entirely `frp-jump-server`
CLI, run over SSH to the box (see docs/architecture.md). This app serves
only the agent-facing control-plane API.
"""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import Engine

from frp_jump.common.api import AGENT_API_PREFIX
from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.server import api as agent_api


def create_app(*, settings: Settings, engine: Engine, ca: CertificateAuthority) -> FastAPI:
    app = FastAPI(title="frp-jump")
    app.state.settings = settings
    app.state.engine = engine
    app.state.ca = ca
    app.include_router(agent_api.router, prefix=AGENT_API_PREFIX, tags=["agent"])
    return app
