"""FastAPI application factory: wires settings/db/CA into app.state.

No WebUI is mounted here -- administration is entirely `frp-jump-server`
CLI, run over SSH to the box (see docs/architecture.md). This app serves
only the agent-facing control-plane API.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from sqlalchemy import Engine

from frp_jump.common.api import AGENT_API_PREFIX
from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.server import api as agent_api

# A relay box is reachable from the whole internet by construction (see
# README's "Ports and firewalls") -- anything that identifies what's
# actually running there (FastAPI's auto-generated /docs, /redoc,
# /openapi.json, or an informative 404 on "/") is free reconnaissance for
# an opportunistic scanner. None of that is needed: the only real client
# is `frp-jump-client`, which only ever calls AGENT_API_PREFIX routes
# directly and never discovers them by crawling.
_DECOY_INDEX = HTMLResponse("<html><body><h1>It works!</h1></body></html>")


def create_app(*, settings: Settings, engine: Engine, ca: CertificateAuthority) -> FastAPI:
    app = FastAPI(title="frp-jump", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.ca = ca
    app.include_router(agent_api.router, prefix=AGENT_API_PREFIX, tags=["agent"])

    @app.get("/", include_in_schema=False)
    def _index() -> HTMLResponse:
        return _DECOY_INDEX

    return app
