"""Local frps hooks: authorize relay operations against the control-plane DB.

The listener is loopback-only and protected by an unguessable path. It is
separate from the public API, so TLS termination/proxy prefixes cannot break
relay authorization. No request bodies or credentials are logged.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from sqlmodel import Session

from frp_jump.common.models import Device, Grant, Service
from frp_jump.server import registry

logger = logging.getLogger(__name__)
OPS = ["Login", "NewProxy", "Ping", "NewWorkConn", "NewUserConn"]


def _reject() -> dict:
    return {"reject": True, "reject_reason": "relay operation not authorized"}


def authorize(db: Session, op: str, content: dict, *, require_device_auth: bool) -> dict:
    if op not in OPS:
        return _reject()
    identity = content if op == "Login" else content.get("user", {})
    metas = identity.get("metas") or {}
    token = metas.get("frp_jump_token", "")
    device_id = metas.get("frp_jump_device", "")
    device = registry.get_device_by_api_token(db, token) if token else None
    if token or device_id or require_device_auth:
        if device is None or not device.enabled or device.id != device_id:
            return _reject()
    if op == "Login":
        if not require_device_auth:
            return {"reject": False, "unchange": True}
        # Identity is assigned by the server, never trusted from the client.
        # Proxy names stay unchanged: frpc uses its own (empty) user setting.
        return {"reject": False, "unchange": False, "content": {
            **content, "user": device.id, "run_id": secrets.token_hex(16),
            "client_id": device.id,
        }}
    if op in {"NewProxy", "NewUserConn"}:
        proxy_type = content.get("proxy_type")
        name = content.get("proxy_name", "")
        if proxy_type not in {"stcp", "xtcp"} or not name.endswith("-" + proxy_type):
            return _reject()
        grant = db.get(Grant, name[: -(len(proxy_type) + 1)])
        service = db.get(Service, grant.service_id) if grant else None
        exposer = db.get(Device, service.device_id) if service else None
        consumer = db.get(Device, grant.consumer_device_id) if grant else None
        if not exposer or not consumer or not exposer.enabled or not consumer.enabled:
            return _reject()
        if device is not None and device.id != exposer.id:
            return _reject()
        if op == "NewProxy":
            if (
                not hmac.compare_digest(content.get("sk", "").encode(), grant.secret.encode())
                or content.get("use_encryption") is not True
                or content.get("group")
                or content.get("remote_port", 0)
            ):
                return _reject()
            # Disallow anonymous visitors (an empty run_id otherwise bypasses
            # Login in frps). Only the authenticated grantee may consume it.
            if require_device_auth:
                return {"reject": False, "unchange": False, "content": {
                    **content, "allow_users": [consumer.id],
                }}
    return {"reject": False, "unchange": True}


class RelayPolicyServer:
    def __init__(self, engine, *, require_device_auth: bool) -> None:
        self.engine = engine
        self.require_device_auth = require_device_auth
        self.path = "/" + secrets.token_urlsafe(32)
        self._server = None
        self._thread = None

    def __enter__(self):
        policy = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def do_POST(self):  # noqa: N802
                result = _reject()
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not hmac.compare_digest(urlsplit(self.path).path, policy.path):
                        self.send_error(404)
                        return
                    if not 0 < length <= 65536:
                        self.send_error(413)
                        return
                    body = json.loads(self.rfile.read(length))
                    with Session(policy.engine) as db:
                        result = authorize(
                            db, body["op"], body["content"],
                            require_device_auth=policy.require_device_auth,
                        )
                except (ValueError, KeyError, TypeError, AttributeError):
                    pass
                except Exception:
                    # SQL exceptions can include bound parameters (tokens).
                    logger.error("relay authorization unavailable; rejecting request")
                payload = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}{self.path}"

    def __exit__(self, *args):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()
