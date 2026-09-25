import datetime

import pytest
from fastapi.testclient import TestClient

from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry
from frp_jump.server.app import create_app
from frp_jump.server.db import make_engine

_TTL = datetime.timedelta(hours=24)


@pytest.fixture
def app_ctx(tmp_path):
    settings = Settings(
        data_dir=tmp_path, relay_public_addr="relay.example.com", relay_bind_port=7000
    )
    engine = make_engine(":memory:")
    ca = CertificateAuthority.bootstrap("test CA")
    app = create_app(settings=settings, engine=engine, ca=ca)
    return app, engine, ca


@pytest.fixture
def client(app_ctx):
    app, _engine, _ca = app_ctx
    return TestClient(app)


def _make_admin_and_token(engine, device_name: str = "wb01") -> str:
    from frp_jump.server.db import make_session

    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com", is_admin=True)
        issued = registry.create_enroll_token(
            db, device_name_hint=device_name, created_by=admin.id, ttl=_TTL
        )
        return issued.token


def test_enroll_with_valid_token_returns_cert_material(client, app_ctx) -> None:
    _app, engine, ca = app_ctx
    token = _make_admin_and_token(engine)

    resp = client.post("/api/agent/enroll", json={"token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_name"] == "wb01"
    assert ca.verify_chain(body["cert_pem"].encode()) is True
    assert body["server_addr"] == "relay.example.com"
    assert body["server_port"] == 7000
    assert body["api_token"]


def test_enroll_with_unknown_token_is_rejected(client) -> None:
    resp = client.post("/api/agent/enroll", json={"token": "not-a-real-token"})
    assert resp.status_code == 400


def test_enroll_token_cannot_be_reused(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _make_admin_and_token(engine)
    first = client.post("/api/agent/enroll", json={"token": token})
    assert first.status_code == 200
    second = client.post("/api/agent/enroll", json={"token": token})
    assert second.status_code == 400


def test_heartbeat_requires_bearer_token(client) -> None:
    resp = client.post("/api/agent/heartbeat", json={})
    assert resp.status_code == 401


def test_heartbeat_with_valid_token_succeeds(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _make_admin_and_token(engine)
    enrolled = client.post("/api/agent/enroll", json={"token": token}).json()

    resp = client.post(
        "/api/agent/heartbeat",
        json={"agent_version": "1.0.0"},
        headers={"Authorization": f"Bearer {enrolled['api_token']}"},
    )
    assert resp.status_code == 204


def test_heartbeat_with_wrong_token_is_rejected(client) -> None:
    resp = client.post(
        "/api/agent/heartbeat", json={}, headers={"Authorization": "Bearer bogus"}
    )
    assert resp.status_code == 401


def test_desired_state_reports_exposed_and_consumed_grants(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    exposer_token = _make_admin_and_token(engine, "wb01")
    exposer = client.post("/api/agent/enroll", json={"token": exposer_token}).json()

    from frp_jump.server.db import make_session

    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="laptop", created_by=admin.id, ttl=_TTL
        )
    consumer_token = issued.token
    consumer = client.post("/api/agent/enroll", json={"token": consumer_token}).json()

    with make_session(engine) as db:
        service = registry.create_service(
            db,
            device_id=exposer["device_id"],
            name="wb01-ssh",
            protocol=ServiceProtocol.SSH,
            target_port=22,
        )
        registry.create_grant(
            db, service_id=service.id, consumer_device_id=consumer["device_id"]
        )

    exposer_state = client.get(
        "/api/agent/desired-state",
        headers={"Authorization": f"Bearer {exposer['api_token']}"},
    ).json()
    assert len(exposer_state["exposed"]) == 1
    assert exposer_state["exposed"][0]["service_name"] == "wb01-ssh"
    assert exposer_state["exposed"][0]["target_port"] == 22
    assert exposer_state["consumed"] == []

    consumer_state = client.get(
        "/api/agent/desired-state",
        headers={"Authorization": f"Bearer {consumer['api_token']}"},
    ).json()
    assert consumer_state["exposed"] == []
    assert len(consumer_state["consumed"]) == 1
    assert consumer_state["consumed"][0]["service_name"] == "wb01-ssh"
    assert consumer_state["consumed"][0]["protocol"] == "ssh"
    assert consumer_state["consumed"][0]["exposer_device_name"] == "wb01"
    assert consumer_state["consumed"][0]["secret"] == exposer_state["exposed"][0]["secret"]
