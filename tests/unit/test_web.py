import datetime

import pytest
from fastapi.testclient import TestClient

from frp_jump.common.models import TokenPurpose
from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.server import auth, registry
from frp_jump.server.app import create_app
from frp_jump.server.db import make_engine, make_session
from frp_jump.server.web import SESSION_COOKIE

_TTL = datetime.timedelta(hours=1)


@pytest.fixture
def app_ctx(tmp_path):
    settings = Settings(
        data_dir=tmp_path,
        relay_public_addr="relay.example.com",
        relay_bind_port=7000,
        public_base_url="https://tunnel.example.com",
    )
    engine = make_engine(":memory:")
    ca = CertificateAuthority.bootstrap("test CA")
    app = create_app(settings=settings, engine=engine, ca=ca)
    return app, engine, ca


@pytest.fixture
def client(app_ctx):
    app, _engine, _ca = app_ctx
    return TestClient(app, follow_redirects=False)


def _admin_login_link(engine) -> str:
    with make_session(engine) as db:
        return auth.issue_login_token(
            db, email="admin@example.com", purpose=TokenPurpose.LOGIN, created_by=None, ttl=_TTL
        )


def test_dashboard_redirects_to_login_when_unauthenticated(client) -> None:
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_visiting_login_link_sets_session_cookie_and_redirects(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _admin_login_link(engine)
    resp = client.get(f"/auth/{token}")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert SESSION_COOKIE in resp.cookies


def test_invalid_login_link_shows_error_without_setting_cookie(client) -> None:
    resp = client.get("/auth/not-a-real-token")
    assert resp.status_code == 200
    assert SESSION_COOKIE not in resp.cookies
    assert "unknown login link" in resp.text


def test_dashboard_accessible_after_login(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _admin_login_link(engine)
    client.get(f"/auth/{token}")
    resp = client.get("/")
    assert resp.status_code == 200
    assert "admin@example.com" in resp.text


def test_logout_clears_session(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _admin_login_link(engine)
    client.get(f"/auth/{token}")
    client.post("/logout")
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_create_enroll_token_shows_command_once(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    resp = client.post("/devices/enroll-token", data={"device_name": "wb01"})
    assert resp.status_code == 200
    assert "frp-jump client enroll" in resp.text
    assert "wb01" in resp.text

    with make_session(engine) as db:
        assert registry.list_devices(db) == []  # not enrolled yet, just a token was minted


def test_duplicate_device_name_shows_error(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    client.post("/devices/enroll-token", data={"device_name": "wb01"})
    resp = client.post("/devices/enroll-token", data={"device_name": "wb01"})
    assert resp.status_code == 200
    assert "already exists" in resp.text


def _enroll_device(engine, admin_id: str, name: str) -> str:
    with make_session(engine) as db:
        issued = registry.create_enroll_token(
            db, device_name_hint=name, created_by=admin_id, ttl=_TTL
        )
        enrolled = registry.redeem_enroll_token(db, issued.token, cert_serial="1")
        return enrolled.device.id


def test_add_service_and_grant_end_to_end(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")

    exposer_id = _enroll_device(engine, admin.id, "wb01")
    consumer_id = _enroll_device(engine, admin.id, "laptop")

    resp = client.post(
        "/services",
        data={"device_id": exposer_id, "name": "wb01-ssh", "protocol": "ssh", "target_port": "22"},
    )
    assert resp.status_code == 303

    with make_session(engine) as db:
        services = registry.list_services_view(db)
    assert len(services) == 1
    service_id = services[0].id

    resp = client.post(
        "/grants", data={"service_id": service_id, "consumer_device_id": consumer_id}
    )
    assert resp.status_code == 303

    with make_session(engine) as db:
        grants = registry.list_grants_view(db)
    assert len(grants) == 1
    assert grants[0].consumer_device_name == "laptop"

    dashboard = client.get("/")
    assert "wb01-ssh" in dashboard.text
    assert "laptop" in dashboard.text


def test_admin_can_invite(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    resp = client.post("/users/invite", data={"email": "friend@example.com"})
    assert resp.status_code == 200
    assert "https://tunnel.example.com/auth/" in resp.text


def test_non_admin_cannot_invite(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    # first user becomes admin; enroll a second, non-admin user via an invite token
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        invite_token = auth.issue_login_token(
            db,
            email="friend@example.com",
            purpose=TokenPurpose.INVITE,
            created_by=None,
            ttl=_TTL,
        )
    friend_client = TestClient(client.app, follow_redirects=False)
    friend_client.get(f"/auth/{invite_token}")
    resp = friend_client.post("/users/invite", data={"email": "third@example.com"})
    assert resp.status_code == 200
    assert "only an admin can invite" in resp.text
