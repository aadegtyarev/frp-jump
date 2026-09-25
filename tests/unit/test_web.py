import datetime

import pytest
from fastapi.testclient import TestClient

from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.driver.base import ServiceProtocol
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
    # https base_url: app_ctx's public_base_url is https, so the session
    # cookie is set Secure -- httpx's cookiejar (correctly) won't re-send a
    # Secure cookie to a plain http:// URL, so the test client must actually
    # be https to round-trip the session across requests like a real browser
    # would behind the documented TLS-terminating reverse proxy.
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def _admin_login_link(engine) -> str:
    with make_session(engine) as db:
        return auth.issue_login_token(db, email="admin@example.com", created_by=None, ttl=_TTL)


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


def test_session_cookie_is_secure_when_public_base_url_is_https_even_over_plain_http(
    app_ctx,
) -> None:
    """The documented deployment is a TLS-terminating reverse proxy -> plain
    HTTP to uvicorn, so `request.url.scheme` (plain "http" here, deliberately,
    unlike the `client` fixture) must not be the only signal -- public_base_url
    being https must be enough on its own."""
    app, engine, _ca = app_ctx
    http_client = TestClient(app, base_url="http://testserver", follow_redirects=False)
    token = _admin_login_link(engine)
    resp = http_client.get(f"/auth/{token}")
    set_cookie = resp.headers.get("set-cookie", "")
    assert "Secure" in set_cookie


def test_session_cookie_is_not_secure_when_neither_scheme_nor_public_url_is_https(
    tmp_path,
) -> None:
    settings = Settings(
        data_dir=tmp_path, relay_public_addr="relay.example.com", public_base_url=None
    )
    engine = make_engine(":memory:")
    ca = CertificateAuthority.bootstrap("test CA")
    app = create_app(settings=settings, engine=engine, ca=ca)
    plain_client = TestClient(app, follow_redirects=False)

    with make_session(engine) as db:
        token = auth.issue_login_token(db, email="admin@example.com", created_by=None, ttl=_TTL)
    resp = plain_client.get(f"/auth/{token}")
    set_cookie = resp.headers.get("set-cookie", "")
    assert "Secure" not in set_cookie


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
    assert "frp-jump-client enroll" in resp.text
    assert "wb01" in resp.text

    with make_session(engine) as db:
        assert registry.list_devices(db) == []  # not enrolled yet, just a token was minted


def test_create_enroll_token_without_a_name_defers_naming_to_the_client(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    resp = client.post("/devices/enroll-token", data={})
    assert resp.status_code == 200
    assert "--name" in resp.text


def test_create_enroll_token_for_a_friends_email_makes_them_the_owner(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    resp = client.post(
        "/devices/enroll-token",
        data={"device_name": "phone", "owner_email": "friend@example.com"},
    )
    assert resp.status_code == 200
    assert "friend@example.com" in resp.text

    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        issued_tokens = registry.list_pending_enroll_tokens(db)
    assert len(issued_tokens) == 1
    assert issued_tokens[0].owner_email == friend.email


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


def test_admin_can_revoke_a_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
    device_id = _enroll_device(engine, admin.id, "wb01")

    resp = client.post(f"/devices/{device_id}/revoke")
    assert resp.status_code == 303

    with make_session(engine) as db:
        device = registry.get_device(db, device_id)
        assert device.revoked_at is not None


def test_admin_can_delete_a_device_and_reenroll_the_name(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
    device_id = _enroll_device(engine, admin.id, "wb01")

    resp = client.post(f"/devices/{device_id}/delete")
    assert resp.status_code == 303
    with make_session(engine) as db:
        assert registry.get_device(db, device_id) is None

    # name is free again
    resp = client.post("/devices/enroll-token", data={"device_name": "wb01"})
    assert resp.status_code == 200
    assert "already" not in resp.text


def test_non_admin_session_cannot_reach_the_dashboard_or_mutate_anything(client, app_ctx) -> None:
    """A second user (e.g. one created as the owner of a friend's enroll
    token) never gets a WebUI session of their own -- but simulate one to
    confirm require_admin still blocks it as defense in depth."""
    _app, engine, _ca = app_ctx
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
        admin_id = admin.id
        registry.get_or_create_user(db, "friend@example.com")
    device_id = _enroll_device(engine, admin_id, "wb01")
    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        session_token = auth.create_session(db, friend, ttl=_TTL)
    friend_client = TestClient(client.app, base_url="https://testserver", follow_redirects=False)
    friend_client.cookies.set(SESSION_COOKIE, session_token)

    assert friend_client.get("/").status_code == 403
    sneaky = friend_client.post("/devices/enroll-token", data={"device_name": "sneaky"})
    assert sneaky.status_code == 403
    assert friend_client.post(f"/devices/{device_id}/revoke").status_code == 403
    assert friend_client.post(f"/devices/{device_id}/delete").status_code == 403
    with make_session(engine) as db:
        assert registry.list_devices(db) == [registry.get_device(db, device_id)]
        assert registry.get_device(db, device_id).revoked_at is None


def test_admin_can_revoke_a_grant(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
    exposer_id = _enroll_device(engine, admin.id, "wb01")
    consumer_id = _enroll_device(engine, admin.id, "laptop")
    with make_session(engine) as db:
        service = registry.create_service(
            db, device_id=exposer_id, name="wb01-ssh", protocol=ServiceProtocol.SSH, target_port=22
        )
        grant = registry.create_grant(db, service_id=service.id, consumer_device_id=consumer_id)

    resp = client.post(f"/grants/{grant.id}/revoke")
    assert resp.status_code == 303
    with make_session(engine) as db:
        assert registry.list_grants_view(db)[0].revoked is True


def test_revoked_device_is_rejected_by_the_agent_api(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )
        enrolled = registry.redeem_enroll_token(db, issued.token, cert_serial="1")

    resp = client.post(f"/devices/{enrolled.device.id}/revoke")
    assert resp.status_code == 303

    api_resp = client.post(
        "/api/agent/heartbeat",
        json={},
        headers={"Authorization": f"Bearer {enrolled.api_token}"},
    )
    assert api_resp.status_code == 401


def test_dashboard_shows_device_owner_and_users_table(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")
        admin_id = admin.id
        friend = registry.get_or_create_user(db, "friend@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
        registry.redeem_enroll_token(db, issued.token, cert_serial="1")
    _enroll_device(engine, admin_id, "wb01")

    resp = client.get("/")
    assert resp.status_code == 200
    assert "phone" in resp.text
    assert "friend@example.com" in resp.text
    assert "admin@example.com" in resp.text


def test_admin_can_delete_a_user_and_their_devices(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        friend_id = friend.id
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
        enrolled = registry.redeem_enroll_token(db, issued.token, cert_serial="1")
        device_id = enrolled.device.id

    resp = client.post(f"/users/{friend_id}/delete")
    assert resp.status_code == 303

    with make_session(engine) as db:
        assert registry.get_device(db, device_id) is None


def test_admin_cannot_delete_themself_as_the_only_admin(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com")

    resp = client.post(f"/users/{admin.id}/delete")
    assert resp.status_code == 200
    assert "only remaining admin" in resp.text


def test_admin_can_revoke_a_pending_enroll_token(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    client.get(f"/auth/{_admin_login_link(engine)}")
    client.post("/devices/enroll-token", data={"device_name": "wb01"})

    with make_session(engine) as db:
        (pending,) = registry.list_pending_enroll_tokens(db)

    resp = client.post(f"/enroll-tokens/{pending.id}/revoke")
    assert resp.status_code == 303

    with make_session(engine) as db:
        assert registry.list_pending_enroll_tokens(db) == []
