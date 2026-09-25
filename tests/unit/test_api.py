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


def _auth(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


def test_enroll_nameless_token_requires_requested_name(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com", is_admin=True)
        issued = registry.create_enroll_token(db, created_by=admin.id, ttl=_TTL)

    resp = client.post("/api/agent/enroll", json={"token": issued.token})
    assert resp.status_code == 400


def test_enroll_nameless_token_with_requested_name_succeeds(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com", is_admin=True)
        issued = registry.create_enroll_token(db, created_by=admin.id, ttl=_TTL)

    resp = client.post(
        "/api/agent/enroll", json={"token": issued.token, "requested_name": "wb01"}
    )
    assert resp.status_code == 200
    assert resp.json()["device_name"] == "wb01"


def test_add_device_mints_a_token_owned_by_the_same_user(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": token}).json()

    resp = client.post(
        "/api/agent/devices/enroll-tokens",
        json={"device_name_hint": "laptop"},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 200
    new_token = resp.json()["token"]

    laptop = client.post("/api/agent/enroll", json={"token": new_token}).json()

    devices = client.get("/api/agent/devices", headers=_auth(wb01["api_token"])).json()
    names = {d["name"] for d in devices}
    assert names == {"wb01", "laptop"}
    assert laptop["device_name"] == "laptop"


def test_list_devices_only_shows_the_same_owners_devices(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
    phone = client.post("/api/agent/enroll", json={"token": issued.token}).json()

    devices = client.get("/api/agent/devices", headers=_auth(wb01["api_token"])).json()
    assert {d["name"] for d in devices} == {"wb01"}
    devices = client.get("/api/agent/devices", headers=_auth(phone["api_token"])).json()
    assert {d["name"] for d in devices} == {"phone"}


def test_delete_device_removes_your_own_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()
    laptop_token = _make_admin_and_token(engine, "laptop")
    client.post("/api/agent/enroll", json={"token": laptop_token})

    resp = client.post("/api/agent/devices/laptop/delete", headers=_auth(wb01["api_token"]))
    assert resp.status_code == 204

    devices = client.get("/api/agent/devices", headers=_auth(wb01["api_token"])).json()
    assert {d["name"] for d in devices} == {"wb01"}


def test_delete_device_rejects_someone_elses_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
    client.post("/api/agent/enroll", json={"token": issued.token})

    resp = client.post("/api/agent/devices/phone/delete", headers=_auth(wb01["api_token"]))
    assert resp.status_code == 404


def test_connect_creates_a_grant_and_is_idempotent(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    body = {"device_name": "wb01", "target_port": 22, "protocol": "ssh"}
    first = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert first.status_code == 200
    assert first.json()["exposer_device_name"] == "wb01"
    second = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert second.status_code == 200
    assert second.json()["grant_id"] == first.json()["grant_id"]

    consumed = client.get(
        "/api/agent/desired-state", headers=_auth(laptop["api_token"])
    ).json()["consumed"]
    assert len(consumed) == 1
    assert consumed[0]["exposer_device_name"] == "wb01"


def test_connect_rejects_a_device_you_do_not_own(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})

    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
    phone = client.post("/api/agent/enroll", json={"token": issued.token}).json()

    resp = client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(phone["api_token"]),
    )
    assert resp.status_code == 404


def test_disconnect_removes_an_existing_connection(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    body = {"device_name": "wb01", "target_port": 22, "protocol": "ssh"}
    client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))

    resp = client.post(
        "/api/agent/disconnect",
        json={"device_name": "wb01", "target_port": 22},
        headers=_auth(laptop["api_token"]),
    )
    assert resp.status_code == 204

    consumed = client.get(
        "/api/agent/desired-state", headers=_auth(laptop["api_token"])
    ).json()["consumed"]
    assert consumed == []


def test_disconnect_rejects_a_connection_that_does_not_exist(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    resp = client.post(
        "/api/agent/disconnect",
        json={"device_name": "wb01", "target_port": 22},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 404


# --- fixes from the post-self-service Opus review --------------------------


def test_enroll_rejects_an_overlong_requested_name_before_signing_a_cert(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    with make_session(engine) as db:
        admin = registry.get_or_create_user(db, "admin@example.com", is_admin=True)
        issued = registry.create_enroll_token(db, created_by=admin.id, ttl=_TTL)

    resp = client.post(
        "/api/agent/enroll", json={"token": issued.token, "requested_name": "a" * 100}
    )
    assert resp.status_code == 400


def test_connect_rejects_an_out_of_range_port(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    for bad_port in (0, -1, 70000):
        resp = client.post(
            "/api/agent/connect",
            json={"device_name": "wb01", "target_port": bad_port, "protocol": "ssh"},
            headers=_auth(laptop["api_token"]),
        )
        assert resp.status_code == 422, bad_port


def test_connect_rejects_a_protocol_mismatch_with_an_existing_connection(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    body = {"device_name": "wb01", "target_port": 8080, "protocol": "http"}
    first = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert first.status_code == 200

    body["protocol"] = "ssh"
    second = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert second.status_code == 400


def test_connect_response_protocol_matches_the_actual_service(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    body = {"device_name": "wb01", "target_port": 8080, "protocol": "http"}
    resp = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert resp.json()["protocol"] == "http"


def test_connect_rejects_a_revoked_target_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    with make_session(engine) as db:
        registry.revoke_device(db, wb01["device_id"])

    resp = client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(laptop["api_token"]),
    )
    assert resp.status_code == 404


def test_connect_rejects_connecting_a_device_to_itself(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    resp = client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 400


def test_add_device_conflict_message_does_not_leak_who_owns_the_name(client, app_ctx) -> None:
    """A same-owner conflict and a cross-owner conflict must be
    indistinguishable from the response -- otherwise any device can probe
    whether a name belongs to someone else's account."""
    _app, engine, _ca = app_ctx
    from frp_jump.server.db import make_session

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = registry.get_or_create_user(db, "friend@example.com")
        registry.create_enroll_token(
            db, device_name_hint="bobs-secret-laptop", created_by=friend.id, ttl=_TTL
        )

    resp = client.post(
        "/api/agent/devices/enroll-tokens",
        json={"device_name_hint": "bobs-secret-laptop"},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 400
    assert "bobs-secret-laptop" not in resp.text
    assert "already" not in resp.text.lower()
