import base64
import datetime
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from frp_jump.common.pki import CertificateAuthority
from frp_jump.common.settings import Settings
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry
from frp_jump.server.app import create_app
from frp_jump.server.db import make_engine, make_session

_TTL = datetime.timedelta(hours=24)


def _generate_public_key() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "id"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            check=True,
            capture_output=True,
        )
        return key_path.with_suffix(".pub").read_text()


def _generate_keypair(dir_path: Path) -> tuple[Path, str]:
    """Like `_generate_public_key`, but keeps the private key around too,
    for tests that need to actually sign a challenge with it."""
    key_path = dir_path / "id"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
        check=True,
        capture_output=True,
    )
    return key_path, key_path.with_suffix(".pub").read_text()


# Two fixed identities, generated once -- most tests just need *some*
# owner and reuse "admin" across every `_make_admin_and_token` call within
# the same test (mirroring one real person enrolling several of their own
# devices); a few tests need a second, distinct owner ("friend").
_ADMIN_PUBLIC_KEY = _generate_public_key()
_FRIEND_PUBLIC_KEY = _generate_public_key()


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


def _get_or_create_admin(db) -> registry.User:
    admin = registry.get_user_by_label(db, "admin")
    if admin is None:
        admin = registry.create_user(db, public_key=_ADMIN_PUBLIC_KEY, label="admin")
    return admin


def _get_or_create_friend(db) -> registry.User:
    friend = registry.get_user_by_label(db, "friend")
    if friend is None:
        friend = registry.create_user(db, public_key=_FRIEND_PUBLIC_KEY, label="friend")
    return friend


def _make_admin_and_token(engine, device_name: str = "wb01") -> str:
    with make_session(engine) as db:
        admin = _get_or_create_admin(db)
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

    with make_session(engine) as db:
        admin = _get_or_create_admin(db)
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


def test_desired_state_is_empty_for_a_disabled_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    exposer_token = _make_admin_and_token(engine, "wb01")
    exposer = client.post("/api/agent/enroll", json={"token": exposer_token}).json()
    consumer_token = _make_admin_and_token(engine, "laptop")
    consumer = client.post("/api/agent/enroll", json={"token": consumer_token}).json()

    client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(consumer["api_token"]),
    )
    with make_session(engine) as db:
        registry.disable_device(db, exposer["device_id"])

    state = client.get(
        "/api/agent/desired-state", headers=_auth(exposer["api_token"])
    ).json()
    assert state["exposed"] == []
    consumer_state = client.get(
        "/api/agent/desired-state", headers=_auth(consumer["api_token"])
    ).json()
    assert consumer_state["consumed"] == []


def _auth(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


def test_enroll_nameless_token_requires_requested_name(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    with make_session(engine) as db:
        admin = _get_or_create_admin(db)
        issued = registry.create_enroll_token(db, created_by=admin.id, ttl=_TTL)

    resp = client.post("/api/agent/enroll", json={"token": issued.token})
    assert resp.status_code == 400


def test_enroll_nameless_token_with_requested_name_succeeds(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    with make_session(engine) as db:
        admin = _get_or_create_admin(db)
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

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = _get_or_create_friend(db)
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

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = _get_or_create_friend(db)
        issued = registry.create_enroll_token(
            db, device_name_hint="phone", created_by=friend.id, ttl=_TTL
        )
    client.post("/api/agent/enroll", json={"token": issued.token})

    resp = client.post("/api/agent/devices/phone/delete", headers=_auth(wb01["api_token"]))
    assert resp.status_code == 404


def test_disable_then_enable_a_device(client, app_ctx) -> None:
    """A device manages another of its owner's devices, not itself here --
    once *this* caller (laptop) disables wb01, wb01's own token can no
    longer act on mutating routes at all (see `get_enabled_device`), so
    re-enabling it has to come from an still-enabled device -- laptop."""
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    resp = client.post("/api/agent/devices/wb01/disable", headers=_auth(laptop["api_token"]))
    assert resp.status_code == 204
    devices = client.get("/api/agent/devices", headers=_auth(laptop["api_token"])).json()
    assert {d["name"]: d["enabled"] for d in devices}["wb01"] is False

    resp = client.post("/api/agent/devices/wb01/enable", headers=_auth(laptop["api_token"]))
    assert resp.status_code == 204
    devices = client.get("/api/agent/devices", headers=_auth(laptop["api_token"])).json()
    assert {d["name"]: d["enabled"] for d in devices}["wb01"] is True


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

    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})

    with make_session(engine) as db:
        friend = _get_or_create_friend(db)
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


def test_disconnect_as_a_different_owned_device(client, app_ctx) -> None:
    """`consumer_device_name` lets one of your devices tear down a
    connection actually made from another of your own devices."""
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()
    phone_token = _make_admin_and_token(engine, "phone")
    phone = client.post("/api/agent/enroll", json={"token": phone_token}).json()

    client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(laptop["api_token"]),
    )

    resp = client.post(
        "/api/agent/disconnect",
        json={"device_name": "wb01", "target_port": 22, "consumer_device_name": "laptop"},
        headers=_auth(phone["api_token"]),
    )
    assert resp.status_code == 204

    consumed = client.get(
        "/api/agent/desired-state", headers=_auth(laptop["api_token"])
    ).json()["consumed"]
    assert consumed == []


# --- fixes from the post-self-service Opus review --------------------------


def test_enroll_rejects_an_overlong_requested_name_before_signing_a_cert(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx
    with make_session(engine) as db:
        admin = _get_or_create_admin(db)
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

    body = {"device_name": "wb01", "target_port": 8080, "protocol": "tcp"}
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

    body = {"device_name": "wb01", "target_port": 8080, "protocol": "tcp"}
    resp = client.post("/api/agent/connect", json=body, headers=_auth(laptop["api_token"]))
    assert resp.json()["protocol"] == "tcp"


def test_connect_rejects_a_disabled_target_device(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    with make_session(engine) as db:
        registry.disable_device(db, wb01["device_id"])

    resp = client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(laptop["api_token"]),
    )
    assert resp.status_code == 400


def test_connect_rejects_from_a_disabled_caller_device(client, app_ctx) -> None:
    """A disabled device's token stops working for any mutating route at
    all (see `get_enabled_device`) -- connect included."""
    _app, engine, _ca = app_ctx

    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()

    with make_session(engine) as db:
        registry.disable_device(db, laptop["device_id"])

    resp = client.post(
        "/api/agent/connect",
        json={"device_name": "wb01", "target_port": 22, "protocol": "ssh"},
        headers=_auth(laptop["api_token"]),
    )
    assert resp.status_code == 403


def test_every_mutating_route_rejects_a_disabled_caller_device(client, app_ctx) -> None:
    """`get_enabled_device` must actually gate every one of these -- not
    just the one (`connect`) covered above."""
    _app, engine, _ca = app_ctx

    wb01_token = _make_admin_and_token(engine, "wb01")
    client.post("/api/agent/enroll", json={"token": wb01_token})
    laptop_token = _make_admin_and_token(engine, "laptop")
    laptop = client.post("/api/agent/enroll", json={"token": laptop_token}).json()
    headers = _auth(laptop["api_token"])

    with make_session(engine) as db:
        registry.disable_device(db, laptop["device_id"])

    requests = [
        ("post", "/api/agent/users/set-key/challenge", {"public_key": _generate_public_key()}),
        ("post", "/api/agent/devices/enroll-tokens", {"device_name_hint": None}),
        ("post", "/api/agent/devices/wb01/delete", None),
        ("post", "/api/agent/devices/wb01/disable", None),
        ("post", "/api/agent/devices/laptop/enable", None),
        (
            "post",
            "/api/agent/disconnect",
            {"device_name": "wb01", "target_port": 22, "consumer_device_name": None},
        ),
    ]
    for method, path, json_body in requests:
        resp = getattr(client, method)(path, json=json_body, headers=headers)
        assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}: {resp.text}"


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


def test_add_device_rejects_a_name_you_already_have(client, app_ctx) -> None:
    _app, engine, _ca = app_ctx

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    resp = client.post(
        "/api/agent/devices/enroll-tokens",
        json={"device_name_hint": "wb01"},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 400


def test_add_device_does_not_collide_across_different_owners(client, app_ctx) -> None:
    """Device names are unique only per-owner -- another owner already
    having "laptop" must not block you from adding your own."""
    _app, engine, _ca = app_ctx

    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    with make_session(engine) as db:
        friend = _get_or_create_friend(db)
        registry.create_enroll_token(
            db, device_name_hint="laptop", created_by=friend.id, ttl=_TTL
        )

    resp = client.post(
        "/api/agent/devices/enroll-tokens",
        json={"device_name_hint": "laptop"},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 200


# --- key-based enrollment + set-key ----------------------------------------


def test_enroll_challenge_then_by_key_creates_a_device(client, app_ctx) -> None:
    from frp_jump.common import ssh_signing

    _app, engine, _ca = app_ctx
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "id"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            check=True,
            capture_output=True,
        )
        public_key = key_path.with_suffix(".pub").read_text()

        with make_session(engine) as db:
            registry.create_user(db, public_key=public_key, label="alice")

        challenge_resp = client.post("/api/agent/enroll/challenge", json={"public_key": public_key})
        assert challenge_resp.status_code == 200
        challenge = challenge_resp.json()

        import base64

        signature = ssh_signing.sign(key_path, base64.b64decode(challenge["challenge"]))
        signature_b64 = base64.b64encode(signature).decode("ascii")

    resp = client.post(
        "/api/agent/enroll/by-key",
        json={
            "challenge_id": challenge["challenge_id"],
            "signature": signature_b64,
            "requested_name": "alices-laptop",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["device_name"] == "alices-laptop"


def test_enroll_challenge_always_succeeds_even_for_an_unregistered_key(client) -> None:
    """A 404-vs-200 split here would itself be an oracle for which keys
    the server knows about -- rejection only happens at /enroll/by-key,
    indistinguishable from a bad signature there."""
    resp = client.post(
        "/api/agent/enroll/challenge", json={"public_key": _generate_public_key()}
    )
    assert resp.status_code == 200
    assert resp.json()["challenge"]


def test_set_key_requires_proof_of_possession_of_the_new_key(client, app_ctx) -> None:
    """A bearer token alone must not be enough to repoint the account at
    an attacker-chosen key nobody has proven they hold."""
    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    new_public_key = _generate_public_key()
    resp = client.post(
        "/api/agent/users/set-key",
        json={"challenge_id": "nonexistent", "signature": "bm90IGEgcmVhbCBzaWc="},
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 400

    with make_session(engine) as db:
        admin = registry.get_user_by_label(db, "admin")
        assert admin.ssh_public_key.strip() != new_public_key.strip()


def test_set_key_rotates_the_callers_owner_key(client, app_ctx, tmp_path) -> None:
    from frp_jump.common import ssh_signing

    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    key_path, new_public_key = _generate_keypair(tmp_path)
    challenge_resp = client.post(
        "/api/agent/users/set-key/challenge",
        json={"public_key": new_public_key},
        headers=_auth(wb01["api_token"]),
    )
    assert challenge_resp.status_code == 200
    challenge = challenge_resp.json()

    signature = ssh_signing.sign(key_path, base64.b64decode(challenge["challenge"]))
    resp = client.post(
        "/api/agent/users/set-key",
        json={
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 204

    with make_session(engine) as db:
        admin = registry.get_user_by_label(db, "admin")
        assert admin.ssh_public_key.strip() == new_public_key.strip()


def test_set_key_rejects_a_signature_from_a_different_key_than_challenged(
    client, app_ctx, tmp_path
) -> None:
    from frp_jump.common import ssh_signing

    _app, engine, _ca = app_ctx
    wb01_token = _make_admin_and_token(engine, "wb01")
    wb01 = client.post("/api/agent/enroll", json={"token": wb01_token}).json()

    key_path, new_public_key = _generate_keypair(tmp_path)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_key_path, _ = _generate_keypair(other_dir)
    challenge_resp = client.post(
        "/api/agent/users/set-key/challenge",
        json={"public_key": new_public_key},
        headers=_auth(wb01["api_token"]),
    )
    challenge = challenge_resp.json()

    # Signed with a DIFFERENT key than the one the challenge was issued
    # for -- must not rotate to the challenged key regardless.
    signature = ssh_signing.sign(other_key_path, base64.b64decode(challenge["challenge"]))
    resp = client.post(
        "/api/agent/users/set-key",
        json={
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        headers=_auth(wb01["api_token"]),
    )
    assert resp.status_code == 400

    with make_session(engine) as db:
        admin = registry.get_user_by_label(db, "admin")
        assert admin.ssh_public_key.strip() != new_public_key.strip()
