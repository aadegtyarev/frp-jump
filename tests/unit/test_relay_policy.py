import pytest

from frp_jump.common.crypto import hash_token
from frp_jump.common.models import Device, User
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry
from frp_jump.server.relay_policy import authorize


def topology(db):
    user = User(label="owner", ssh_public_key="unused", ssh_key_fingerprint="unused")
    db.add(user)
    db.commit()
    devices = []
    for name in ("exposer", "consumer", "stranger"):
        d = Device(name=name, owner_user_id=user.id, cert_serial=name,
                   api_token_hash=hash_token(name + "-token"))
        db.add(d)
        db.commit()
        db.refresh(d)
        devices.append(d)
    service = registry.create_service(
        db, device_id=devices[0].id, name="ssh", protocol=ServiceProtocol.SSH, target_port=22
    )
    grant = registry.create_grant(db, service_id=service.id, consumer_device_id=devices[1].id)
    return devices, grant


def identity(device):
    return {"metas": {"frp_jump_device": device.id, "frp_jump_token": device.name + "-token"}}


def proxy(device, grant, **changes):
    return {"user": identity(device), "proxy_type": "stcp",
            "proxy_name": grant.id + "-stcp", "sk": grant.secret,
            "use_encryption": True, **changes}


def test_strict_login_assigns_identity_and_replaces_untrusted_run_id(db_session):
    devices, _ = topology(db_session)
    request = {**identity(devices[0]), "user": "forged", "run_id": "stolen"}
    result = authorize(db_session, "Login", request, require_device_auth=True)
    assert not result["reject"]
    assert result["content"]["user"] == devices[0].id
    assert result["content"]["run_id"] != "stolen"
    assert authorize(db_session, "Login", {}, require_device_auth=True)["reject"]
    assert not authorize(db_session, "Login", {}, require_device_auth=False)["reject"]


@pytest.mark.parametrize("changes", [
    {"proxy_type": "tcp"}, {"proxy_type": "udp"}, {"proxy_type": "http"},
    {"proxy_name": "unknown-stcp"}, {"sk": "wrong"}, {"use_encryption": False},
    {"remote_port": 12345}, {"group": "shared"},
])
def test_unapproved_proxies_rejected_in_both_modes(db_session, changes):
    devices, grant = topology(db_session)
    for strict in (False, True):
        assert authorize(db_session, "NewProxy", proxy(devices[0], grant, **changes),
                         require_device_auth=strict)["reject"]


def test_grant_is_bound_to_exposer_and_consumer(db_session):
    devices, grant = topology(db_session)
    result = authorize(db_session, "NewProxy", proxy(devices[0], grant),
                       require_device_auth=True)
    assert not result["reject"]
    assert result["content"]["allow_users"] == [devices[1].id]
    for other in devices[1:]:
        assert authorize(db_session, "NewProxy", proxy(other, grant),
                         require_device_auth=True)["reject"]


def test_revoked_device_and_grant_are_rejected(db_session):
    devices, grant = topology(db_session)
    request = proxy(devices[0], grant)
    registry.disable_device(db_session, devices[1].id)
    assert authorize(db_session, "NewUserConn", request, require_device_auth=True)["reject"]
    assert authorize(db_session, "Login", identity(devices[1]),
                     require_device_auth=True)["reject"]
    registry.enable_device(db_session, devices[1].id)
    assert not authorize(db_session, "NewUserConn", request,
                         require_device_auth=True)["reject"]
    registry.delete_device(db_session, devices[1].id)
    assert authorize(db_session, "NewUserConn", request, require_device_auth=True)["reject"]
    assert authorize(db_session, "Ping", {"user": identity(devices[1])},
                     require_device_auth=True)["reject"]
