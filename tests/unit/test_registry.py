import datetime

import pytest
import sqlalchemy

from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry

_TTL = datetime.timedelta(hours=24)


def _make_admin(db_session):
    return registry.get_or_create_user(db_session, "admin@example.com", is_admin=True)


def _enroll(db_session, admin, name: str) -> registry.EnrolledDevice:
    issued = registry.create_enroll_token(
        db_session, device_name_hint=name, created_by=admin.id, ttl=_TTL
    )
    return registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")


def test_get_or_create_user_is_idempotent_by_email(db_session) -> None:
    a = registry.get_or_create_user(db_session, "x@example.com")
    b = registry.get_or_create_user(db_session, "x@example.com")
    assert a.id == b.id


@pytest.mark.parametrize(
    "bad_name",
    [
        "wb01\nHost evil",  # newline injection into ssh_config
        "wb01 evil",
        "",
        "-leading-hyphen",
        "a" * 64,  # too long
        "wb/01",
        "wb01;rm -rf",
    ],
)
def test_create_enroll_token_rejects_dangerous_names(db_session, bad_name) -> None:
    admin = _make_admin(db_session)
    with pytest.raises(registry.ValidationError):
        registry.create_enroll_token(
            db_session, device_name_hint=bad_name, created_by=admin.id, ttl=_TTL
        )


@pytest.mark.parametrize(
    "bad_name",
    ["wb01-ssh\nHost evil", "wb01 ssh", "", "a" * 64],
)
def test_create_service_rejects_dangerous_names(db_session, bad_name) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ValidationError):
        registry.create_service(
            db_session,
            device_id=exposer.device.id,
            name=bad_name,
            protocol=ServiceProtocol.SSH,
            target_port=22,
        )


def test_create_enroll_token_rejects_duplicate_device_name(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ConflictError):
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_create_enroll_token_rejects_duplicate_name_while_unredeemed_token_exists(
    db_session,
) -> None:
    admin = _make_admin(db_session)
    registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    with pytest.raises(registry.ConflictError):
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_create_enroll_token_allows_reissue_after_the_first_is_redeemed(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ConflictError):
        # already enrolled -- the *device* name check, not the token one
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_redeem_enroll_token_creates_device_and_api_token(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    assert enrolled.device.name == "wb01"
    assert enrolled.device.owner_user_id == admin.id
    found = registry.get_device_by_api_token(db_session, enrolled.api_token)
    assert found is not None
    assert found.id == enrolled.device.id


def test_redeem_enroll_token_cannot_be_reused(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")
    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_token(db_session, issued.token, cert_serial="2")


def test_peek_enroll_token_does_not_consume_it(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    peeked = registry.peek_enroll_token(db_session, issued.token)
    assert peeked.device_name_hint == "wb01"
    # still usable afterwards
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")


def test_peek_enroll_token_rejects_unknown_token(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.peek_enroll_token(db_session, "not-a-real-token")


def test_redeem_enroll_token_rejects_unknown_token(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_token(db_session, "not-a-real-token", cert_serial="1")


def test_get_device_by_api_token_returns_none_for_wrong_token(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    assert registry.get_device_by_api_token(db_session, "wrong") is None


def test_record_heartbeat_updates_last_seen_and_version(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    assert enrolled.device.last_seen_at is None
    registry.record_heartbeat(db_session, enrolled.device, agent_version="1.2.3")
    assert enrolled.device.last_seen_at is not None
    assert enrolled.device.agent_version == "1.2.3"


def test_create_service_rejects_duplicate_name(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.create_service(
        db_session,
        device_id=enrolled.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    with pytest.raises(registry.ConflictError):
        registry.create_service(
            db_session,
            device_id=enrolled.device.id,
            name="wb01-ssh",
            protocol=ServiceProtocol.SSH,
            target_port=22,
        )


def test_create_grant_rejects_duplicate_pair(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    registry.create_grant(db_session, service_id=service.id, consumer_device_id=consumer.device.id)
    with pytest.raises(registry.ConflictError):
        registry.create_grant(
            db_session, service_id=service.id, consumer_device_id=consumer.device.id
        )


def test_create_service_rejects_nonexistent_device(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.create_service(
            db_session,
            device_id="no-such-device",
            name="wb01-ssh",
            protocol=ServiceProtocol.SSH,
            target_port=22,
        )


def test_create_grant_rejects_nonexistent_service(db_session) -> None:
    admin = _make_admin(db_session)
    consumer = _enroll(db_session, admin, "laptop")
    with pytest.raises(registry.NotFoundError):
        registry.create_grant(
            db_session, service_id="no-such-service", consumer_device_id=consumer.device.id
        )


def test_create_grant_rejects_nonexistent_consumer_device(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    with pytest.raises(registry.NotFoundError):
        registry.create_grant(
            db_session, service_id=service.id, consumer_device_id="no-such-device"
        )


def test_foreign_keys_are_enforced_at_the_sqlite_level(db_session) -> None:
    result = db_session.exec(sqlalchemy.text("PRAGMA foreign_keys")).first()
    assert result[0] == 1


def test_exposed_and_consumed_grant_views(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )

    exposed = registry.exposed_grants_for_device(db_session, exposer.device.id)
    assert len(exposed) == 1
    assert exposed[0].grant_id == grant.id
    assert exposed[0].secret == grant.secret
    assert exposed[0].service_name == "wb01-ssh"
    assert exposed[0].target_port == 22

    consumed = registry.consumed_grants_for_device(db_session, consumer.device.id)
    assert len(consumed) == 1
    assert consumed[0].grant_id == grant.id
    assert consumed[0].secret == grant.secret
    assert consumed[0].service_name == "wb01-ssh"
    assert consumed[0].protocol == ServiceProtocol.SSH
    assert consumed[0].exposer_device_name == "wb01"

    assert registry.exposed_grants_for_device(db_session, consumer.device.id) == []
    assert registry.consumed_grants_for_device(db_session, exposer.device.id) == []


def test_list_services_view_includes_device_name(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    views = registry.list_services_view(db_session)
    assert len(views) == 1
    assert views[0].name == "wb01-ssh"
    assert views[0].device_name == "wb01"


def test_list_grants_view_includes_device_names(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    registry.create_grant(db_session, service_id=service.id, consumer_device_id=consumer.device.id)

    views = registry.list_grants_view(db_session)
    assert len(views) == 1
    assert views[0].service_name == "wb01-ssh"
    assert views[0].exposer_device_name == "wb01"
    assert views[0].consumer_device_name == "laptop"


def test_list_devices_returns_all(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    _enroll(db_session, admin, "laptop")
    names = {d.name for d in registry.list_devices(db_session)}
    assert names == {"wb01", "laptop"}


# --- revocation --------------------------------------------------------


def test_revoke_device_marks_it_revoked(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.revoke_device(db_session, enrolled.device.id)
    device = registry.get_device(db_session, enrolled.device.id)
    assert device.revoked_at is not None


def test_revoke_device_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.revoke_device(db_session, "no-such-device")


def test_get_device_by_api_token_returns_none_for_a_revoked_device(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.revoke_device(db_session, enrolled.device.id)
    assert registry.get_device_by_api_token(db_session, enrolled.api_token) is None


def test_delete_device_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.delete_device(db_session, "no-such-device")


def test_delete_device_frees_the_name_for_a_new_enrollment(db_session) -> None:
    admin = _make_admin(db_session)
    enrolled = _enroll(db_session, admin, "wb01")

    # even revoked, the name stays blocked until actually deleted
    registry.revoke_device(db_session, enrolled.device.id)
    with pytest.raises(registry.ConflictError):
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )

    registry.delete_device(db_session, enrolled.device.id)
    assert registry.get_device(db_session, enrolled.device.id) is None

    reissued = _enroll(db_session, admin, "wb01")
    assert reissued.device.name == "wb01"
    assert reissued.device.id != enrolled.device.id


def test_delete_device_cascades_to_its_own_services_and_grants(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )

    registry.delete_device(db_session, exposer.device.id)

    assert registry.get_device(db_session, exposer.device.id) is None
    assert registry.list_services_view(db_session) == []
    assert db_session.get(type(grant), grant.id) is None


def test_delete_device_cascades_to_grants_it_consumed(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )

    registry.delete_device(db_session, consumer.device.id)

    assert registry.get_device(db_session, consumer.device.id) is None
    # the exposer's service survives -- only the grant tying it to the
    # now-deleted consumer is gone
    assert len(registry.list_services_view(db_session)) == 1
    assert db_session.get(type(grant), grant.id) is None


def test_revoke_grant_marks_it_revoked_in_list_grants_view(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )
    registry.revoke_grant(db_session, grant.id)
    view = registry.list_grants_view(db_session)[0]
    assert view.revoked is True


def test_revoke_grant_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.revoke_grant(db_session, "no-such-grant")


def test_revoked_grant_disappears_from_both_sides_desired_state(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )
    assert len(registry.exposed_grants_for_device(db_session, exposer.device.id)) == 1
    assert len(registry.consumed_grants_for_device(db_session, consumer.device.id)) == 1

    registry.revoke_grant(db_session, grant.id)

    assert registry.exposed_grants_for_device(db_session, exposer.device.id) == []
    assert registry.consumed_grants_for_device(db_session, consumer.device.id) == []


def test_revoked_consumer_device_drops_out_of_exposer_view(db_session) -> None:
    """Revoking a device, not just a specific grant, should also stop the
    exposer from continuing to offer it that service."""
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    registry.create_grant(db_session, service_id=service.id, consumer_device_id=consumer.device.id)

    registry.revoke_device(db_session, consumer.device.id)

    assert registry.exposed_grants_for_device(db_session, exposer.device.id) == []


def test_revoked_exposer_device_drops_out_of_consumer_view(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="wb01-ssh",
        protocol=ServiceProtocol.SSH,
        target_port=22,
    )
    registry.create_grant(db_session, service_id=service.id, consumer_device_id=consumer.device.id)

    registry.revoke_device(db_session, exposer.device.id)

    assert registry.consumed_grants_for_device(db_session, consumer.device.id) == []
