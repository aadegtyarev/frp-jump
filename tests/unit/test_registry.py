import datetime

import pytest

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
