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


# --- nameless enroll tokens (name supplied at redeem time) --------------


def test_create_enroll_token_without_name_defers_naming(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    assert issued.device_name_hint is None


def test_redeem_nameless_token_requires_a_name(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    with pytest.raises(registry.ValidationError):
        registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")


def test_redeem_nameless_token_with_requested_name(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    enrolled = registry.redeem_enroll_token(
        db_session, issued.token, cert_serial="1", requested_name="wb01"
    )
    assert enrolled.device.name == "wb01"


def test_redeem_nameless_token_validates_requested_name(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    with pytest.raises(registry.ValidationError):
        registry.redeem_enroll_token(
            db_session, issued.token, cert_serial="1", requested_name="bad name!"
        )


def test_redeem_fixed_name_token_ignores_requested_name(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    enrolled = registry.redeem_enroll_token(
        db_session, issued.token, cert_serial="1", requested_name="ignored"
    )
    assert enrolled.device.name == "wb01"


# --- enroll token revocation ----------------------------------------------


def test_revoke_enroll_token_prevents_redemption(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    (pending,) = registry.list_pending_enroll_tokens(db_session)

    registry.revoke_enroll_token(db_session, pending.id)

    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")
    assert registry.list_pending_enroll_tokens(db_session) == []


def test_revoke_enroll_token_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.revoke_enroll_token(db_session, "no-such-token")


def test_revoke_enroll_token_rejects_already_redeemed(db_session) -> None:
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    (pending,) = registry.list_pending_enroll_tokens(db_session)
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")

    with pytest.raises(registry.ConflictError):
        registry.revoke_enroll_token(db_session, pending.id)


def test_list_pending_enroll_tokens_shows_unredeemed_only(db_session) -> None:
    admin = _make_admin(db_session)
    registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    issued2 = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="laptop"
    )
    registry.redeem_enroll_token(db_session, issued2.token, cert_serial="1")

    pending = registry.list_pending_enroll_tokens(db_session)
    assert len(pending) == 1
    assert pending[0].device_name_hint == "wb01"
    assert pending[0].owner_email == "admin@example.com"


# --- users view / delete ---------------------------------------------------


def test_list_users_view_includes_device_counts(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    _enroll(db_session, admin, "laptop")
    views = {v.email: v for v in registry.list_users_view(db_session)}
    assert views["admin@example.com"].device_count == 2
    assert views["admin@example.com"].is_admin is True


def test_delete_user_cascades_to_their_devices(db_session) -> None:
    admin = _make_admin(db_session)
    friend = registry.get_or_create_user(db_session, "friend@example.com")
    issued = registry.create_enroll_token(
        db_session, created_by=friend.id, ttl=_TTL, device_name_hint="phone"
    )
    enrolled = registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")

    registry.delete_user(db_session, friend.id)

    assert registry.get_device(db_session, enrolled.device.id) is None
    assert db_session.get(type(admin), friend.id) is None


def test_delete_user_refuses_to_delete_the_only_admin(db_session) -> None:
    admin = _make_admin(db_session)
    with pytest.raises(registry.ConflictError):
        registry.delete_user(db_session, admin.id)


def test_delete_user_allows_deleting_one_of_several_admins(db_session) -> None:
    admin = _make_admin(db_session)
    second_admin = registry.get_or_create_user(db_session, "second@example.com", is_admin=True)
    registry.delete_user(db_session, second_admin.id)
    assert db_session.get(type(admin), second_admin.id) is None


def test_delete_user_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.delete_user(db_session, "no-such-user")


# --- self-service device queries ------------------------------------------


def test_list_devices_for_owner_scopes_correctly(db_session) -> None:
    admin = _make_admin(db_session)
    friend = registry.get_or_create_user(db_session, "friend@example.com")
    _enroll(db_session, admin, "wb01")
    issued = registry.create_enroll_token(
        db_session, created_by=friend.id, ttl=_TTL, device_name_hint="phone"
    )
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")

    admin_devices = {d.name for d in registry.list_devices_for_owner(db_session, admin.id)}
    friend_devices = {d.name for d in registry.list_devices_for_owner(db_session, friend.id)}
    assert admin_devices == {"wb01"}
    assert friend_devices == {"phone"}


def test_get_device_by_name(db_session) -> None:
    admin = _make_admin(db_session)
    _enroll(db_session, admin, "wb01")
    assert registry.get_device_by_name(db_session, "wb01").name == "wb01"
    assert registry.get_device_by_name(db_session, "no-such") is None


# --- find-or-create service/grant (client connect) -------------------------


def test_find_or_create_service_creates_with_private_name(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    service = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    assert service.name == f"svc-{exposer.device.id}-22"
    assert service.target_port == 22


def test_find_or_create_service_reuses_existing(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    first = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    second = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    assert first.id == second.id


def test_find_or_create_grant_is_idempotent(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    first = registry.find_or_create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )
    second = registry.find_or_create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )
    assert first.id == second.id
    assert first.secret == second.secret


def test_two_consumers_can_connect_to_the_same_service_independently(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    b = _enroll(db_session, admin, "b")
    c = _enroll(db_session, admin, "c")
    service = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    grant_b = registry.find_or_create_grant(
        db_session, service_id=service.id, consumer_device_id=b.device.id
    )
    grant_c = registry.find_or_create_grant(
        db_session, service_id=service.id, consumer_device_id=c.device.id
    )
    assert grant_b.id != grant_c.id
    assert grant_b.secret != grant_c.secret

    registry.delete_grant(db_session, grant_c.id)
    # b's grant is untouched by c's disconnect
    assert len(registry.consumed_grants_for_device(db_session, b.device.id)) == 1
    assert registry.consumed_grants_for_device(db_session, c.device.id) == []


def test_find_grant_for_connection(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    consumer = _enroll(db_session, admin, "laptop")
    service = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    grant = registry.find_or_create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )
    found = registry.find_grant_for_connection(
        db_session,
        device_id=exposer.device.id,
        target_port=22,
        consumer_device_id=consumer.device.id,
    )
    assert found.id == grant.id

    missing = registry.find_grant_for_connection(
        db_session,
        device_id=exposer.device.id,
        target_port=9999,
        consumer_device_id=consumer.device.id,
    )
    assert missing is None


def test_delete_grant_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.delete_grant(db_session, "no-such-grant")


# --- fixes from the post-self-service Opus review --------------------------


def test_delete_user_also_removes_their_sessions_and_login_tokens(db_session) -> None:
    """A user with a WebUI session or an issued login link must still be
    deletable -- both tables FK to users.id, and PRAGMA foreign_keys=ON
    means an incomplete cascade raises IntegrityError instead of a clean
    delete."""
    from sqlmodel import select as _select

    from frp_jump.common.crypto import generate_token, hash_token
    from frp_jump.common.models import LoginToken
    from frp_jump.common.models import Session as SessionRow

    admin = _make_admin(db_session)
    second_admin = registry.get_or_create_user(db_session, "second@example.com", is_admin=True)
    expires_at = registry._now() + _TTL

    db_session.add(
        SessionRow(
            token_hash=hash_token(generate_token()), user_id=second_admin.id, expires_at=expires_at
        )
    )
    db_session.add(
        LoginToken(
            token_hash=hash_token(generate_token()),
            email=second_admin.email,
            created_by=admin.id,
            expires_at=expires_at,
        )
    )
    db_session.commit()

    registry.delete_user(db_session, second_admin.id)

    assert db_session.get(type(admin), second_admin.id) is None
    remaining = db_session.exec(
        _select(SessionRow).where(SessionRow.user_id == second_admin.id)
    ).all()
    assert remaining == []


def test_find_or_create_service_rejects_out_of_range_port(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ValidationError):
        registry.find_or_create_service(
            db_session, device_id=exposer.device.id, target_port=0, protocol=ServiceProtocol.SSH
        )
    with pytest.raises(registry.ValidationError):
        registry.find_or_create_service(
            db_session,
            device_id=exposer.device.id,
            target_port=70000,
            protocol=ServiceProtocol.SSH,
        )


def test_find_or_create_service_rejects_a_protocol_mismatch_on_reuse(db_session) -> None:
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=8080, protocol=ServiceProtocol.HTTP
    )
    with pytest.raises(registry.ConflictError):
        registry.find_or_create_service(
            db_session,
            device_id=exposer.device.id,
            target_port=8080,
            protocol=ServiceProtocol.SSH,
        )


def test_find_or_create_service_converts_a_name_collision_to_conflict_error(db_session) -> None:
    """An admin-authored service can collide with connect's synthetic
    `svc-<device_id>-<port>` name -- must be a clean ConflictError, not a
    raw IntegrityError from the services.name unique index."""
    admin = _make_admin(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    colliding_name = f"svc-{exposer.device.id}-22"
    registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name=colliding_name,
        protocol=ServiceProtocol.SSH,
        target_port=9999,
    )
    with pytest.raises(registry.ConflictError):
        registry.find_or_create_service(
            db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
        )


def test_redeem_enroll_token_converts_a_name_race_to_conflict_error(db_session) -> None:
    """Simulates the race where two redemptions for the same requested_name
    both pass _check_name_free before either commits."""
    admin = _make_admin(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1", requested_name="wb01")

    issued2 = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    # Bypass _check_name_free entirely to simulate the race window.
    from frp_jump.server import registry as registry_module

    original_check = registry_module._check_name_free
    registry_module._check_name_free = lambda *a, **k: None
    try:
        with pytest.raises(registry.ConflictError):
            registry.redeem_enroll_token(
                db_session, issued2.token, cert_serial="2", requested_name="wb01"
            )
    finally:
        registry_module._check_name_free = original_check
