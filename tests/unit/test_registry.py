import base64
import datetime
import itertools
import subprocess
import tempfile
from pathlib import Path

import pytest
import sqlalchemy

from frp_jump.common import ssh_signing
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry

_TTL = datetime.timedelta(hours=24)
_KEY_COUNTER = itertools.count()


def _make_keypair(tmp_path: Path) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    key_path = tmp_path / f"id-{next(_KEY_COUNTER)}"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
        check=True,
        capture_output=True,
    )
    return key_path, key_path.with_suffix(".pub").read_text()


def _make_user(db_session, label: str | None = None):
    """A registered user with a real, freshly-generated SSH keypair --
    most tests only need *a* user to own devices, so the private key
    itself is discarded; tests that need to actually sign something use
    `_make_user_with_key` instead."""
    with tempfile.TemporaryDirectory() as tmp:
        _, public_key = _make_keypair(Path(tmp))
    return registry.create_user(db_session, public_key=public_key, label=label)


def _make_user_with_key(db_session, tmp_path: Path, label: str | None = None):
    """Like `_make_user`, but also returns the private key path so the
    caller can sign a real challenge with it (`ssh_signing.sign`)."""
    key_path, public_key = _make_keypair(tmp_path)
    user = registry.create_user(db_session, public_key=public_key, label=label)
    return user, key_path


def _sign_challenge(key_path: Path, challenge_b64: str) -> str:
    signature = ssh_signing.sign(key_path, base64.b64decode(challenge_b64))
    return base64.b64encode(signature).decode("ascii")


def _enroll(db_session, admin, name: str) -> registry.EnrolledDevice:
    issued = registry.create_enroll_token(
        db_session, device_name_hint=name, created_by=admin.id, ttl=_TTL
    )
    return registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")


def test_create_user_generates_a_label_when_none_given(db_session) -> None:
    user = _make_user(db_session)
    assert user.label
    assert user.ssh_key_fingerprint.startswith("SHA256:")


def test_create_user_rejects_a_duplicate_key(db_session) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        _, public_key = _make_keypair(Path(tmp))
    registry.create_user(db_session, public_key=public_key, label="alice")
    with pytest.raises(registry.ConflictError):
        registry.create_user(db_session, public_key=public_key, label="alice2")


def test_create_user_rejects_a_duplicate_label(db_session) -> None:
    _make_user(db_session, label="alice")
    with pytest.raises(registry.ConflictError):
        _make_user(db_session, label="alice")


def test_set_user_key_rotates_the_fingerprint(db_session) -> None:
    user = _make_user(db_session)
    old_fingerprint = user.ssh_key_fingerprint
    with tempfile.TemporaryDirectory() as tmp:
        _, new_public_key = _make_keypair(Path(tmp))
    updated = registry.set_user_key(db_session, user.id, public_key=new_public_key)
    assert updated.ssh_key_fingerprint != old_fingerprint
    assert registry.get_user_by_fingerprint(db_session, old_fingerprint) is None


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
    admin = _make_user(db_session)
    with pytest.raises(registry.ValidationError):
        registry.create_enroll_token(
            db_session, device_name_hint=bad_name, created_by=admin.id, ttl=_TTL
        )


@pytest.mark.parametrize(
    "bad_name",
    ["wb01-ssh\nHost evil", "wb01 ssh", "", "a" * 64],
)
def test_create_service_rejects_dangerous_names(db_session, bad_name) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ConflictError):
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_create_enroll_token_rejects_duplicate_name_while_unredeemed_token_exists(
    db_session,
) -> None:
    admin = _make_user(db_session)
    registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    with pytest.raises(registry.ConflictError):
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_create_enroll_token_allows_reissue_after_the_first_is_redeemed(db_session) -> None:
    admin = _make_user(db_session)
    _enroll(db_session, admin, "wb01")
    with pytest.raises(registry.ConflictError):
        # already enrolled -- the *device* name check, not the token one
        registry.create_enroll_token(
            db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
        )


def test_redeem_enroll_token_creates_device_and_api_token(db_session) -> None:
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    assert enrolled.device.name == "wb01"
    assert enrolled.device.owner_user_id == admin.id
    found = registry.get_device_by_api_token(db_session, enrolled.api_token)
    assert found is not None
    assert found.id == enrolled.device.id


def test_redeem_enroll_token_cannot_be_reused(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")
    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_token(db_session, issued.token, cert_serial="2")


def test_peek_enroll_token_does_not_consume_it(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    _enroll(db_session, admin, "wb01")
    assert registry.get_device_by_api_token(db_session, "wrong") is None


def test_record_heartbeat_updates_last_seen_and_version(db_session) -> None:
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    assert enrolled.device.last_seen_at is None
    registry.record_heartbeat(db_session, enrolled.device, agent_version="1.2.3")
    assert enrolled.device.last_seen_at is not None
    assert enrolled.device.agent_version == "1.2.3"


def test_create_service_rejects_duplicate_name(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    consumer = _enroll(db_session, admin, "laptop")
    with pytest.raises(registry.NotFoundError):
        registry.create_grant(
            db_session, service_id="no-such-service", consumer_device_id=consumer.device.id
        )


def test_create_grant_rejects_nonexistent_consumer_device(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    _enroll(db_session, admin, "wb01")
    _enroll(db_session, admin, "laptop")
    names = {d.name for d in registry.list_devices(db_session)}
    assert names == {"wb01", "laptop"}


# --- disable/enable, delete ---------------------------------------------


def test_disable_device_marks_it_disabled(db_session) -> None:
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.disable_device(db_session, enrolled.device.id)
    device = registry.get_device(db_session, enrolled.device.id)
    assert device.enabled is False


def test_enable_device_reverses_disable(db_session) -> None:
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.disable_device(db_session, enrolled.device.id)
    registry.enable_device(db_session, enrolled.device.id)
    device = registry.get_device(db_session, enrolled.device.id)
    assert device.enabled is True


def test_disable_device_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.disable_device(db_session, "no-such-device")


def test_enable_device_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.enable_device(db_session, "no-such-device")


def test_get_device_by_api_token_still_authenticates_a_disabled_device(db_session) -> None:
    """Disabled != deleted -- the agent must keep authenticating so it can
    poll its way into noticing a later re-enable (see Device.enabled's
    docstring in common/models.py)."""
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")
    registry.disable_device(db_session, enrolled.device.id)
    found = registry.get_device_by_api_token(db_session, enrolled.api_token)
    assert found is not None
    assert found.id == enrolled.device.id


def test_delete_device_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.delete_device(db_session, "no-such-device")


def test_delete_device_frees_the_name_for_a_new_enrollment(db_session) -> None:
    admin = _make_user(db_session)
    enrolled = _enroll(db_session, admin, "wb01")

    # even disabled, the name stays blocked until actually deleted
    registry.disable_device(db_session, enrolled.device.id)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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


def test_delete_device_after_it_called_set_key_does_not_crash(db_session, tmp_path) -> None:
    """Regression test: KeyRotationChallenge.device_id is an enforced FK
    -- a device that ever redeemed (or even just started) a set-key
    challenge used to leave a dangling row and turn a later delete into
    an IntegrityError instead of a clean delete."""
    admin, current_key_path = _make_user_with_key(db_session, tmp_path / "current")
    laptop = _enroll(db_session, admin, "laptop")
    new_key_path, new_public_key = _make_keypair(tmp_path / "new")

    challenge = registry.create_key_rotation_challenge(
        db_session, device_id=laptop.device.id, public_key=new_public_key, ttl=_TTL
    )
    signature_b64 = _sign_challenge(new_key_path, challenge.challenge)
    current_signature_b64 = _sign_challenge(current_key_path, challenge.challenge)
    registry.redeem_key_rotation_challenge(
        db_session,
        challenge.id,
        signature_b64,
        current_signature_b64=current_signature_b64,
        device_id=laptop.device.id,
    )

    registry.delete_device(db_session, laptop.device.id)

    assert registry.get_device(db_session, laptop.device.id) is None


def test_delete_grant_removes_it_from_list_grants_view(db_session) -> None:
    admin = _make_user(db_session)
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
    registry.delete_grant(db_session, grant.id)
    assert registry.list_grants_view(db_session) == []


def test_deleted_grant_disappears_from_both_sides_desired_state(db_session) -> None:
    admin = _make_user(db_session)
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

    registry.delete_grant(db_session, grant.id)

    assert registry.exposed_grants_for_device(db_session, exposer.device.id) == []
    assert registry.consumed_grants_for_device(db_session, consumer.device.id) == []


def test_disabled_consumer_device_drops_out_of_exposer_view(db_session) -> None:
    """Disabling a device, not just a specific grant, should also stop the
    exposer from continuing to offer it that service."""
    admin = _make_user(db_session)
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

    registry.disable_device(db_session, consumer.device.id)

    assert registry.exposed_grants_for_device(db_session, exposer.device.id) == []


def test_disabled_exposer_device_drops_out_of_consumer_view(db_session) -> None:
    admin = _make_user(db_session)
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

    registry.disable_device(db_session, exposer.device.id)

    assert registry.consumed_grants_for_device(db_session, consumer.device.id) == []


# --- nameless enroll tokens (name supplied at redeem time) --------------


def test_create_enroll_token_without_name_defers_naming(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    assert issued.device_name_hint is None


def test_redeem_nameless_token_requires_a_name(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    with pytest.raises(registry.ValidationError):
        registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")


def test_redeem_nameless_token_with_requested_name(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    enrolled = registry.redeem_enroll_token(
        db_session, issued.token, cert_serial="1", requested_name="wb01"
    )
    assert enrolled.device.name == "wb01"


def test_redeem_nameless_token_validates_requested_name(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(db_session, created_by=admin.id, ttl=_TTL)
    with pytest.raises(registry.ValidationError):
        registry.redeem_enroll_token(
            db_session, issued.token, cert_serial="1", requested_name="bad name!"
        )


def test_redeem_fixed_name_token_ignores_requested_name(db_session) -> None:
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    enrolled = registry.redeem_enroll_token(
        db_session, issued.token, cert_serial="1", requested_name="ignored"
    )
    assert enrolled.device.name == "wb01"


# --- enroll token revocation ----------------------------------------------


def test_revoke_enroll_token_prevents_redemption(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=admin.id, ttl=_TTL, device_name_hint="wb01"
    )
    (pending,) = registry.list_pending_enroll_tokens(db_session)
    registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")

    with pytest.raises(registry.ConflictError):
        registry.revoke_enroll_token(db_session, pending.id)


def test_list_pending_enroll_tokens_shows_unredeemed_only(db_session) -> None:
    admin = _make_user(db_session)
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
    assert pending[0].owner_label == admin.label


# --- users view / delete ---------------------------------------------------


def test_list_users_view_includes_device_counts(db_session) -> None:
    admin = _make_user(db_session, label="admin")
    _enroll(db_session, admin, "wb01")
    _enroll(db_session, admin, "laptop")
    views = {v.label: v for v in registry.list_users_view(db_session)}
    assert views["admin"].device_count == 2
    assert views["admin"].fingerprint == admin.ssh_key_fingerprint


def test_delete_user_cascades_to_their_devices(db_session) -> None:
    admin = _make_user(db_session)
    friend = _make_user(db_session)
    issued = registry.create_enroll_token(
        db_session, created_by=friend.id, ttl=_TTL, device_name_hint="phone"
    )
    enrolled = registry.redeem_enroll_token(db_session, issued.token, cert_serial="1")

    registry.delete_user(db_session, friend.id)

    assert registry.get_device(db_session, enrolled.device.id) is None
    assert db_session.get(type(admin), friend.id) is None


def test_delete_user_does_not_affect_other_users(db_session) -> None:
    first = _make_user(db_session)
    second = _make_user(db_session)
    registry.delete_user(db_session, second.id)
    assert db_session.get(type(first), second.id) is None
    assert db_session.get(type(first), first.id) is not None


def test_delete_user_rejects_unknown_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.delete_user(db_session, "no-such-user")


# --- self-service device queries ------------------------------------------


def test_list_devices_for_owner_scopes_correctly(db_session) -> None:
    admin = _make_user(db_session)
    friend = _make_user(db_session)
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
    admin = _make_user(db_session)
    _enroll(db_session, admin, "wb01")
    assert registry.get_device_by_name(db_session, admin.id, "wb01").name == "wb01"
    assert registry.get_device_by_name(db_session, admin.id, "no-such") is None


def test_get_device_by_name_is_scoped_per_owner(db_session) -> None:
    """Two different owners may each name a device the same thing -- only
    the composite (owner, name) is unique."""
    admin = _make_user(db_session)
    friend = _make_user(db_session)
    admin_device = _enroll(db_session, admin, "laptop")
    friend_device = _enroll(db_session, friend, "laptop")

    found_admin = registry.get_device_by_name(db_session, admin.id, "laptop")
    found_friend = registry.get_device_by_name(db_session, friend.id, "laptop")
    assert found_admin.id == admin_device.device.id
    assert found_friend.id == friend_device.device.id
    # not visible under the wrong owner
    assert registry.get_device_by_name(db_session, friend.id, "not-friends") is None


# --- find-or-create service/grant (client connect) -------------------------


def test_find_or_create_service_creates_with_private_name(db_session) -> None:
    admin = _make_user(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    service = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    assert service.name == f"svc-{exposer.device.id}-22"
    assert service.target_port == 22


def test_find_or_create_service_reuses_existing(db_session) -> None:
    admin = _make_user(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    first = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    second = registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=22, protocol=ServiceProtocol.SSH
    )
    assert first.id == second.id


def test_find_or_create_grant_is_idempotent(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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


def test_find_or_create_service_rejects_out_of_range_port(db_session) -> None:
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
    exposer = _enroll(db_session, admin, "wb01")
    registry.find_or_create_service(
        db_session, device_id=exposer.device.id, target_port=8080, protocol=ServiceProtocol.TCP
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
    admin = _make_user(db_session)
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
    admin = _make_user(db_session)
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


# --- key-based enrollment (EnrollChallenge) --------------------------------


def test_create_enroll_challenge_succeeds_even_for_an_unregistered_key(db_session) -> None:
    """A 404-vs-200 split here would itself be an oracle for which keys
    the server knows about -- see registry.create_enroll_challenge's
    docstring. Rejection only happens at redeem time (below), where it's
    indistinguishable from a bad signature."""
    challenge = registry.create_enroll_challenge(db_session, fingerprint="SHA256:nope", ttl=_TTL)
    assert challenge.challenge


def test_redeem_enroll_challenge_rejects_an_unregistered_fingerprint_like_a_bad_signature(
    db_session, tmp_path
) -> None:
    challenge = registry.create_enroll_challenge(db_session, fingerprint="SHA256:nope", ttl=_TTL)
    key_path, _ = _make_keypair(tmp_path)
    signature_b64 = _sign_challenge(key_path, challenge.challenge)
    with pytest.raises(registry.ValidationError, match="signature verification failed"):
        registry.redeem_enroll_challenge(
            db_session, challenge.id, signature_b64, cert_serial="1", requested_name="wb01"
        )


def test_enroll_challenge_round_trip_creates_a_device(db_session, tmp_path) -> None:
    user, key_path = _make_user_with_key(db_session, tmp_path)
    challenge = registry.create_enroll_challenge(
        db_session, fingerprint=user.ssh_key_fingerprint, ttl=_TTL
    )
    signature_b64 = _sign_challenge(key_path, challenge.challenge)

    enrolled = registry.redeem_enroll_challenge(
        db_session,
        challenge.id,
        signature_b64,
        cert_serial="1",
        requested_name="wb01",
    )
    assert enrolled.device.name == "wb01"
    assert enrolled.device.owner_user_id == user.id


def test_peek_enroll_challenge_does_not_consume_it(db_session, tmp_path) -> None:
    user, key_path = _make_user_with_key(db_session, tmp_path)
    challenge = registry.create_enroll_challenge(
        db_session, fingerprint=user.ssh_key_fingerprint, ttl=_TTL
    )
    signature_b64 = _sign_challenge(key_path, challenge.challenge)

    peeked = registry.peek_enroll_challenge(db_session, challenge.id, signature_b64)
    assert peeked.id == user.id
    # still usable afterwards
    registry.redeem_enroll_challenge(
        db_session, challenge.id, signature_b64, cert_serial="1", requested_name="wb01"
    )


def test_redeem_enroll_challenge_cannot_be_reused(db_session, tmp_path) -> None:
    user, key_path = _make_user_with_key(db_session, tmp_path)
    challenge = registry.create_enroll_challenge(
        db_session, fingerprint=user.ssh_key_fingerprint, ttl=_TTL
    )
    signature_b64 = _sign_challenge(key_path, challenge.challenge)
    registry.redeem_enroll_challenge(
        db_session, challenge.id, signature_b64, cert_serial="1", requested_name="wb01"
    )
    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_challenge(
            db_session, challenge.id, signature_b64, cert_serial="2", requested_name="wb02"
        )


def test_redeem_enroll_challenge_rejects_a_signature_from_the_wrong_key(
    db_session, tmp_path
) -> None:
    user, _ = _make_user_with_key(db_session, tmp_path)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    _, other_key_path = _make_user_with_key(db_session, other_dir, label="other")
    challenge = registry.create_enroll_challenge(
        db_session, fingerprint=user.ssh_key_fingerprint, ttl=_TTL
    )
    wrong_signature_b64 = _sign_challenge(other_key_path, challenge.challenge)
    with pytest.raises(registry.ValidationError):
        registry.redeem_enroll_challenge(
            db_session, challenge.id, wrong_signature_b64, cert_serial="1", requested_name="wb01"
        )


def test_redeem_enroll_challenge_rejects_unknown_challenge_id(db_session) -> None:
    with pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_challenge(
            db_session, "no-such-challenge", "sig", cert_serial="1", requested_name="wb01"
        )
