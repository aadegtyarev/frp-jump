"""Regression checks for enrollment eviction and credential transport."""

import base64
import datetime
import subprocess
from pathlib import Path

import httpx
import pytest
from sqlmodel import select

from frp_jump.agent import enroll, poller
from frp_jump.agent.state import AgentState
from frp_jump.common import ssh_signing
from frp_jump.common.api import ControlURLValueError, require_https_url
from frp_jump.common.models import EnrollChallenge
from frp_jump.server import registry
from frp_jump.server.db import make_engine, make_session


def keypair(tmp_path):
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    return key, key.with_suffix(".pub").read_text()


def signature(key, challenge):
    return base64.b64encode(
        ssh_signing.sign(key, base64.b64decode(challenge.challenge))
    ).decode()


def test_anonymous_challenges_cannot_evict_pending_enrollment(db_session, tmp_path):
    key, public = keypair(tmp_path)
    user = registry.create_user(db_session, public_key=public)
    issued = [
        registry.create_enroll_challenge(
            db_session, fingerprint=user.ssh_key_fingerprint, ttl=datetime.timedelta(minutes=2)
        )
        for _ in range(30)
    ]
    # No pending rows, even when an attacker varies the public key.
    registry.create_enroll_challenge(
        db_session, fingerprint="SHA256:unknown", ttl=datetime.timedelta(minutes=2)
    )
    assert list(db_session.exec(select(EnrollChallenge))) == []
    # Both early and late requests remain usable independently.
    for i, challenge in enumerate((issued[0], issued[-1])):
        registry.redeem_enroll_challenge(
            db_session, challenge.id, signature(key, challenge),
            cert_serial=str(i), requested_name=f"device-{i}",
        )
    assert len(list(db_session.exec(select(EnrollChallenge)))) == 2


def test_challenge_survives_engine_restart_and_replay_is_rejected(tmp_path):
    key, public = keypair(tmp_path)
    path = tmp_path / "db.sqlite3"
    engine = make_engine(path)
    with make_session(engine) as db:
        user = registry.create_user(db, public_key=public)
        challenge = registry.create_enroll_challenge(
            db, fingerprint=user.ssh_key_fingerprint, ttl=datetime.timedelta(minutes=2)
        )
    engine.dispose()
    engine = make_engine(path)
    with make_session(engine) as db:
        signed = signature(key, challenge)
        registry.redeem_enroll_challenge(
            db, challenge.id, signed, cert_serial="1", requested_name="device"
        )
    with make_session(engine) as db, pytest.raises(registry.NotFoundError):
        registry.redeem_enroll_challenge(
            db, challenge.id, signed, cert_serial="2", requested_name="replay"
        )
    engine.dispose()


def test_challenge_rejects_tampering_and_expiry(db_session, tmp_path):
    key, public = keypair(tmp_path)
    user = registry.create_user(db_session, public_key=public)
    for ttl in (datetime.timedelta(minutes=2), datetime.timedelta(seconds=-1)):
        challenge = registry.create_enroll_challenge(
            db_session, fingerprint=user.ssh_key_fingerprint, ttl=ttl
        )
        challenge_id = challenge.id
        if ttl.total_seconds() > 0:
            prefix, mac = challenge_id.rsplit(".", 1)
            challenge_id = prefix + "." + ("0" if mac[0] != "0" else "1") + mac[1:]
        with pytest.raises(registry.NotFoundError):
            registry.peek_enroll_challenge(db_session, challenge_id, signature(key, challenge))


@pytest.mark.parametrize("url", [
    "http://example.com", "http://localhost", "http://127.0.0.1:8443",
    "ftp://example.com", "https://", "https://user:pass@example.com",
    "https://example.com?token=x", "https://example.com/#fragment",
    "https://example.com:bad", "https://example.com\n", "https://example.com:0",
])
def test_insecure_enrollment_fails_before_network_or_signing(url, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("unsafe URL reached the network or SSH signing")

    monkeypatch.setattr(httpx, "post", forbidden)
    monkeypatch.setattr(ssh_signing, "sign", forbidden)
    with pytest.raises(ControlURLValueError):
        require_https_url(url)
    with pytest.raises(enroll.EnrollError):
        enroll.enroll(control_url=url, token="secret", data_dir=tmp_path)
    with pytest.raises(enroll.EnrollError):
        enroll.enroll_by_key(
            control_url=url, identity_path=Path("unused"), public_key="unused",
            name="device", data_dir=tmp_path,
        )


def test_https_retains_reverse_proxy_prefix_and_custom_port():
    assert require_https_url("https://example.com:9443/tunnels/") == (
        "https://example.com:9443/tunnels"
    )


def test_saved_http_url_cannot_send_credentials(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("saved HTTP state reached the network")

    monkeypatch.setattr(httpx, "get", forbidden)
    monkeypatch.setattr(httpx, "post", forbidden)
    state = AgentState(
        device_id="d", device_name="d", control_url="http://example.com",
        relay_addr="example.com", relay_port=7000, api_token="secret",
        cert_pem="", key_pem="", ca_cert_pem="",
    )
    for call in (poller.send_heartbeat, poller.fetch_desired_state, poller.fetch_server_version):
        with pytest.raises(poller.SyncError, match="https://"):
            call(state)


def test_legacy_challenge_survives_upgrade(db_session, tmp_path):
    key, public = keypair(tmp_path)
    user = registry.create_user(db_session, public_key=public)
    legacy = EnrollChallenge(
        fingerprint=user.ssh_key_fingerprint,
        challenge=base64.b64encode(b"legacy-random-nonce").decode(),
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=2),
    )
    db_session.add(legacy)
    db_session.commit()
    db_session.refresh(legacy)
    challenge_id, signed = legacy.id, signature(key, legacy)
    db_session.expunge_all()
    enrolled = registry.redeem_enroll_challenge(
        db_session, challenge_id, signed, cert_serial="legacy", requested_name="legacy-device"
    )
    assert enrolled.device.name == "legacy-device"


def test_concurrent_redemption_creates_exactly_one_device(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from frp_jump.common.models import Device

    key, public = keypair(tmp_path)
    engine = make_engine(tmp_path / "race.sqlite3")
    with make_session(engine) as db:
        user = registry.create_user(db, public_key=public)
        challenge = registry.create_enroll_challenge(
            db, fingerprint=user.ssh_key_fingerprint, ttl=datetime.timedelta(minutes=2)
        )
        signed = signature(key, challenge)
    barrier = Barrier(2)
    original = registry._verify_enroll_challenge

    def verify(*args):
        result = original(*args)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(registry, "_verify_enroll_challenge", verify)

    def redeem(i):
        with make_session(engine) as db:
            try:
                registry.redeem_enroll_challenge(
                    db, challenge.id, signed, cert_serial=str(i), requested_name=f"racer-{i}"
                )
                return "enrolled"
            except registry.NotFoundError:
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(redeem, range(2))) == ["enrolled", "rejected"]
    with make_session(engine) as db:
        assert len(list(db.exec(select(Device)))) == 1
    engine.dispose()
