"""Authenticated enrollment challenges without unauthenticated database growth.

The client still signs a base64 nonce and returns an opaque challenge_id.
Only successful redemptions need a database row, for replay protection.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import secrets

from sqlalchemy.dialects.sqlite import insert
from sqlmodel import Session

from frp_jump.common.models import EnrollChallenge, ServerSecret

PREFIX = "v1."
_KEY_NAME = "enrollment-challenges-v1"


def _key(session: Session) -> bytes:
    record = session.get(ServerSecret, _KEY_NAME)
    if record is None:
        # Concurrent first requests must all use the same durable key.
        session.execute(
            insert(ServerSecret)
            .values(name=_KEY_NAME, value=secrets.token_hex(32))
            .on_conflict_do_nothing(index_elements=["name"])
        )
        session.commit()
        record = session.get(ServerSecret, _KEY_NAME)
    return bytes.fromhex(record.value)


def issue(session: Session, fingerprint: str, ttl: datetime.timedelta) -> EnrollChallenge:
    now = datetime.datetime.now(datetime.UTC)
    nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    payload = json.dumps(
        [fingerprint, nonce, (now + ttl).timestamp()], separators=(",", ":")
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii")
    signature = hmac.new(_key(session), (PREFIX + encoded).encode(), hashlib.sha256).hexdigest()
    return EnrollChallenge(
        id=PREFIX + encoded + "." + signature,
        fingerprint=fingerprint,
        challenge=nonce,
        created_at=now,
        expires_at=now + ttl,
    )


def read(session: Session, challenge_id: str) -> EnrollChallenge:
    """Raise ValueError for an invalid, expired or already redeemed challenge."""
    if len(challenge_id) > 2048 or not challenge_id.startswith(PREFIX):
        raise ValueError("invalid challenge")
    encoded, signature = challenge_id[len(PREFIX):].rsplit(".", 1)
    expected = hmac.new(_key(session), (PREFIX + encoded).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.encode(), expected.encode()):
        raise ValueError("invalid challenge")
    fingerprint, nonce, timestamp = json.loads(base64.urlsafe_b64decode(encoded))
    expires_at = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
    if expires_at < datetime.datetime.now(datetime.UTC):
        raise ValueError("expired challenge")
    # Hash the opaque token for a small, fixed-width replay key.
    replay_id = hashlib.sha256(challenge_id.encode()).hexdigest()
    if session.get(EnrollChallenge, replay_id) is not None:
        raise ValueError("used challenge")
    return EnrollChallenge(
        id=replay_id, fingerprint=fingerprint, challenge=nonce, expires_at=expires_at
    )
