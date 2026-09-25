"""Passwordless WebUI auth: magic-link LoginTokens, cookie-backed Sessions.

No passwords, no SMTP: an admin mints a link (``issue_login_token``) and
hand-delivers it out of band; visiting it (``redeem_login_token``) creates
the user on first use and starts a session. Both tokens and sessions are
opaque high-entropy strings, hashed at rest, looked up by hash -- the same
pattern as ``EnrollToken``/``Device.api_token_hash``.
"""

from __future__ import annotations

import datetime

from sqlmodel import Session as DbSession
from sqlmodel import select

from frp_jump.common.crypto import generate_token, hash_token
from frp_jump.common.models import LoginToken, User
from frp_jump.common.models import Session as SessionRow
from frp_jump.server.registry import get_or_create_user


class InvalidTokenError(ValueError):
    pass


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def issue_login_token(
    db: DbSession,
    *,
    email: str,
    created_by: str | None,
    ttl: datetime.timedelta,
) -> str:
    """Mint a magic link for ``email``. Returns the raw token (only ever seen once)."""
    token = generate_token()
    record = LoginToken(
        token_hash=hash_token(token),
        email=email,
        created_by=created_by,
        expires_at=_now() + ttl,
    )
    db.add(record)
    db.commit()
    return token


def redeem_login_token(db: DbSession, token: str) -> User:
    """Verify + consume a login link once; get-or-create its User."""
    record = db.exec(select(LoginToken).where(LoginToken.token_hash == hash_token(token))).first()
    if record is None:
        raise InvalidTokenError("unknown login link")
    if record.used_at is not None:
        raise InvalidTokenError("login link already used")
    if record.revoked_at is not None:
        raise InvalidTokenError("login link revoked")
    if record.expires_at < _now():
        raise InvalidTokenError("login link expired")

    record.used_at = _now()
    db.add(record)
    is_first_user = db.exec(select(User)).first() is None
    user = get_or_create_user(db, record.email, is_admin=is_first_user)
    db.commit()
    return user


def create_session(db: DbSession, user: User, *, ttl: datetime.timedelta) -> str:
    token = generate_token()
    row = SessionRow(token_hash=hash_token(token), user_id=user.id, expires_at=_now() + ttl)
    db.add(row)
    db.commit()
    return token


def _find_session(db: DbSession, session_token: str) -> SessionRow | None:
    stmt = select(SessionRow).where(SessionRow.token_hash == hash_token(session_token))
    return db.exec(stmt).first()


def get_current_user(db: DbSession, session_token: str | None) -> User | None:
    if not session_token:
        return None
    row = _find_session(db, session_token)
    if row is None or row.revoked_at is not None or row.expires_at < _now():
        return None
    return db.get(User, row.user_id)


def revoke_session(db: DbSession, session_token: str) -> None:
    row = _find_session(db, session_token)
    if row is not None:
        row.revoked_at = _now()
        db.add(row)
        db.commit()
