import datetime

import pytest

from frp_jump.common.models import TokenPurpose
from frp_jump.server import auth

_LOGIN_TTL = datetime.timedelta(hours=1)
_INVITE_TTL = datetime.timedelta(days=7)
_SESSION_TTL = datetime.timedelta(days=30)


def _issue_login(db_session, email: str, *, created_by: str | None = None) -> str:
    return auth.issue_login_token(
        db_session, email=email, purpose=TokenPurpose.LOGIN, created_by=created_by, ttl=_LOGIN_TTL
    )


def test_redeem_login_token_creates_user_on_first_use(db_session) -> None:
    token = _issue_login(db_session, "admin@example.com")
    user = auth.redeem_login_token(db_session, token)
    assert user.email == "admin@example.com"


def test_first_ever_redeemed_user_becomes_admin(db_session) -> None:
    token = _issue_login(db_session, "admin@example.com")
    user = auth.redeem_login_token(db_session, token)
    assert user.is_admin is True


def test_second_invited_user_is_not_admin(db_session) -> None:
    admin = auth.redeem_login_token(db_session, _issue_login(db_session, "admin@example.com"))

    invite = auth.issue_login_token(
        db_session,
        email="friend@example.com",
        purpose=TokenPurpose.INVITE,
        created_by=admin.id,
        ttl=_INVITE_TTL,
    )
    friend = auth.redeem_login_token(db_session, invite)
    assert friend.is_admin is False


def test_login_token_cannot_be_redeemed_twice(db_session) -> None:
    token = _issue_login(db_session, "admin@example.com")
    auth.redeem_login_token(db_session, token)
    with pytest.raises(auth.InvalidTokenError):
        auth.redeem_login_token(db_session, token)


def test_login_token_expired_is_rejected(db_session) -> None:
    token = auth.issue_login_token(
        db_session,
        email="admin@example.com",
        purpose=TokenPurpose.LOGIN,
        created_by=None,
        ttl=datetime.timedelta(seconds=-1),
    )
    with pytest.raises(auth.InvalidTokenError):
        auth.redeem_login_token(db_session, token)


def test_redeem_rejects_unknown_token(db_session) -> None:
    with pytest.raises(auth.InvalidTokenError):
        auth.redeem_login_token(db_session, "not-a-real-token")


def test_create_session_and_get_current_user_round_trip(db_session) -> None:
    user = auth.redeem_login_token(db_session, _issue_login(db_session, "admin@example.com"))
    session_token = auth.create_session(db_session, user, ttl=_SESSION_TTL)
    fetched = auth.get_current_user(db_session, session_token)
    assert fetched is not None
    assert fetched.id == user.id


def test_get_current_user_returns_none_for_missing_or_invalid_token(db_session) -> None:
    assert auth.get_current_user(db_session, None) is None
    assert auth.get_current_user(db_session, "bogus") is None


def test_revoke_session_invalidates_it(db_session) -> None:
    user = auth.redeem_login_token(db_session, _issue_login(db_session, "admin@example.com"))
    session_token = auth.create_session(db_session, user, ttl=_SESSION_TTL)
    auth.revoke_session(db_session, session_token)
    assert auth.get_current_user(db_session, session_token) is None


def test_expired_session_is_rejected(db_session) -> None:
    user = auth.redeem_login_token(db_session, _issue_login(db_session, "admin@example.com"))
    session_token = auth.create_session(db_session, user, ttl=datetime.timedelta(seconds=-1))
    assert auth.get_current_user(db_session, session_token) is None
