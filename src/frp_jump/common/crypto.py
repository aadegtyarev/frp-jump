"""Opaque secret tokens (magic links, enroll tokens) and row ids.

Tokens are high-entropy random strings handed to a human or a device. Only
their SHA-256 digest is ever persisted, so a database leak does not hand out
usable login links or enroll commands — the same pattern used for API keys.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_TOKEN_BYTES = 32
_ID_BYTES = 16


def generate_token() -> str:
    """A high-entropy, URL-safe secret to hand to a user or device."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """One-way digest of ``token``, safe to store in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, token_hash: str) -> bool:
    """Constant-time check that ``token`` hashes to ``token_hash``."""
    return hmac.compare_digest(hash_token(token), token_hash)


def generate_id() -> str:
    """A short, URL-safe, unguessable id for a database row."""
    return secrets.token_urlsafe(_ID_BYTES)
