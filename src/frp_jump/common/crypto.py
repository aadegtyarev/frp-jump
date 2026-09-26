"""Opaque secret tokens (enroll tokens, challenges) and row ids, plus
restrictive-permission file writes for secret material (private keys).

Tokens are high-entropy random strings handed to a human or a device. Only
their SHA-256 digest is ever persisted, so a database leak does not hand out
usable enroll commands — the same pattern used for API keys.

Deliberately dependency-free (stdlib only): both `frp-jump-client` and
`frp-jump-server` import this, and the client's own dependency list stays
lean on purpose (see pyproject.toml) -- nothing here should ever need
`cryptography` or anything else from the `[server]` extra.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

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


def write_private_key(path: Path, data: bytes) -> None:
    """Write a private key with restrictive permissions from creation, not
    chmod after -- chmod-after-write leaves a window where the key is
    readable by anyone on the box (default umask)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
