"""Server first-run setup: private CA, database, and the admin's login link.

Idempotent -- safe to call again (e.g. after a crash mid-setup); it only
creates what is missing, it never overwrites an existing CA.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from frp_jump.common.models import TokenPurpose
from frp_jump.common.pki import CertificateAuthority, KeyCertPair
from frp_jump.common.settings import Settings
from frp_jump.server import auth
from frp_jump.server.db import make_engine, make_session


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    data_dir: Path
    db_path: Path
    ca_cert_pem: bytes
    admin_login_url: str


def ca_paths(settings: Settings) -> tuple[Path, Path]:
    return settings.data_dir / "ca.crt", settings.data_dir / "ca.key"


def db_path(settings: Settings) -> Path:
    return settings.data_dir / "db.sqlite3"


def load_or_create_ca(settings: Settings) -> CertificateAuthority:
    cert_path, key_path = ca_paths(settings)
    if cert_path.exists() and key_path.exists():
        return CertificateAuthority.from_pair(
            KeyCertPair(key_pem=key_path.read_bytes(), cert_pem=cert_path.read_bytes())
        )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    ca = CertificateAuthority.bootstrap("frp-jump CA")
    cert_path.write_bytes(ca.cert_pem)
    key_path.write_bytes(ca.pair.key_pem)
    key_path.chmod(0o600)
    return ca


def relay_cert_paths(settings: Settings) -> tuple[Path, Path]:
    return settings.data_dir / "relay" / "server.crt", settings.data_dir / "relay" / "server.key"


def load_or_create_relay_cert(settings: Settings, ca: CertificateAuthority) -> KeyCertPair:
    """The relay's own leaf cert, signed by our CA, SAN'd for relay_public_addr.

    frpc validates this against ``serverAddr`` (see ``common.pki._san_entries``
    for why IP vs hostname SANs are handled automatically).
    """
    if not settings.relay_public_addr:
        raise ConfigError("relay_public_addr is not set")
    cert_path, key_path = relay_cert_paths(settings)
    if cert_path.exists() and key_path.exists():
        return KeyCertPair(key_pem=key_path.read_bytes(), cert_pem=cert_path.read_bytes())
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    pair = ca.issue("relay", san_names=[settings.relay_public_addr])
    cert_path.write_bytes(pair.cert_pem)
    key_path.write_bytes(pair.key_pem)
    key_path.chmod(0o600)
    return pair


def build_url(settings: Settings, path: str) -> str:
    """Render a clickable link, if the admin configured ``public_base_url``."""
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/") + path
    return path


def initialize(settings: Settings, *, admin_email: str) -> BootstrapResult:
    if not settings.relay_public_addr:
        raise ConfigError(
            "relay_public_addr is not set -- configure FRP_JUMP_RELAY_PUBLIC_ADDR "
            "(or relay_public_addr in the config file) to the address other "
            "devices will use to reach this server, then retry."
        )

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    ca = load_or_create_ca(settings)

    engine = make_engine(db_path(settings))
    with make_session(engine) as db:
        login_token = auth.issue_login_token(
            db,
            email=admin_email,
            purpose=TokenPurpose.LOGIN,
            created_by=None,
            ttl=datetime.timedelta(minutes=settings.login_token_ttl_minutes),
        )

    return BootstrapResult(
        data_dir=settings.data_dir,
        db_path=db_path(settings),
        ca_cert_pem=ca.cert_pem,
        admin_login_url=build_url(settings, f"/auth/{login_token}"),
    )
