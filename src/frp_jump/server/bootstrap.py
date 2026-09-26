"""Server first-run setup: private CA and database.

Idempotent -- safe to call again (e.g. after a crash mid-setup); it only
creates what is missing, it never overwrites an existing CA. There is no
admin-account concept to bootstrap here -- an admin is just whoever has
SSH access to run `frp-jump-server` on this box (see `users add-key` to
register the first human).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from frp_jump.common.crypto import write_private_key
from frp_jump.common.pki import CertificateAuthority, KeyCertPair
from frp_jump.common.settings import Settings
from frp_jump.server.db import make_engine


class ConfigError(ValueError):
    pass


def _ensure_data_dir(settings: Settings) -> None:
    """The CA private key and the database (grant secrets, mTLS certs)
    both live directly under here -- explicitly chmod, since `mkdir`'s own
    `mode` argument is still subject to the process umask, and this must
    not end up world- or group-readable regardless of what the operator's
    umask happens to be (e.g. a plain `frp-jump-server init` run by hand,
    as opposed to `install-service`, which already chmods its own
    dedicated account's directory separately)."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.chmod(0o700)


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    data_dir: Path
    db_path: Path
    ca_cert_pem: bytes


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
    _ensure_data_dir(settings)
    ca = CertificateAuthority.bootstrap("frp-jump CA")
    cert_path.write_bytes(ca.cert_pem)
    write_private_key(key_path, ca.pair.key_pem)
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
    pair = ca.issue("relay", san_names=[settings.relay_public_addr], server_auth=True)
    cert_path.write_bytes(pair.cert_pem)
    write_private_key(key_path, pair.key_pem)
    return pair


def initialize(settings: Settings) -> BootstrapResult:
    if not settings.relay_public_addr:
        raise ConfigError(
            "relay_public_addr is not set -- configure FRP_JUMP_RELAY_PUBLIC_ADDR "
            "(or relay_public_addr in the config file) to the address other "
            "devices will use to reach this server, then retry."
        )

    _ensure_data_dir(settings)
    ca = load_or_create_ca(settings)
    # Creates the sqlite file and every table on first run; a no-op
    # otherwise (SQLModel.metadata.create_all only adds missing tables).
    make_engine(db_path(settings))

    return BootstrapResult(
        data_dir=settings.data_dir,
        db_path=db_path(settings),
        ca_cert_pem=ca.cert_pem,
    )
