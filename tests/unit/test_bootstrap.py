import pytest

from frp_jump.common.settings import Settings
from frp_jump.server import bootstrap


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(data_dir=tmp_path / "data", relay_public_addr="relay.example.com")
    base.update(overrides)
    return Settings(**base)


def test_initialize_requires_relay_public_addr(tmp_path) -> None:
    settings = _settings(tmp_path, relay_public_addr=None)
    with pytest.raises(bootstrap.ConfigError):
        bootstrap.initialize(settings)


def test_initialize_creates_ca_and_db(tmp_path) -> None:
    settings = _settings(tmp_path)
    result = bootstrap.initialize(settings)

    cert_path, key_path = bootstrap.ca_paths(settings)
    assert cert_path.exists()
    assert key_path.exists()
    assert result.db_path.exists()
    assert result.ca_cert_pem == cert_path.read_bytes()


def test_initialize_is_idempotent_and_keeps_the_same_ca(tmp_path) -> None:
    settings = _settings(tmp_path)
    first = bootstrap.initialize(settings)
    second = bootstrap.initialize(settings)
    assert first.ca_cert_pem == second.ca_cert_pem


def test_load_or_create_relay_cert_is_signed_by_the_ca_and_stable(tmp_path) -> None:
    settings = _settings(tmp_path)
    ca = bootstrap.load_or_create_ca(settings)
    first = bootstrap.load_or_create_relay_cert(settings, ca)
    second = bootstrap.load_or_create_relay_cert(settings, ca)
    assert ca.verify_chain(first.cert_pem) is True
    assert first.cert_pem == second.cert_pem


def test_load_or_create_relay_cert_requires_relay_public_addr(tmp_path) -> None:
    settings = _settings(tmp_path, relay_public_addr=None)
    ca = bootstrap.load_or_create_ca(settings)
    with pytest.raises(bootstrap.ConfigError):
        bootstrap.load_or_create_relay_cert(settings, ca)
