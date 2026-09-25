from pathlib import Path

from frp_jump.common.settings import Settings, resolve_config_file


def _isolate(monkeypatch, tmp_path: Path) -> Path:
    """Put settings resolution in a sandbox: no ambient env vars, no real files."""
    for key in list(__import__("os").environ):
        if key.startswith("FRP_JUMP_"):
            monkeypatch.delenv(key, raising=False)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.chdir(tmp_path)
    return fake_home


def test_defaults_apply_when_nothing_overrides_them(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    settings = Settings()
    assert settings.relay_bind_port == 7000
    assert settings.frp_version == "0.70.0"
    assert settings.xtcp_fallback_timeout_ms == 1500


def test_env_var_overrides_default(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("FRP_JUMP_RELAY_BIND_PORT", "9999")
    assert Settings().relay_bind_port == 9999


def test_config_file_overrides_default(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    (tmp_path / "frp-jump.toml").write_text('relay_bind_port = 12345\nfrp_version = "0.69.0"\n')
    settings = Settings()
    assert settings.relay_bind_port == 12345
    assert settings.frp_version == "0.69.0"


def test_env_var_wins_over_config_file(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    (tmp_path / "frp-jump.toml").write_text("relay_bind_port = 12345\n")
    monkeypatch.setenv("FRP_JUMP_RELAY_BIND_PORT", "9999")
    assert Settings().relay_bind_port == 9999


def test_resolve_config_file_prefers_explicit_env_var(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    explicit = tmp_path / "custom.toml"
    explicit.write_text("relay_bind_port = 1\n")
    (tmp_path / "frp-jump.toml").write_text("relay_bind_port = 2\n")
    monkeypatch.setenv("FRP_JUMP_CONFIG_FILE", str(explicit))
    assert resolve_config_file() == explicit


def test_resolve_config_file_returns_none_when_nothing_exists(monkeypatch, tmp_path) -> None:
    _isolate(monkeypatch, tmp_path)
    assert resolve_config_file() is None
