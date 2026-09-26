"""Single source of truth for every configurable knob in frp-jump.

Nothing outside this module should hardcode a port number, TTL, path, or
version pin -- those are read from here, and here alone, so the whole
system can be reconfigured through environment variables or a config file
without touching code.

Precedence (highest wins): environment variables (``FRP_JUMP_*``) > a TOML
config file > the defaults below. The config file location is
``$FRP_JUMP_CONFIG_FILE``, else the first of ``./frp-jump.toml``,
``~/.config/frp-jump/config.toml``, ``/etc/frp-jump/config.toml`` that
exists.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


def resolve_config_file() -> Path | None:
    env_path = os.environ.get("FRP_JUMP_CONFIG_FILE")
    if env_path:
        return Path(env_path)
    for candidate in (
        Path("frp-jump.toml"),
        Path.home() / ".config" / "frp-jump" / "config.toml",
        Path("/etc/frp-jump/config.toml"),
    ):
        if candidate.is_file():
            return candidate
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FRP_JUMP_", extra="ignore")

    # storage
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".local/share/frp-jump")

    # frp engine
    frp_version: str = "0.70.0"
    # Address agents dial to reach the relay (public IP or domain). No sane
    # default exists -- must be set via FRP_JUMP_RELAY_PUBLIC_ADDR or the
    # config file before `server init` will run.
    relay_public_addr: str | None = None
    relay_bind_port: int = 7000
    frps_admin_port: int = 7500
    xtcp_fallback_timeout_ms: int = 1500

    # agent
    # How often `client run` polls for desired-state changes. The side
    # that calls `connect`/`disconnect` applies its own change almost
    # immediately regardless (see agent/state.py's wake-file mechanism),
    # but the *other* device in that pair only notices on its own next
    # poll -- this interval bounds that. Also overridable per invocation
    # via `client run --poll-interval`.
    agent_poll_interval_seconds: float = 2.0
    # Consumed-grant local bind ports come from this range, not the kernel's
    # ephemeral port range -- picking from the ephemeral range risks the OS
    # handing out the same port for an unrelated outbound connection later.
    agent_local_port_range_start: int = 40000
    agent_local_port_range_end: int = 40999
    # Where to maintain the `Include` line + managed Host blocks for consumed
    # SSH grants. Defaults to the invoking user's own ~/.ssh/config -- override
    # when running as a dedicated service account that isn't the human's login.
    ssh_config_path: Path | None = None

    # token lifetimes
    enroll_token_ttl_hours: int = 24
    # How long a POST /enroll/challenge nonce stays redeemable. Short on
    # purpose -- signing it is a local, near-instant operation on the
    # enrolling device, this only needs to survive one HTTP round trip.
    enroll_challenge_ttl_seconds: int = 120

    # control-plane API
    api_host: str = "0.0.0.0"
    api_port: int = 8443
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    # Used only to render clickable enroll URLs, e.g. "https://tunnel.example.com".
    public_base_url: str | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        config_file = resolve_config_file()
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        if config_file is not None:
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=config_file))
        sources.append(file_secret_settings)
        return tuple(sources)
