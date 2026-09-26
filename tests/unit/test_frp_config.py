import tomllib

from frp_jump.driver.base import ConsumedGrant, DesiredState, ExposedService, RelayState
from frp_jump.driver.frp.config import build_frpc_config, build_frps_config, write_toml


def _desired(**overrides) -> DesiredState:
    base = dict(
        device_id="dev-1",
        server_addr="relay.example.com",
        server_port=7000,
        ca_cert_pem=b"ca",
        cert_pem=b"cert",
        key_pem=b"key",
    )
    base.update(overrides)
    return DesiredState(**base)


def test_frpc_config_has_no_proxies_or_visitors_when_nothing_wired() -> None:
    config = build_frpc_config(
        _desired(), cert_file="c.crt", key_file="c.key", ca_file="ca.crt", fallback_timeout_ms=1500
    )
    assert "proxies" not in config
    assert "visitors" not in config
    assert config["serverAddr"] == "relay.example.com"
    assert config["serverPort"] == 7000
    assert config["transport"]["tls"] == {
        "certFile": "c.crt",
        "keyFile": "c.key",
        "trustedCaFile": "ca.crt",
    }


def test_frpc_config_exposes_paired_xtcp_and_stcp_proxies() -> None:
    desired = _desired(exposed=(ExposedService(grant_id="g1", secret="topsecret", local_port=22),))
    config = build_frpc_config(
        desired, cert_file="c.crt", key_file="c.key", ca_file="ca.crt", fallback_timeout_ms=1500
    )

    proxies = {p["name"]: p for p in config["proxies"]}
    assert set(proxies) == {"g1-xtcp", "g1-stcp"}
    for proxy in proxies.values():
        assert proxy["secretKey"] == "topsecret"
        assert proxy["localIP"] == "127.0.0.1"
        assert proxy["localPort"] == 22
        assert proxy["allowUsers"] == ["*"]
    assert proxies["g1-xtcp"]["type"] == "xtcp"
    assert proxies["g1-stcp"]["type"] == "stcp"


def test_frpc_config_wires_xtcp_visitor_fallback_to_stcp_visitor() -> None:
    desired = _desired(
        consumed=(ConsumedGrant(grant_id="g2", secret="s2", local_bind_port=2222),)
    )
    config = build_frpc_config(
        desired, cert_file="c.crt", key_file="c.key", ca_file="ca.crt", fallback_timeout_ms=750
    )

    visitors = {v["name"]: v for v in config["visitors"]}
    assert set(visitors) == {"g2-stcp-visitor", "g2-xtcp-visitor"}

    stcp_visitor = visitors["g2-stcp-visitor"]
    assert stcp_visitor["type"] == "stcp"
    assert stcp_visitor["serverName"] == "g2-stcp"
    assert stcp_visitor["secretKey"] == "s2"
    assert stcp_visitor["bindPort"] == -1

    xtcp_visitor = visitors["g2-xtcp-visitor"]
    assert xtcp_visitor["type"] == "xtcp"
    assert xtcp_visitor["serverName"] == "g2-xtcp"
    assert xtcp_visitor["secretKey"] == "s2"
    assert xtcp_visitor["bindAddr"] == "127.0.0.1"
    assert xtcp_visitor["bindPort"] == 2222
    assert xtcp_visitor["fallbackTo"] == "g2-stcp-visitor"
    assert xtcp_visitor["fallbackTimeoutMs"] == 750


def test_frpc_config_disable_p2p_skips_xtcp_visitor_entirely() -> None:
    desired = _desired(
        consumed=(ConsumedGrant(grant_id="g2", secret="s2", local_bind_port=2222),)
    )
    config = build_frpc_config(
        desired,
        cert_file="c.crt",
        key_file="c.key",
        ca_file="ca.crt",
        fallback_timeout_ms=500,
        disable_p2p=True,
    )

    visitors = {v["name"]: v for v in config["visitors"]}
    assert set(visitors) == {"g2-stcp-visitor"}
    stcp_visitor = visitors["g2-stcp-visitor"]
    assert stcp_visitor["type"] == "stcp"
    assert stcp_visitor["serverName"] == "g2-stcp"
    assert stcp_visitor["bindAddr"] == "127.0.0.1"
    assert stcp_visitor["bindPort"] == 2222


def test_frpc_config_disable_p2p_still_exposes_xtcp_proxy() -> None:
    """Only this device's own *consuming* side opts out -- other devices
    should still be able to reach it peer-to-peer."""
    desired = _desired(exposed=(ExposedService(grant_id="g1", secret="s", local_port=22),))
    config = build_frpc_config(
        desired,
        cert_file="c.crt",
        key_file="c.key",
        ca_file="ca.crt",
        fallback_timeout_ms=500,
        disable_p2p=True,
    )
    assert {p["name"] for p in config["proxies"]} == {"g1-xtcp", "g1-stcp"}


def test_frps_config_forces_tls_and_sets_bind_port() -> None:
    relay = RelayState(bind_port=7000, ca_cert_pem=b"ca", cert_pem=b"cert", key_pem=b"key")
    config = build_frps_config(relay, cert_file="s.crt", key_file="s.key", ca_file="ca.crt")
    assert config["bindPort"] == 7000
    assert config["transport"]["tls"]["force"] is True
    assert config["transport"]["tls"]["trustedCaFile"] == "ca.crt"
    assert config["log"]["level"] == "warn"


def test_frpc_config_quiets_frpc_own_log_level() -> None:
    config = build_frpc_config(
        _desired(), cert_file="c.crt", key_file="c.key", ca_file="ca.crt", fallback_timeout_ms=1500
    )
    assert config["log"]["level"] == "warn"


def test_write_toml_round_trips_through_tomllib(tmp_path) -> None:
    desired = _desired(exposed=(ExposedService(grant_id="g1", secret="s", local_port=80),))
    config = build_frpc_config(
        desired, cert_file="c.crt", key_file="c.key", ca_file="ca.crt", fallback_timeout_ms=1500
    )
    path = tmp_path / "frpc.toml"
    write_toml(config, path)
    loaded = tomllib.loads(path.read_text())
    assert loaded == config
