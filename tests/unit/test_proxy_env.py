import os

import httpx
import pytest

from frp_jump.common.proxy_env import drop_ipv6_networks_from_no_proxy

_REAL_WORLD = (
    "localhost,127.0.0.1,::1,.local,10.0.0.0/8,172.16.0.0/12,"
    "192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10"
)


@pytest.fixture
def proxy_env(monkeypatch):
    for var in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:10809")
    return monkeypatch


def test_httpx_still_chokes_on_an_ipv6_network_in_no_proxy(proxy_env) -> None:
    """Guards the workaround: once httpx parses these, it can go."""
    proxy_env.setenv("NO_PROXY", "fc00::/7")
    proxy_env.delenv("no_proxy", raising=False)
    with pytest.raises(httpx.InvalidURL):
        httpx.Client()


def test_drops_only_ipv6_networks(proxy_env) -> None:
    proxy_env.setenv("NO_PROXY", _REAL_WORLD)
    proxy_env.setenv("no_proxy", _REAL_WORLD)

    drop_ipv6_networks_from_no_proxy()

    expected = (
        "localhost,127.0.0.1,::1,.local,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
    )

    assert os.environ["NO_PROXY"] == expected
    assert os.environ["no_proxy"] == expected
    httpx.Client()  # no longer raises


def test_leaves_an_unproblematic_no_proxy_untouched(proxy_env) -> None:
    proxy_env.setenv("NO_PROXY", "localhost, ::1 ,example.com")
    proxy_env.delenv("no_proxy", raising=False)

    drop_ipv6_networks_from_no_proxy()


    assert os.environ["NO_PROXY"] == "localhost, ::1 ,example.com"
    assert "no_proxy" not in os.environ


def test_client_cli_works_with_an_ipv6_network_in_no_proxy(proxy_env, tmp_path) -> None:
    from typer.testing import CliRunner

    from frp_jump.cli import client_cmds

    proxy_env.setenv("NO_PROXY", _REAL_WORLD)
    proxy_env.setenv("FRP_JUMP_DATA_DIR", str(tmp_path))

    result = CliRunner().invoke(client_cmds.app, ["status"])

    assert "InvalidURL" not in repr(result.exception)
