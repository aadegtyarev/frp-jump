import httpx
import pytest


@pytest.mark.parametrize("proxy", ["socks5://127.0.0.1:1080", "socks5h://127.0.0.1:1080"])
def test_httpx_accepts_a_socks_all_proxy(monkeypatch, proxy) -> None:
    """ALL_PROXY=socks5h://... is a common setup for routing a terminal
    through a local proxy. Without socksio bundled, httpx raised
    ImportError on every request the client made to the server."""
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ALL_PROXY", proxy)

    httpx.Client()
