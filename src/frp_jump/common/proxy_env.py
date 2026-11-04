"""Workarounds for proxy environment variables that httpx can't handle."""

from __future__ import annotations

import ipaddress
import os

_NO_PROXY_VARS = ("NO_PROXY", "no_proxy")


def _is_ipv6_network(entry: str) -> bool:
    if "/" not in entry:
        return False
    try:
        return ipaddress.ip_network(entry.strip("[]"), strict=False).version == 6
    except ValueError:
        return False


def drop_ipv6_networks_from_no_proxy() -> None:
    """Remove IPv6 CIDR entries (``fc00::/7``, ``fe80::/10``) from
    ``NO_PROXY``/``no_proxy`` in this process's environment.

    httpx (0.28.1 at the time of writing) turns every NO_PROXY entry into
    a URL pattern, and an IPv6 network becomes ``all://fc00::/7`` -- its
    parser then reads the second colon as a port and every request fails
    with ``InvalidURL: Invalid port: ':'`` before it is sent. A common
    "bypass the proxy for local addresses" NO_PROXY made every command
    that talks to the server crash with a traceback.

    httpx never matches CIDR ranges anyway (it compares hostnames), so
    dropping these entries changes nothing about which requests it
    proxies. Single IPv6 addresses such as ``::1`` work and are kept.
    """
    for var in _NO_PROXY_VARS:
        value = os.environ.get(var)
        if not value:
            continue
        entries = value.split(",")
        kept = [e for e in entries if not _is_ipv6_network(e.strip())]
        if len(kept) != len(entries):
            os.environ[var] = ",".join(kept)
