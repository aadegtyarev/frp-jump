"""Render frps.toml / frpc.toml from our own DesiredState / RelayState.

Key layout verified against fatedier/frp's frpc_full_example.toml and
frps_full_example.toml (dev branch, frp v0.70.x, TOML config format).

Every grant gets *two* proxies on the exposing side (xtcp + stcp) and *two*
visitors on the consuming side, wired together with ``fallbackTo`` /
``fallbackTimeoutMs`` — p2p first, transparent relay fallback if hole
punching does not complete in time. This is a native frp behavior, not
something we implement ourselves.

Every proxy/visitor also sets its own ``transport.useEncryption`` -- not
to be confused with the frpc-wide ``transport.tls`` block below, which
only ever covers the frpc<->frps control/relay connection. Once an xtcp
grant actually punches through (real peer-to-peer), its data connection
goes directly between the two frpc processes and never touches frps or
that TLS listener at all -- `useEncryption` (verified against frp's own
source, ``client/visitor/visitor.go``'s ``WithEncryption(rwc,
[]byte(cfg.SecretKey))``, gated on this exact flag, default off) is the
only thing that encrypts that leg. Off by default in frp itself; we turn
it on for every proxy/visitor so a plain-tcp grant (a web UI, MQTT,
anything without its own encryption -- unlike ssh, which encrypts itself
regardless) that ends up genuinely p2p isn't silently sent in the clear.
"""

from __future__ import annotations

from pathlib import Path

import tomli_w

from frp_jump.driver.base import DesiredState, RelayState


def _xtcp_proxy_name(grant_id: str) -> str:
    return f"{grant_id}-xtcp"


def stcp_proxy_name(grant_id: str) -> str:
    """Public (unlike the other name helpers here): also used by
    ``driver.frp.driver.fetch_proxy_traffic`` to look up a grant's relayed
    traffic on frps's admin API by the same name this renders into the
    frpc config."""
    return f"{grant_id}-stcp"


def _stcp_visitor_name(grant_id: str) -> str:
    return f"{grant_id}-stcp-visitor"


def _xtcp_visitor_name(grant_id: str) -> str:
    return f"{grant_id}-xtcp-visitor"


def _tls_block(*, cert_file: str, key_file: str, ca_file: str) -> dict:
    return {
        "certFile": cert_file,
        "keyFile": key_file,
        "trustedCaFile": ca_file,
    }


def _encrypted() -> dict:
    """Every proxy/visitor gets this -- see the module docstring for why.
    A fresh dict per call, not a shared module-level constant, so nothing
    downstream can accidentally mutate a value every proxy/visitor shares.
    """
    return {"transport": {"useEncryption": True}}


def build_frpc_config(
    desired: DesiredState,
    *,
    cert_file: str,
    key_file: str,
    ca_file: str,
    fallback_timeout_ms: int,
) -> dict:
    """Build the frpc config dict for one device's desired state."""
    proxies: list[dict] = []
    for exposed in desired.exposed:
        proxies.append(
            {
                "name": _xtcp_proxy_name(exposed.grant_id),
                "type": "xtcp",
                "secretKey": exposed.secret,
                "localIP": "127.0.0.1",
                "localPort": exposed.local_port,
                "allowUsers": ["*"],
                **_encrypted(),
            }
        )
        proxies.append(
            {
                "name": stcp_proxy_name(exposed.grant_id),
                "type": "stcp",
                "secretKey": exposed.secret,
                "localIP": "127.0.0.1",
                "localPort": exposed.local_port,
                "allowUsers": ["*"],
                **_encrypted(),
            }
        )

    visitors: list[dict] = []
    for consumed in desired.consumed:
        stcp_name = _stcp_visitor_name(consumed.grant_id)
        visitors.append(
            {
                "name": stcp_name,
                "type": "stcp",
                "serverName": stcp_proxy_name(consumed.grant_id),
                "secretKey": consumed.secret,
                "bindPort": -1,
                **_encrypted(),
            }
        )
        visitors.append(
            {
                "name": _xtcp_visitor_name(consumed.grant_id),
                "type": "xtcp",
                "serverName": _xtcp_proxy_name(consumed.grant_id),
                "secretKey": consumed.secret,
                "bindAddr": "127.0.0.1",
                "bindPort": consumed.local_bind_port,
                "fallbackTo": stcp_name,
                "fallbackTimeoutMs": fallback_timeout_ms,
                **_encrypted(),
            }
        )

    config: dict = {
        "serverAddr": desired.server_addr,
        "serverPort": desired.server_port,
        "loginFailExit": False,
        "transport": {"tls": _tls_block(cert_file=cert_file, key_file=key_file, ca_file=ca_file)},
        # frpc's own "info" level logs its full connection/heartbeat/proxy
        # chatter to stdout every cycle -- under systemd that's every line
        # in `journalctl`, forever. "warn" keeps genuine problems (auth
        # failures, connection errors) visible while dropping the routine
        # noise; the agent's own poller.py logs the meaningful lifecycle
        # events (what's exposed/consumed) at its own INFO level instead,
        # and `status` shows the current state on demand.
        "log": {"level": "warn"},
    }
    if proxies:
        config["proxies"] = proxies
    if visitors:
        config["visitors"] = visitors
    return config


def build_frps_config(
    desired: RelayState,
    *,
    cert_file: str,
    key_file: str,
    ca_file: str,
) -> dict:
    """Build the frps config dict for the relay."""
    tls = _tls_block(cert_file=cert_file, key_file=key_file, ca_file=ca_file)
    tls["force"] = True
    return {
        "bindPort": desired.bind_port,
        "transport": {"tls": tls},
        "log": {"level": "warn"},
    }


def write_toml(config: dict, path: Path) -> None:
    path.write_bytes(tomli_w.dumps(config).encode("utf-8"))
