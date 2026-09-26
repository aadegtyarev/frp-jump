"""Real frps + 2x frpc end to end, over loopback.

Validates the whole chain: mTLS-issued certs actually get accepted by real
frp binaries, and a grant's xtcp+stcp(+fallback) wiring actually proxies
traffic from the consumer's local bound port to the exposer's local
service. There is no real NAT here, so this cannot prove p2p hole punching
itself works -- only that the fallback path (and the config shape) is
correct. See docs/architecture.md for the follow-up manual check on real
hardware/networks.
"""

from __future__ import annotations

import contextlib
import http.server
import socket
import threading
import time

import httpx
import pytest

from frp_jump.common.crypto import generate_token
from frp_jump.common.pki import CertificateAuthority
from frp_jump.driver.base import ConsumedGrant, DesiredState, ExposedService, RelayState
from frp_jump.driver.frp.driver import FrpDriver, FrpsRelayDriver

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = b"hello from exposer"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence default stderr logging
        pass


@contextlib.contextmanager
def _run_http_server(port: int):
    server = http.server.HTTPServer(("127.0.0.1", port), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_grant_proxies_traffic_from_consumer_to_exposer(tmp_path, frp_binaries) -> None:
    ca = CertificateAuthority.bootstrap("test CA")
    relay_port = _free_port()
    target_port = _free_port()
    local_bind_port = _free_port()
    grant_secret = generate_token()

    relay = FrpsRelayDriver(
        binary=frp_binaries.frps, state_dir=tmp_path / "relay", admin_port=_free_port()
    )
    server_pair = ca.issue("relay", san_names=["127.0.0.1"], server_auth=True)
    relay.apply(
        RelayState(
            bind_port=relay_port,
            ca_cert_pem=ca.cert_pem,
            cert_pem=server_pair.cert_pem,
            key_pem=server_pair.key_pem,
        )
    )

    exposer = FrpDriver(
        binary=frp_binaries.frpc,
        state_dir=tmp_path / "exposer",
        fallback_timeout_ms=1500,
    )
    exposer_pair = ca.issue("exposer")

    consumer = FrpDriver(
        binary=frp_binaries.frpc,
        state_dir=tmp_path / "consumer",
        fallback_timeout_ms=1500,
    )
    consumer_pair = ca.issue("consumer")

    try:
        with _run_http_server(target_port):
            exposer.apply(
                DesiredState(
                    device_id="exposer",
                    server_addr="127.0.0.1",
                    server_port=relay_port,
                    ca_cert_pem=ca.cert_pem,
                    cert_pem=exposer_pair.cert_pem,
                    key_pem=exposer_pair.key_pem,
                    exposed=(
                        ExposedService(grant_id="g1", secret=grant_secret, local_port=target_port),
                    ),
                )
            )
            consumer.apply(
                DesiredState(
                    device_id="consumer",
                    server_addr="127.0.0.1",
                    server_port=relay_port,
                    ca_cert_pem=ca.cert_pem,
                    cert_pem=consumer_pair.cert_pem,
                    key_pem=consumer_pair.key_pem,
                    consumed=(
                        ConsumedGrant(
                            grant_id="g1", secret=grant_secret, local_bind_port=local_bind_port
                        ),
                    ),
                )
            )

            deadline = time.monotonic() + 20.0
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                try:
                    resp = httpx.get(f"http://127.0.0.1:{local_bind_port}", timeout=1.0)
                    if resp.status_code == 200:
                        assert resp.content == b"hello from exposer"
                        return
                except httpx.HTTPError as exc:
                    last_error = exc
                time.sleep(0.5)
            pytest.fail(f"tunnel never came up in time (last error: {last_error})")
    finally:
        consumer.stop()
        exposer.stop()
        relay.stop()


def test_frps_rejects_a_client_whose_cert_chains_to_a_different_ca(tmp_path, frp_binaries) -> None:
    """The core security claim (docs: "an unenrolled device cannot reach the
    relay at all") was previously asserted only in prose. This checks it
    against a real frps: `force=true` + `trustedCaFile` must reject a
    structurally valid cert that simply chains to the wrong CA, same as it
    would reject a device that was never enrolled at all.
    """
    real_ca = CertificateAuthority.bootstrap("real CA")
    rogue_ca = CertificateAuthority.bootstrap("rogue CA")

    relay_port = _free_port()
    target_port = _free_port()
    local_bind_port = _free_port()
    grant_secret = generate_token()

    relay = FrpsRelayDriver(
        binary=frp_binaries.frps, state_dir=tmp_path / "relay", admin_port=_free_port()
    )
    server_pair = real_ca.issue("relay", san_names=["127.0.0.1"], server_auth=True)
    relay.apply(
        RelayState(
            bind_port=relay_port,
            ca_cert_pem=real_ca.cert_pem,
            cert_pem=server_pair.cert_pem,
            key_pem=server_pair.key_pem,
        )
    )

    # The exposer presents a cert issued by a DIFFERENT CA than the one
    # frps trusts -- everything else about it is a legitimate, validly
    # signed certificate.
    rogue_exposer_pair = rogue_ca.issue("exposer")
    exposer = FrpDriver(
        binary=frp_binaries.frpc,
        state_dir=tmp_path / "rogue-exposer",
        fallback_timeout_ms=1500,
    )

    consumer = FrpDriver(
        binary=frp_binaries.frpc,
        state_dir=tmp_path / "consumer",
        fallback_timeout_ms=1500,
    )
    consumer_pair = real_ca.issue("consumer")

    try:
        with _run_http_server(target_port):
            exposer.apply(
                DesiredState(
                    device_id="rogue-exposer",
                    server_addr="127.0.0.1",
                    server_port=relay_port,
                    ca_cert_pem=real_ca.cert_pem,
                    cert_pem=rogue_exposer_pair.cert_pem,
                    key_pem=rogue_exposer_pair.key_pem,
                    exposed=(
                        ExposedService(grant_id="g1", secret=grant_secret, local_port=target_port),
                    ),
                )
            )
            consumer.apply(
                DesiredState(
                    device_id="consumer",
                    server_addr="127.0.0.1",
                    server_port=relay_port,
                    ca_cert_pem=real_ca.cert_pem,
                    cert_pem=consumer_pair.cert_pem,
                    key_pem=consumer_pair.key_pem,
                    consumed=(
                        ConsumedGrant(
                            grant_id="g1", secret=grant_secret, local_bind_port=local_bind_port
                        ),
                    ),
                )
            )

            # The positive-case test proves a valid pair comes up well within
            # this window (fallback alone is 1.5s). If a rogue-CA exposer's
            # proxy had been accepted, this grant would work the same way.
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                with contextlib.suppress(httpx.HTTPError):
                    resp = httpx.get(f"http://127.0.0.1:{local_bind_port}", timeout=1.0)
                    assert resp.status_code != 200, (
                        "tunnel came up despite the exposer's cert chaining to a "
                        "different CA than frps trusts -- mTLS enforcement is broken"
                    )
                time.sleep(0.5)
    finally:
        consumer.stop()
        exposer.stop()
        relay.stop()
