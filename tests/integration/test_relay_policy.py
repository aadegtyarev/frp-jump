"""Exercise policy hooks against the pinned, unmodified frp binaries."""
import time

import httpx
import pytest

from frp_jump.common.pki import CertificateAuthority
from frp_jump.driver.base import ConsumedGrant, DesiredState, ExposedService, RelayState
from frp_jump.driver.frp.driver import FrpDriver, FrpsRelayDriver
from frp_jump.server import registry
from frp_jump.server.db import make_engine, make_session
from frp_jump.server.relay_policy import RelayPolicyServer
from tests.integration.test_frp_e2e import _free_port, _run_http_server
from tests.unit.test_relay_policy import topology

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("disable_p2p", [False, True])
def test_policy_preserves_tunnel_and_blocks_revoked_consumer(
    tmp_path, frp_binaries, strict, disable_p2p
):
    engine = make_engine(tmp_path / "db.sqlite3")
    with make_session(engine) as db:
        devices, grant = topology(db)
        exposer_id, consumer_id = devices[0].id, devices[1].id
        grant_id, secret = grant.id, grant.secret
    ca = CertificateAuthority.bootstrap()
    pair = ca.issue("relay", san_names=["127.0.0.1"], server_auth=True)
    relay_port, target_port, local_port = _free_port(), _free_port(), _free_port()
    relay = FrpsRelayDriver(binary=frp_binaries.frps, state_dir=tmp_path / "relay",
                           admin_port=_free_port())
    drivers = []
    with RelayPolicyServer(engine, require_device_auth=strict) as policy:
        try:
            relay.apply(RelayState(relay_port, ca.cert_pem, pair.cert_pem, pair.key_pem,
                                   policy_url=policy.url, require_device_auth=strict))
            with _run_http_server(target_port):
                for name, device_id in (("exposer", exposer_id), ("consumer", consumer_id)):
                    leaf = ca.issue(name)
                    driver = FrpDriver(binary=frp_binaries.frpc, state_dir=tmp_path / name,
                                       fallback_timeout_ms=500)
                    drivers.append(driver)
                    driver.apply(DesiredState(
                        device_id, "127.0.0.1", relay_port, ca.cert_pem,
                        leaf.cert_pem, leaf.key_pem,
                        exposed=(ExposedService(grant_id, secret, target_port),)
                        if name == "exposer" else (),
                        consumed=(ConsumedGrant(grant_id, secret, local_port),)
                        if name == "consumer" else (),
                        # Migration mode must work with genuinely old clients too.
                        api_token=name + "-token" if strict else "",
                    ), disable_p2p=disable_p2p)
                deadline = time.monotonic() + 15
                while True:
                    try:
                        response = httpx.get(f"http://127.0.0.1:{local_port}", timeout=1)
                        if response.status_code == 200:
                            assert response.content == b"hello from exposer"
                            break
                    except httpx.HTTPError:
                        pass
                    assert time.monotonic() < deadline, "authorized tunnel did not start"
                    time.sleep(0.2)
                # Keep both frpc processes running: no cooperative agent polling.
                with make_session(engine) as db:
                    registry.disable_device(db, consumer_id)
                with pytest.raises(httpx.HTTPError):
                    httpx.get(f"http://127.0.0.1:{local_port}", timeout=2)
                with make_session(engine) as db:
                    registry.enable_device(db, consumer_id)
                response = httpx.get(f"http://127.0.0.1:{local_port}", timeout=3)
                assert response.content == b"hello from exposer"
        finally:
            for driver in reversed(drivers):
                driver.stop()
            relay.stop()
    engine.dispose()


@pytest.mark.parametrize("strict,authenticated", [(False, False), (True, True), (True, False)])
def test_real_relay_rejects_arbitrary_tcp_proxy(tmp_path, frp_binaries, strict, authenticated):
    import socket
    import subprocess

    import tomli_w

    engine = make_engine(tmp_path / "db.sqlite3")
    with make_session(engine) as db:
        devices, _ = topology(db)
        device_id = devices[0].id
    ca = CertificateAuthority.bootstrap()
    pair = ca.issue("relay", san_names=["127.0.0.1"], server_auth=True)
    leaf = ca.issue("exposer")
    relay_port, remote_port = _free_port(), _free_port()
    for name, data in (("ca.crt", ca.cert_pem), ("client.crt", leaf.cert_pem),
                       ("client.key", leaf.key_pem)):
        (tmp_path / name).write_bytes(data)
    config = {
        "serverAddr": "127.0.0.1", "serverPort": relay_port, "loginFailExit": False,
        "transport": {"tls": {
            "certFile": str(tmp_path / "client.crt"),
            "keyFile": str(tmp_path / "client.key"),
            "trustedCaFile": str(tmp_path / "ca.crt"),
        }},
        "proxies": [{"name": "unapproved", "type": "tcp", "remotePort": remote_port,
                     "localIP": "127.0.0.1", "localPort": 22}],
    }
    if authenticated:
        config["metadatas"] = {"frp_jump_device": device_id, "frp_jump_token": "exposer-token"}
    path = tmp_path / "rogue.toml"
    path.write_text(tomli_w.dumps(config))
    relay = FrpsRelayDriver(binary=frp_binaries.frps, state_dir=tmp_path / "relay",
                           admin_port=_free_port())
    with RelayPolicyServer(engine, require_device_auth=strict) as policy:
        process = None
        try:
            relay.apply(RelayState(relay_port, ca.cert_pem, pair.cert_pem, pair.key_pem,
                                   policy_url=policy.url, require_device_auth=strict))
            log_path = tmp_path / "rogue.log"
            with log_path.open("w") as log:
                process = subprocess.Popen([str(frp_binaries.frpc), "-c", str(path)],
                                           stdout=log, stderr=log)
                deadline = time.monotonic() + 10
                while "relay operation not authorized" not in log_path.read_text():
                    assert time.monotonic() < deadline, log_path.read_text()
                    time.sleep(0.1)
                with socket.socket() as sock:
                    assert sock.connect_ex(("127.0.0.1", remote_port)) != 0
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
            relay.stop()
    engine.dispose()
