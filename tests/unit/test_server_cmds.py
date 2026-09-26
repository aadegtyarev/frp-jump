import contextlib
import datetime
import subprocess
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from frp_jump.cli import server_cmds
from frp_jump.driver.base import ServiceProtocol
from frp_jump.server import registry

runner = CliRunner()

_TTL = datetime.timedelta(hours=24)


def _make_user(db_session):
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "id"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            check=True,
            capture_output=True,
        )
        public_key = key_path.with_suffix(".pub").read_text()
    return registry.create_user(db_session, public_key=public_key, label="alice")


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("tunnel.example.com", False),
    ],
)
def test_is_loopback_host(host, expected) -> None:
    assert server_cmds._is_loopback_host(host) is expected


def test_install_service_wires_options_through(monkeypatch):
    captured = {}

    def fake_install(*, system_user, relay_public_addr, tls_cert_file, tls_key_file):
        captured["system_user"] = system_user
        captured["relay_public_addr"] = relay_public_addr
        captured["tls_cert_file"] = tls_cert_file
        captured["tls_key_file"] = tls_key_file
        return Path("/etc/systemd/system/frp-jump-server.service")

    monkeypatch.setattr(server_cmds.service_install, "install", fake_install)

    result = runner.invoke(
        server_cmds.app,
        ["install-service", "--relay-public-addr", "tunnel.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert captured == {
        "system_user": "frp-jump",
        "relay_public_addr": "tunnel.example.com",
        "tls_cert_file": None,
        "tls_key_file": None,
    }
    assert "Installed and started" in result.output


def test_install_service_wires_tls_options_through(monkeypatch, tmp_path):
    captured = {}

    def fake_install(*, system_user, relay_public_addr, tls_cert_file, tls_key_file):
        captured["tls_cert_file"] = tls_cert_file
        captured["tls_key_file"] = tls_key_file
        return Path("/etc/systemd/system/frp-jump-server.service")

    monkeypatch.setattr(server_cmds.service_install, "install", fake_install)

    result = runner.invoke(
        server_cmds.app,
        [
            "install-service",
            "--relay-public-addr",
            "tunnel.example.com",
            "--tls-cert",
            str(tmp_path / "fullchain.pem"),
            "--tls-key",
            str(tmp_path / "privkey.pem"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["tls_cert_file"] == tmp_path / "fullchain.pem"
    assert captured["tls_key_file"] == tmp_path / "privkey.pem"


def test_install_service_reports_a_clean_error(monkeypatch):
    def fake_install(*, system_user, relay_public_addr, tls_cert_file, tls_key_file):
        raise server_cmds.service_install.ServiceInstallError("boom")

    monkeypatch.setattr(server_cmds.service_install, "install", fake_install)

    result = runner.invoke(server_cmds.app, ["install-service"])

    assert result.exit_code == 1
    assert "boom" in result.output


def test_version_flag_prints_the_installed_version_and_exits():
    result = runner.invoke(server_cmds.app, ["--version"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == server_cmds._PACKAGE_VERSION


def test_bare_invocation_shows_help_instead_of_missing_command_error():
    """Click's own convention: `no_args_is_help` still exits non-zero (a
    UsageError, exit code 2) -- the point is that the full rich help text,
    including every subcommand, now shows instead of a bare "Missing
    command" one-liner with no further guidance."""
    result = runner.invoke(server_cmds.app, [])

    assert result.exit_code == 2
    assert "Missing command" not in result.output
    assert "install-service" in result.output
    assert "users" in result.output


def test_bare_subcommand_group_shows_help_instead_of_missing_command_error():
    result = runner.invoke(server_cmds.app, ["users"])

    assert result.exit_code == 2
    assert "Missing command" not in result.output
    assert "add-key" in result.output
    assert "list" in result.output


def test_devices_list_shows_online_and_offline(db_session, monkeypatch):
    admin = _make_user(db_session)
    issued_online = registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    online = registry.redeem_enroll_token(db_session, issued_online.token, cert_serial="1")
    issued_offline = registry.create_enroll_token(
        db_session, device_name_hint="old", created_by=admin.id, ttl=_TTL
    )
    offline = registry.redeem_enroll_token(db_session, issued_offline.token, cert_serial="2")

    online_row = registry.get_device(db_session, online.device.id)
    online_row.last_seen_at = datetime.datetime.now(datetime.UTC)
    offline_row = registry.get_device(db_session, offline.device.id)
    offline_row.last_seen_at = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
    db_session.add(online_row)
    db_session.add(offline_row)
    db_session.commit()

    monkeypatch.setattr(
        server_cmds, "_open_db", lambda settings: contextlib.nullcontext(db_session)
    )

    result = runner.invoke(server_cmds.app, ["devices", "list"])

    assert result.exit_code == 0, result.output
    assert "online" in result.output
    assert "offline" in result.output


def test_devices_list_shows_relayed_traffic_per_connection(db_session, monkeypatch):
    admin = _make_user(db_session)
    issued_exposer = registry.create_enroll_token(
        db_session, device_name_hint="wb01", created_by=admin.id, ttl=_TTL
    )
    exposer = registry.redeem_enroll_token(db_session, issued_exposer.token, cert_serial="1")
    issued_consumer = registry.create_enroll_token(
        db_session, device_name_hint="laptop", created_by=admin.id, ttl=_TTL
    )
    consumer = registry.redeem_enroll_token(db_session, issued_consumer.token, cert_serial="2")

    service = registry.create_service(
        db_session,
        device_id=exposer.device.id,
        name="svc-wb01-22",
        target_port=22,
        protocol=ServiceProtocol.SSH,
    )
    grant = registry.create_grant(
        db_session, service_id=service.id, consumer_device_id=consumer.device.id
    )

    monkeypatch.setattr(
        server_cmds, "fetch_all_proxy_traffic", lambda admin_port: {grant.id: (100, 200)}
    )
    monkeypatch.setattr(
        server_cmds, "_open_db", lambda settings: contextlib.nullcontext(db_session)
    )

    result = runner.invoke(server_cmds.app, ["devices", "list"])

    assert result.exit_code == 0, result.output
    assert "relayed today" in result.output
    assert "100" in result.output and "200" in result.output
    assert "peer-to-peer" in result.output


class _OrderTrackingDbContext:
    """Wraps a real db_session so a test can observe *when* the DB session
    closes relative to other calls -- used to prove the DB is never held
    open across a blocking frps admin-API call (see devices_list/users_show:
    a long-open read transaction there can make a concurrent device's
    heartbeat commit fail with "database is locked")."""

    def __init__(self, session, events: list[str]):
        self._session = session
        self._events = events

    def __enter__(self):
        return self._session

    def __exit__(self, *exc_info):
        self._events.append("db_closed")
        return False


def test_devices_list_closes_db_before_querying_frps_traffic(db_session, monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(
        server_cmds, "_open_db", lambda settings: _OrderTrackingDbContext(db_session, events)
    )

    def fake_fetch(admin_port):
        events.append("frps_queried")
        return {}

    monkeypatch.setattr(server_cmds, "fetch_all_proxy_traffic", fake_fetch)

    result = runner.invoke(server_cmds.app, ["devices", "list"])

    assert result.exit_code == 0, result.output
    assert events == ["db_closed", "frps_queried"]


def test_users_show_closes_db_before_querying_frps_traffic(db_session, monkeypatch):
    admin = _make_user(db_session)
    events: list[str] = []
    monkeypatch.setattr(
        server_cmds, "_open_db", lambda settings: _OrderTrackingDbContext(db_session, events)
    )

    def fake_fetch(admin_port):
        events.append("frps_queried")
        return {}

    monkeypatch.setattr(server_cmds, "fetch_all_proxy_traffic", fake_fetch)

    result = runner.invoke(server_cmds.app, ["users", "show", admin.label])

    assert result.exit_code == 0, result.output
    assert events == ["db_closed", "frps_queried"]
