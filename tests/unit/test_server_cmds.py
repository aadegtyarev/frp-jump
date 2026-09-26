from pathlib import Path

from typer.testing import CliRunner

from frp_jump.cli import server_cmds

runner = CliRunner()


def test_install_service_wires_options_through(monkeypatch):
    captured = {}

    def fake_install(*, system_user, relay_public_addr):
        captured["system_user"] = system_user
        captured["relay_public_addr"] = relay_public_addr
        return Path("/etc/systemd/system/frp-jump-server.service")

    monkeypatch.setattr(server_cmds.service_install, "install", fake_install)

    result = runner.invoke(
        server_cmds.app,
        ["install-service", "--relay-public-addr", "tunnel.example.com"],
    )

    assert result.exit_code == 0, result.output
    assert captured == {"system_user": "frp-jump", "relay_public_addr": "tunnel.example.com"}
    assert "Installed and started" in result.output


def test_install_service_reports_a_clean_error(monkeypatch):
    def fake_install(*, system_user, relay_public_addr):
        raise server_cmds.service_install.ServiceInstallError("boom")

    monkeypatch.setattr(server_cmds.service_install, "install", fake_install)

    result = runner.invoke(server_cmds.app, ["install-service"])

    assert result.exit_code == 1
    assert "boom" in result.output
