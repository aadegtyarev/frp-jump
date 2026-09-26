import pytest

from frp_jump.server import bootstrap, service_install


def test_install_requires_root(monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 1000)

    with pytest.raises(service_install.ServiceInstallError, match="requires root"):
        service_install.install(relay_public_addr="tunnel.example.com")


def test_install_requires_relay_public_addr_on_first_run(tmp_path, monkeypatch):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: tmp_path / name)
    monkeypatch.setattr(service_install, "_ENV_DIR", tmp_path / "etc-frp-jump")

    with pytest.raises(service_install.ServiceInstallError, match="relay-public-addr"):
        service_install.install()


def test_install_writes_env_file_and_bootstraps(tmp_path, monkeypatch):
    data_dir = tmp_path / "var-lib" / "frp-jump"
    env_dir = tmp_path / "etc-frp-jump"
    unit_dir = tmp_path / "etc-systemd"

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: data_dir)
    monkeypatch.setattr(service_install, "_ENV_DIR", env_dir)
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)
    monkeypatch.setattr(
        service_install, "_ADMIN_WRAPPER_PATH", tmp_path / "usr-local-bin" / "frp-jump-server"
    )
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)
    monkeypatch.setattr(service_install.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(
        service_install, "resolve_exec_path", lambda name: "/usr/bin/frp-jump-server"
    )
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)

    bootstrapped = {}

    def fake_initialize(settings):
        bootstrapped["data_dir"] = settings.data_dir
        bootstrapped["relay_public_addr"] = settings.relay_public_addr
        return bootstrap.BootstrapResult(
            data_dir=settings.data_dir, db_path=settings.data_dir / "db.sqlite3", ca_cert_pem=b""
        )

    monkeypatch.setattr(bootstrap, "initialize", fake_initialize)

    unit_path = service_install.install(
        system_user="frp-jump", relay_public_addr="tunnel.example.com"
    )

    env_path = env_dir / "frp-jump.env"
    assert env_path.is_file()
    env_text = env_path.read_text()
    assert "FRP_JUMP_RELAY_PUBLIC_ADDR=tunnel.example.com" in env_text
    # No --tls-cert/--tls-key given -- defaults to loopback-only, since
    # `server run` refuses a public bind with no TLS configured.
    assert "FRP_JUMP_API_HOST=127.0.0.1" in env_text
    assert (env_path.stat().st_mode & 0o777) == 0o640
    assert bootstrapped["relay_public_addr"] == "tunnel.example.com"
    assert bootstrapped["data_dir"] == data_dir

    assert unit_path == unit_dir / "frp-jump-server.service"
    content = unit_path.read_text()
    assert "User=frp-jump" in content
    assert f"EnvironmentFile={env_path}" in content
    assert "ExecStart=/usr/bin/frp-jump-server run" in content


def test_install_writes_tls_paths_instead_of_loopback_when_given(tmp_path, monkeypatch):
    data_dir = tmp_path / "var-lib" / "frp-jump"
    env_dir = tmp_path / "etc-frp-jump"
    unit_dir = tmp_path / "etc-systemd"

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: data_dir)
    monkeypatch.setattr(service_install, "_ENV_DIR", env_dir)
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)
    monkeypatch.setattr(
        service_install, "_ADMIN_WRAPPER_PATH", tmp_path / "usr-local-bin" / "frp-jump-server"
    )
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)
    monkeypatch.setattr(service_install.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(
        service_install, "resolve_exec_path", lambda name: "/usr/bin/frp-jump-server"
    )
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(
        bootstrap,
        "initialize",
        lambda settings: bootstrap.BootstrapResult(
            data_dir=settings.data_dir, db_path=settings.data_dir / "db.sqlite3", ca_cert_pem=b""
        ),
    )

    service_install.install(
        system_user="frp-jump",
        relay_public_addr="tunnel.example.com",
        tls_cert_file=tmp_path / "fullchain.pem",
        tls_key_file=tmp_path / "privkey.pem",
    )

    env_text = (env_dir / "frp-jump.env").read_text()
    assert f"FRP_JUMP_TLS_CERT_FILE={tmp_path / 'fullchain.pem'}" in env_text
    assert f"FRP_JUMP_TLS_KEY_FILE={tmp_path / 'privkey.pem'}" in env_text
    assert "FRP_JUMP_API_HOST" not in env_text


def test_install_rejects_tls_cert_without_tls_key(monkeypatch, tmp_path):
    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)

    with pytest.raises(service_install.ServiceInstallError, match="--tls-cert and --tls-key"):
        service_install.install(
            relay_public_addr="tunnel.example.com", tls_cert_file=tmp_path / "fullchain.pem"
        )


def test_install_reruns_without_relay_public_addr_using_existing_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "var-lib" / "frp-jump"
    env_dir = tmp_path / "etc-frp-jump"
    env_dir.mkdir(parents=True)
    env_path = env_dir / "frp-jump.env"
    env_path.write_text(
        f"FRP_JUMP_DATA_DIR={data_dir}\nFRP_JUMP_RELAY_PUBLIC_ADDR=already.example.com\n"
    )
    unit_dir = tmp_path / "etc-systemd"

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: data_dir)
    monkeypatch.setattr(service_install, "_ENV_DIR", env_dir)
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)
    monkeypatch.setattr(
        service_install, "_ADMIN_WRAPPER_PATH", tmp_path / "usr-local-bin" / "frp-jump-server"
    )
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)
    monkeypatch.setattr(
        service_install, "resolve_exec_path", lambda name: "/usr/bin/frp-jump-server"
    )
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)

    bootstrapped = {}
    monkeypatch.setattr(
        bootstrap,
        "initialize",
        lambda settings: bootstrapped.update(relay_public_addr=settings.relay_public_addr),
    )

    service_install.install(system_user="frp-jump")

    assert bootstrapped["relay_public_addr"] == "already.example.com"


def test_read_env_value_finds_the_matching_key(tmp_path):
    env_path = tmp_path / "x.env"
    env_path.write_text("FRP_JUMP_DATA_DIR=/var/lib/x\nFRP_JUMP_RELAY_PUBLIC_ADDR=host.example\n")

    assert service_install._read_env_value(env_path, "FRP_JUMP_RELAY_PUBLIC_ADDR") == "host.example"
    assert service_install._read_env_value(env_path, "NOT_PRESENT") is None


def test_install_writes_an_admin_wrapper_that_sudos_admin_commands(tmp_path, monkeypatch):
    """The dedicated system account's data dir is 0700 -- without this
    wrapper, only root (or an explicit `sudo -u <name> env
    FRP_JUMP_DATA_DIR=...`) could run any admin command at all."""
    data_dir = tmp_path / "var-lib" / "frp-jump"
    env_dir = tmp_path / "etc-frp-jump"
    unit_dir = tmp_path / "etc-systemd"
    wrapper_path = tmp_path / "usr-local-bin" / "frp-jump-server"

    monkeypatch.setattr(service_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(service_install, "ensure_system_user", lambda name: data_dir)
    monkeypatch.setattr(service_install, "_ENV_DIR", env_dir)
    monkeypatch.setattr(service_install, "_SYSTEM_UNIT_DIR", unit_dir)
    monkeypatch.setattr(service_install, "_ADMIN_WRAPPER_PATH", wrapper_path)
    monkeypatch.setattr(service_install, "chown_tree", lambda path, name: None)
    monkeypatch.setattr(service_install.shutil, "chown", lambda *a, **k: None)
    monkeypatch.setattr(
        service_install, "resolve_exec_path", lambda name: "/usr/bin/frp-jump-server"
    )
    monkeypatch.setattr(service_install.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(
        bootstrap,
        "initialize",
        lambda settings: bootstrap.BootstrapResult(
            data_dir=settings.data_dir, db_path=settings.data_dir / "db.sqlite3", ca_cert_pem=b""
        ),
    )

    service_install.install(system_user="frp-jump", relay_public_addr="tunnel.example.com")

    assert wrapper_path.is_file()
    assert (wrapper_path.stat().st_mode & 0o777) == 0o755
    content = wrapper_path.read_text()
    assert f"FRP_JUMP_DATA_DIR={data_dir}" in content
    assert "sudo -u frp-jump" in content
    assert "/usr/bin/frp-jump-server" in content
    # install-service/init/run must pass straight through, unwrapped --
    # those need to run as root/under systemd, not the service account.
    assert "install-service|init|run)" in content
