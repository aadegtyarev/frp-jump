from frp_jump.agent.hosts import ensure_include, render_ssh_config, write_ssh_config


def test_render_ssh_config_empty() -> None:
    text = render_ssh_config([])
    assert "managed by frp-jump" in text
    assert "Host" not in text


def test_render_ssh_config_one_entry() -> None:
    text = render_ssh_config([("wb01-ssh", 5000)])
    assert "Host wb01-ssh" in text
    assert "HostName 127.0.0.1" in text
    assert "Port 5000" in text


def test_render_ssh_config_multiple_entries_each_get_a_block() -> None:
    text = render_ssh_config([("wb01-ssh", 5000), ("wb02-ssh", 5001)])
    assert text.count("Host ") == 2
    assert "Port 5000" in text
    assert "Port 5001" in text


def test_write_ssh_config_writes_file(tmp_path) -> None:
    path = write_ssh_config(tmp_path, [("wb01-ssh", 5000)])
    assert path.exists()
    assert "Host wb01-ssh" in path.read_text()


def test_write_ssh_config_overwrites_on_regeneration(tmp_path) -> None:
    write_ssh_config(tmp_path, [("wb01-ssh", 5000)])
    write_ssh_config(tmp_path, [("wb02-ssh", 6000)])
    text = (tmp_path / "ssh_config").read_text()
    assert "wb01-ssh" not in text
    assert "wb02-ssh" in text


def test_ensure_include_adds_line_to_empty_file(tmp_path) -> None:
    ssh_config = tmp_path / "config"
    managed = tmp_path / "frp-jump" / "ssh_config"
    added = ensure_include(ssh_config, managed)
    assert added is True
    assert f"Include {managed}" in ssh_config.read_text()


def test_ensure_include_prepends_before_existing_content(tmp_path) -> None:
    ssh_config = tmp_path / "config"
    ssh_config.write_text("Host *\n    ForwardAgent yes\n")
    managed = tmp_path / "frp-jump" / "ssh_config"
    ensure_include(ssh_config, managed)
    text = ssh_config.read_text()
    assert text.index(str(managed)) < text.index("ForwardAgent")


def test_ensure_include_is_idempotent(tmp_path) -> None:
    ssh_config = tmp_path / "config"
    managed = tmp_path / "frp-jump" / "ssh_config"
    assert ensure_include(ssh_config, managed) is True
    assert ensure_include(ssh_config, managed) is False
    assert ssh_config.read_text().count(str(managed)) == 1
