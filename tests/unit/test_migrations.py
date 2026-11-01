import multiprocessing
import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlmodel import select

from frp_jump.common.models import Device
from frp_jump.server import migrations
from frp_jump.server.db import make_engine, make_session
from frp_jump.server.migrations import MigrationError

# The schema 0.3.18 created, as dumped from a real database file.
SCHEMA_0_3 = (Path(__file__).parent.parent / "support" / "schema_0_3.sql").read_text()
NEW_COLUMNS = ("label", "icon", "kind")

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")


def make_0_3_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_0_3)
    conn.execute(
        "INSERT INTO users VALUES ('u1', 'alice', 'ssh-ed25519 AAAA', 'SHA256:x', "
        "'2026-01-01 00:00:00')"
    )
    conn.execute(
        "INSERT INTO devices VALUES ('d1', 'wb01', 'u1', '42', 'hash', "
        "'2026-01-01 00:00:00', NULL, '0.3.18', 1)"
    )
    conn.commit()
    conn.close()


def version_of(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT version FROM schema_version").fetchone()[0]
    finally:
        conn.close()


def device_columns(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute("PRAGMA table_info(devices)")]
    finally:
        conn.close()


def table_names(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    finally:
        conn.close()


def version_rows(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
    finally:
        conn.close()


def set_version(path: Path, version: int) -> None:
    conn = sqlite3.connect(path)
    conn.execute("UPDATE schema_version SET version = ?", (version,))
    conn.commit()
    conn.close()


@pytest.fixture
def read_only(tmp_path):
    """chmod the database file (and its directory) read-only; undone after."""
    changed = []

    def apply(path: Path) -> None:
        for target, mode in ((path, 0o444), (path.parent, 0o555)):
            changed.append((target, target.stat().st_mode))
            target.chmod(mode)

    yield apply
    for target, mode in reversed(changed):
        target.chmod(mode)


def test_0_3_database_keeps_its_rows_and_gains_null_columns(tmp_path):
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)

    engine = make_engine(path)

    with make_session(engine) as db:
        device = db.exec(select(Device)).one()
    assert (device.id, device.name, device.owner_user_id) == ("d1", "wb01", "u1")
    assert (device.cert_serial, device.agent_version, device.enabled) == ("42", "0.3.18", True)
    assert (device.label, device.icon, device.kind) == (None, None, None)
    assert version_of(path) == 1
    engine.dispose()


def test_fresh_database_gets_current_tables_without_alter(tmp_path, monkeypatch):
    altered = []
    monkeypatch.setattr(migrations, "_add_column", lambda conn, t, c: altered.append(c))
    path = tmp_path / "db.sqlite3"

    make_engine(path).dispose()

    assert altered == []
    assert version_of(path) == 1
    assert set(NEW_COLUMNS) <= set(device_columns(path))


def test_memory_database_is_migrated_on_the_shared_connection():
    engine = make_engine(":memory:")

    with make_session(engine) as db:
        assert db.exec(select(Device)).all() == []
        assert db.exec(text("SELECT version FROM schema_version")).one() == (1,)
        columns = [row[1] for row in db.exec(text("PRAGMA table_info(devices)"))]
    assert set(NEW_COLUMNS) <= set(columns)
    raw = engine.raw_connection()
    try:
        # The runner's autocommit mode must not leak into the app's sessions.
        assert raw.driver_connection.isolation_level == ""
    finally:
        raw.close()


@needs_non_root
def test_second_open_writes_nothing(tmp_path, read_only, monkeypatch):
    path = tmp_path / "db.sqlite3"
    make_engine(path).dispose()
    read_only(path)

    def no_writes(conn):
        raise AssertionError("an up-to-date database must not be written")

    monkeypatch.setattr(migrations, "_create_model_tables", no_writes)
    engine = make_engine(path)
    with make_session(engine) as db:
        assert db.exec(select(Device)).all() == []
    engine.dispose()


@needs_non_root
def test_read_only_database_with_pending_migration_is_refused(tmp_path, read_only):
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)
    read_only(path)

    with pytest.raises(MigrationError, match=r"needs a schema upgrade \(version 0 → 1\) but is "
                       r"not writable by .+; run as the service account"):
        make_engine(path)

    assert "schema_version" not in table_names(path)
    assert "label" not in device_columns(path)


def test_newer_database_is_refused(tmp_path):
    path = tmp_path / "db.sqlite3"
    make_engine(path).dispose()
    set_version(path, 2)

    with pytest.raises(
        MigrationError,
        match=r"database schema version 2 is newer than this frp-jump supports \(1\); "
        r"upgrade frp-jump",
    ):
        make_engine(path)


def test_locked_database_is_reported_busy(tmp_path, monkeypatch):
    monkeypatch.setattr(migrations, "LOCK_TIMEOUT_SECONDS", 0.1)
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(MigrationError, match="the database is busy; another frp-jump"):
            make_engine(path)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert "label" not in device_columns(path)


def _open_after_barrier(path, barrier, results):
    barrier.wait(timeout=10)
    try:
        make_engine(path).dispose()
        results.put("ok")
    except Exception as exc:  # reported to the parent, which fails the test
        results.put(repr(exc))


def _open_concurrently(path: Path) -> list[str]:
    ctx = multiprocessing.get_context("fork")
    barrier = ctx.Barrier(2)
    results = ctx.Queue()
    procs = [
        ctx.Process(target=_open_after_barrier, args=(path, barrier, results)) for _ in range(2)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=30)
    return [results.get(timeout=5) for _ in procs]


def test_two_processes_migrate_a_0_3_file_once(tmp_path):
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)

    assert _open_concurrently(path) == ["ok", "ok"]

    columns = device_columns(path)
    for column in NEW_COLUMNS:
        assert columns.count(column) == 1
    assert version_of(path) == 1
    assert version_rows(path) == 1


def test_two_processes_create_an_empty_file_once(tmp_path):
    path = tmp_path / "db.sqlite3"
    path.touch()

    assert _open_concurrently(path) == ["ok", "ok"]

    tables = table_names(path)
    assert len(tables) == len(set(tables))
    assert {"devices", "users", "grants", "schema_version"} <= set(tables)
    assert version_of(path) == 1
    assert version_rows(path) == 1


def test_runner_waiting_for_the_lock_sees_the_other_migration_and_does_nothing(
    tmp_path, monkeypatch
):
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)
    # The parent plays the other process: it migrates under its own write
    # lock and commits only once the runner has read version 0 and is
    # waiting for that lock.
    other = sqlite3.connect(path, isolation_level=None)
    other.execute("BEGIN IMMEDIATE")
    migrations._migration_1(other)
    other.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    other.execute("INSERT INTO schema_version (version) VALUES (1)")

    def must_not_run(*args):
        raise AssertionError("the runner must not write after another process migrated")

    monkeypatch.setattr(migrations, "_create_model_tables", must_not_run)
    monkeypatch.setattr(migrations, "MIGRATIONS", [(1, must_not_run)])
    first_read = threading.Event()
    read_version = migrations._read_version

    def signalling_read(conn):
        version = read_version(conn)
        first_read.set()
        return version

    monkeypatch.setattr(migrations, "_read_version", signalling_read)
    outcome = []

    def runner():
        try:
            migrations.migrate_file(path)
            outcome.append("ok")
        except BaseException as exc:
            outcome.append(repr(exc))

    thread = threading.Thread(target=runner)
    thread.start()
    try:
        assert first_read.wait(timeout=10)
        time.sleep(0.3)  # the runner is now blocked on BEGIN IMMEDIATE
        other.execute("COMMIT")
    finally:
        thread.join(timeout=15)
        other.close()

    assert outcome == ["ok"]
    assert version_of(path) == 1
    assert version_rows(path) == 1


def test_failing_step_rolls_back_everything(tmp_path, monkeypatch):
    def broken_step(conn):
        migrations._migration_1(conn)
        raise RuntimeError("step failed after its ALTER")

    monkeypatch.setattr(migrations, "MIGRATIONS", [(1, broken_step)])
    path = tmp_path / "db.sqlite3"
    make_0_3_db(path)

    with pytest.raises(RuntimeError, match="step failed after its ALTER"):
        make_engine(path)

    assert "label" not in device_columns(path)
    assert "schema_version" not in table_names(path)


def test_add_column_treats_duplicate_column_as_applied(tmp_path):
    conn = sqlite3.connect(tmp_path / "db.sqlite3", isolation_level=None)
    conn.execute("CREATE TABLE devices (id VARCHAR, label VARCHAR)")

    migrations._add_column(conn, "devices", "label")

    assert [row[1] for row in conn.execute("PRAGMA table_info(devices)")] == ["id", "label"]
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        migrations._add_column(conn, "missing", "label")
    conn.close()
