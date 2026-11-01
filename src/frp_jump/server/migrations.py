"""Versioned schema migrations for the control-plane database.

``SQLModel.metadata.create_all`` creates missing tables but never adds a
column to an existing one, so a schema change after a release needs a
step of its own. The schema version lives in ``schema_version`` (one row,
one integer); a missing table or row is version 0, the 0.3.x schema.

The table is created in raw SQL, not as a SQLModel model, so nothing but
this runner, under its write lock, ever creates it. The model's tables
are created here too, under the same lock, so two processes starting on
an empty file cannot both create them.
"""

from __future__ import annotations

import os
import pwd
import sqlite3
from collections.abc import Callable
from pathlib import Path

from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.schema import CreateIndex, CreateTable
from sqlmodel import SQLModel

LOCK_TIMEOUT_SECONDS = 10


class MigrationError(RuntimeError):
    """The schema could not be brought to the version this code expects."""


def _add_column(conn: sqlite3.Connection, table: str, column: str) -> None:
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR")
    except sqlite3.OperationalError as exc:
        # Only possible when something changed the schema without this
        # runner's lock (a hand-run sqlite3): the column is already there.
        if "duplicate column name" not in str(exc):
            raise


def _add_missing_columns(conn: sqlite3.Connection, table: str, columns: list[str]) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for column in columns:
        if column not in existing:
            _add_column(conn, table, column)


def _migration_1(conn: sqlite3.Connection) -> None:
    """Device label, icon override and detected kind."""
    _add_missing_columns(conn, "devices", ["label", "icon", "kind"])


MIGRATIONS: list[tuple[int, Callable[[sqlite3.Connection], None]]] = [
    (1, _migration_1),
]
CURRENT_VERSION = MIGRATIONS[-1][0]


def _read_version(conn: sqlite3.Connection) -> int:
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if not has_table:
        return 0
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return row[0] if row else 0


def _write_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))


def _create_model_tables(conn: sqlite3.Connection) -> None:
    # Not metadata.create_all: that opens and commits a transaction of its
    # own and would end BEGIN IMMEDIATE early.
    dialect = sqlite_dialect.dialect()
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    for table in SQLModel.metadata.sorted_tables:
        conn.execute(str(CreateTable(table, if_not_exists=True).compile(dialect=dialect)))
        for index in sorted(table.indexes, key=lambda i: i.name or ""):
            conn.execute(str(CreateIndex(index, if_not_exists=True).compile(dialect=dialect)))


def _check_not_newer(version: int) -> None:
    if version > CURRENT_VERSION:
        raise MigrationError(
            f"database schema version {version} is newer than this frp-jump supports "
            f"({CURRENT_VERSION}); upgrade frp-jump"
        )


def _current_user() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return f"uid {os.geteuid()}"


def _not_writable(location: str, version: int) -> MigrationError:
    return MigrationError(
        f"the database at {location} needs a schema upgrade (version {version} → "
        f"{CURRENT_VERSION}) but is not writable by {_current_user()}; run as the service "
        "account (sudo frp-jump-server …) or start the service once"
    )


def _busy() -> MigrationError:
    return MigrationError("the database is busy; another frp-jump process holds it; retry")


def migrate_connection(conn: sqlite3.Connection, location: str) -> None:
    """Bring the database behind ``conn`` to ``CURRENT_VERSION``.

    ``conn`` must be in autocommit mode (``isolation_level=None``): every
    BEGIN/COMMIT/ROLLBACK here is the runner's own. An up-to-date database
    is only read, so it never needs write access.
    """
    version = 0
    try:
        version = _read_version(conn)
        _check_not_newer(version)
        if version == CURRENT_VERSION:
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            _create_model_tables(conn)
            version = _read_version(conn)
            _check_not_newer(version)
            for step_version, step in MIGRATIONS:
                if step_version > version:
                    step(conn)
            if version != CURRENT_VERSION:
                _write_version(conn, CURRENT_VERSION)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    except sqlite3.OperationalError as exc:
        code = exc.sqlite_errorcode & 0xFF
        if code == sqlite3.SQLITE_BUSY:
            raise _busy() from exc
        if code in (sqlite3.SQLITE_READONLY, sqlite3.SQLITE_CANTOPEN):
            raise _not_writable(location, version) from exc
        raise


def migrate_file(path: Path | str) -> None:
    """Migrate the SQLite file at ``path`` on a raw connection of its own.

    pysqlite's default transaction handling decides by itself when to emit
    BEGIN and COMMIT; ``isolation_level=None`` hands that to the runner, so
    the write lock really spans every statement of the upgrade.
    """
    conn = sqlite3.connect(path, isolation_level=None, timeout=LOCK_TIMEOUT_SECONDS)
    try:
        migrate_connection(conn, str(path))
    finally:
        conn.close()


def migrate_shared(dbapi_conn: sqlite3.Connection) -> None:
    """Migrate an in-memory database through its one shared connection.

    A fresh ``sqlite3.connect(":memory:")`` would be a different, empty
    database, so the engine's own connection is borrowed and its
    transaction mode restored afterwards.
    """
    previous = dbapi_conn.isolation_level
    dbapi_conn.isolation_level = None
    try:
        migrate_connection(dbapi_conn, ":memory:")
    finally:
        dbapi_conn.isolation_level = previous
