"""SQLite engine/session plumbing for the control-plane database."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, create_engine

# Force model registration with SQLModel.metadata before the migration
# runner creates the tables.
from frp_jump.common import models as _models  # noqa: F401
from frp_jump.server.migrations import migrate_file, migrate_shared


def _enable_foreign_keys(dbapi_connection, connection_record) -> None:
    # SQLite ignores FOREIGN KEY constraints unless told otherwise, per
    # connection -- every `foreign_key=` in common/models.py is decorative
    # without this.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def make_engine(path: Path | str = ":memory:"):
    """Create the engine and bring the schema to the current version.

    Raises ``migrations.MigrationError`` when the schema cannot be
    upgraded (not writable, busy for longer than the lock timeout, or
    newer than this code).

    ``:memory:`` uses ``StaticPool`` so every connection shares the same
    database -- without it, each new connection (e.g. from a different
    thread, as FastAPI's TestClient uses) would see a fresh, empty
    in-memory database and every query would fail with "no such table".
    """
    if path == ":memory:":
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _enable_foreign_keys)
    if path == ":memory:":
        raw = engine.raw_connection()
        try:
            migrate_shared(raw.driver_connection)
        finally:
            raw.close()
    else:
        migrate_file(path)
    return engine


def make_session(engine) -> Session:
    return Session(engine)
