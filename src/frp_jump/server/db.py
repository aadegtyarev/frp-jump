"""SQLite engine/session plumbing for the control-plane database."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Force model registration with SQLModel.metadata before create_all().
from frp_jump.common import models as _models  # noqa: F401


def make_engine(path: Path | str = ":memory:"):
    """Create the engine and ensure the schema exists.

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
    SQLModel.metadata.create_all(engine)
    return engine


def make_session(engine) -> Session:
    return Session(engine)
