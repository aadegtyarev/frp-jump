import pytest

from frp_jump.server.db import make_engine, make_session


@pytest.fixture
def db_session():
    engine = make_engine(":memory:")
    with make_session(engine) as session:
        yield session
