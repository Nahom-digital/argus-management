"""Shared fixtures. The panel is a single-process app that talks to a real
PostgreSQL instance, so these tests talk to the same database the panel does
and clean up after themselves rather than mocking the layer under test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def db():
    import DB
    DB.init_pool()
    yield DB
    DB.close_pool()


@pytest.fixture
def conn(db):
    c = db.get_connection()
    try:
        yield c
    finally:
        db.release_connection(c)
