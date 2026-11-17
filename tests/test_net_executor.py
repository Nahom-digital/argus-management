"""Outbound linked-server calls must not share the database worker pool.

A peer that is slow to answer, or never answers, would otherwise hold DB
workers and freeze ordinary panel requests behind it.
"""
import asyncio
import threading
import pytest

import DB


def _thread_name():
    return threading.current_thread().name


def test_run_net_uses_the_network_executor_not_the_db_executor():
    db_name = asyncio.run(DB.run(_thread_name))
    net_name = asyncio.run(DB.run_net(_thread_name))

    assert db_name.startswith("db")
    assert net_name.startswith("argus-net")
    assert db_name != net_name


def test_run_net_propagates_exceptions():
    def boom():
        raise ValueError("remote peer failed")

    with pytest.raises(ValueError, match="remote peer failed"):
        asyncio.run(DB.run_net(boom))


def test_run_keeps_its_existing_result_and_keyword_semantics():
    assert asyncio.run(DB.run(lambda a, b=0: a + b, 2, b=3)) == 5


def test_a_closed_pool_refuses_to_rebuild_itself(monkeypatch):
    """Shutdown must not let an in-flight network task recreate the pool."""
    monkeypatch.setattr(DB, "_CLOSED", True)
    with pytest.raises(RuntimeError, match="shutting down"):
        DB._get_pool()
    with pytest.raises(RuntimeError, match="shutting down"):
        DB._get_net_executor()
