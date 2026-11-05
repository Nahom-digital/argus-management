"""One telemetry sampler feeds every dashboard reader.

psutil's CPU and network rates are deltas from the previous call. A local page,
a linked panel and the Telegram bot used to call live_stats() independently,
so each reset the other's baseline and reported a different speed for the same
machine. These tests pin the shared snapshot that fixes that.
"""
import inspect

import System


def test_live_stats_returns_the_same_snapshot_to_every_caller(monkeypatch):
    calls = []
    started = []

    def fake_sample():
        calls.append(True)
        return {"ts": 123.0, "net": {"rate_in": 42.0}}

    monkeypatch.setattr(System, "_sample_live_stats", fake_sample)
    monkeypatch.setattr(System, "_stats_cache", {"t": 0.0, "value": None})
    monkeypatch.setattr(System, "_stats_thread", None)
    monkeypatch.setattr(System, "_start_stats_sampler",
                        lambda: started.append(True))

    first = System.live_stats()
    second = System.live_stats()

    assert first is second
    assert first["net"]["rate_in"] == 42.0
    assert calls == [True]
    assert started == [True, True]


def test_the_sampler_uses_a_daemon_thread_and_keeps_the_last_good_sample():
    loop = inspect.getsource(System._live_stats_loop)
    starter = inspect.getsource(System._start_stats_sampler)
    assert "except Exception as exc:" in loop
    assert "keep the last good snapshot" in loop
    assert "_stats_cache[\"value\"] = sample" in loop
    assert "name=\"argus-live-stats\", daemon=True" in starter
