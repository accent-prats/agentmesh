"""Coverage for get_session_factory()'s lazy, lru_cache-backed
construction - specifically the cold-start concurrency race found
2026-10-13 while reviewing the Settings redesign: a fresh process's first
page load fires loadAzure()/loadDatadog()/loadSchedule() concurrently,
each hitting its own `def` (sync) route handler on FastAPI's threadpool,
each missing the still-empty lru_cache and racing into
Base.metadata.create_all() on the same file-backed sqlite DB - one loses
with `sqlite3.OperationalError: table ... already exists`.

lru_cache's own lock only guards its cache dict, released before calling
the wrapped function - it does not stop two concurrent misses from both
running the function body. The actual sqlite TOCTOU race (both threads'
checkfirst introspection completing before either's CREATE TABLE) is too
timing-sensitive to reproduce reliably with real threads and no
artificial delay, so this test instead verifies the fix's actual
mechanism directly: make_session_factory must never run on more than one
thread at once, regardless of how the DB driver's own race would or
wouldn't resolve."""
from __future__ import annotations

import dataclasses
import threading
import time

import culprit.api.deps as deps_module
import culprit.config as config_module
import culprit.db.engine as engine_module


def test_concurrent_first_calls_never_run_make_session_factory_in_parallel(monkeypatch, tmp_path):
    db_path = tmp_path / "race.db"
    monkeypatch.setattr(
        config_module, "settings",
        dataclasses.replace(config_module.settings, database_url=f"sqlite:///{db_path}"),
    )
    deps_module.get_session_factory.cache_clear()

    active = 0
    max_concurrent = 0
    count_lock = threading.Lock()
    real_make_session_factory = engine_module.make_session_factory

    def spy(engine=None):
        nonlocal active, max_concurrent
        with count_lock:
            active += 1
            max_concurrent = max(max_concurrent, active)
        try:
            time.sleep(0.05)  # widen the window - any real overlap must land inside this sleep
            return real_make_session_factory(engine)
        finally:
            with count_lock:
                active -= 1

    # deps.py did `from culprit.db.engine import make_session_factory`, so
    # the name to patch is the one bound in deps_module's own namespace,
    # not engine_module's - get_session_factory() calls that local name.
    monkeypatch.setattr(deps_module, "make_session_factory", spy)

    errors = []

    def worker():
        try:
            deps_module.get_session_factory()
        except Exception as exc:  # noqa: BLE001 - captured for the assertion below, not re-raised
            errors.append(exc)

    # A barrier maximizes the odds every thread misses the lru_cache at
    # the exact same instant - starting threads without synchronizing
    # their first call could pass even with the race still present.
    barrier = threading.Barrier(8)

    def synced_worker():
        barrier.wait()
        worker()

    threads = [threading.Thread(target=synced_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrent get_session_factory() calls raised: {errors}"
    assert max_concurrent == 1, "make_session_factory ran concurrently on more than one thread"
