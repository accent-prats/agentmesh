"""Coverage for the 2026-10-18 run-recency fix: a real production report
that a live analysis run given a large "Hours back" window (e.g. 200)
didn't show up in the Runs list, and its date looked wrong on the
Console. Root cause: `RunRecord.started_at` is the evidence-collection
window's *start* (`window_end - window_hours`, pipeline/live_run.py), a
caller-chosen value that can be days in the past - not when the run was
actually triggered - yet every "most recent run" query ordered by it.
`RunRecord.created_at` (set once, in repository.save_run(), never on a
later stage-transition call) is the real trigger-recency signal; these
tests reproduce the exact large-window scenario and confirm each
ordering call site now uses it (via the shared `_RUN_RECENCY` COALESCE
expression), plus the backward-compatibility fallback for rows an
already-deployed database wrote before this column existed."""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from culprit.db import repository
from culprit.db.engine import make_engine, make_session_factory
from culprit.db.models import RunRecord, RunStage
from culprit.models.patch_run import PatchRun, TriggerMode


def _make_run(session, run_id, scope_name, started_at, total_machines=10, failed_machines=0, stage=RunStage.COMPLETE):
    run = PatchRun(
        run_id=run_id, maintenance_configuration_id="mc-1", subscription_id="sub-1",
        scope_name=scope_name, started_at=started_at, total_machines=total_machines,
    )
    repository.save_run(session, run, stage=RunStage.STARTED)
    repository.update_run_stage(session, run_id, stage, ended_at=started_at, failed_machines=failed_machines)


def test_save_run_sets_created_at_once_and_never_touches_it_again(session_factory):
    with session_factory() as session:
        run = PatchRun(
            run_id="run-1", maintenance_configuration_id="mc-1", subscription_id="sub-1",
            scope_name="scope-a", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10,
        )
        repository.save_run(session, run, stage=RunStage.STARTED)
        first_created_at = session.get(RunRecord, "run-1").created_at
        assert first_created_at is not None

        # A later save_run() call for the same run_id (the orchestrator's
        # own stage-transition pattern) must not move created_at - it's
        # "when this run was first triggered," not "last touched."
        repository.save_run(session, run, stage=RunStage.CLUSTERED)
        assert session.get(RunRecord, "run-1").created_at == first_created_at


def test_list_runs_orders_by_trigger_recency_not_window_start(session_factory):
    """The exact reported bug: a run given a large lookback window has a
    `started_at` far in the past, but was triggered *after* a run with a
    small window - it must still sort as the most recent."""
    with session_factory() as session:
        # Triggered first, small window -> recent started_at.
        _make_run(session, "run-small-window", "scope-a", datetime(2026, 10, 17, tzinfo=timezone.utc) - timedelta(hours=50))
        # Triggered second (real wall-clock time, since created_at comes
        # from datetime.now()), but a 200-hour window pushes started_at
        # more than a week into the past - chronologically *before*
        # run-small-window's own started_at.
        _make_run(session, "run-large-window", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc) - timedelta(hours=200))

        runs = repository.list_runs(session)

    assert [r.run_id for r in runs] == ["run-large-window", "run-small-window"]


def test_list_runs_carries_created_at_through_to_run_summary(session_factory):
    with session_factory() as session:
        _make_run(session, "run-1", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc))
        runs = repository.list_runs(session)

    assert runs[0].created_at is not None


def test_latest_completed_run_id_prefers_trigger_recency_over_window_start(session_factory):
    with session_factory() as session:
        _make_run(session, "run-small-window", "scope-a", datetime(2026, 10, 17, tzinfo=timezone.utc) - timedelta(hours=50))
        _make_run(session, "run-large-window", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc) - timedelta(hours=200))

        assert repository.latest_completed_run_id(session) == "run-large-window"


def test_compliance_trend_orders_by_trigger_recency_not_window_start(session_factory):
    with session_factory() as session:
        _make_run(session, "run-small-window", "scope-a", datetime(2026, 10, 17, tzinfo=timezone.utc) - timedelta(hours=50), failed_machines=5)
        _make_run(session, "run-large-window", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc) - timedelta(hours=200), failed_machines=1)

        trend = repository.compliance_trend(session, "scope-a")

    # Oldest-first for charting, but "oldest" now means trigger order.
    assert [p.run_id for p in trend] == ["run-small-window", "run-large-window"]


def test_previous_completed_run_picks_the_last_triggered_not_the_earliest_window(session_factory):
    with session_factory() as session:
        _make_run(session, "run-small-window", "scope-a", datetime(2026, 10, 17, tzinfo=timezone.utc) - timedelta(hours=50))
        _make_run(session, "run-large-window", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc) - timedelta(hours=200))
        # A third run, triggered last, used as the one requesting "my
        # previous cycle" - should get run-large-window (triggered just
        # before it), not run-small-window (which has the later started_at
        # but was triggered first).
        _make_run(session, "run-latest", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc))

        latest_record = session.get(RunRecord, "run-latest")
        previous = repository._previous_completed_run(session, latest_record)

    assert previous is not None
    assert previous.run_id == "run-large-window"


def test_a_pre_migration_row_with_no_created_at_falls_back_to_started_at_for_ordering(session_factory):
    """Backward compatibility: a row an already-deployed database wrote
    before this column existed reads back as created_at=None - it must
    still sort sensibly (by started_at) rather than always ranking last/
    first under a NULL-ordering surprise."""
    with session_factory() as session:
        _make_run(session, "run-legacy-older", "scope-a", datetime(2026, 1, 1, tzinfo=timezone.utc))
        _make_run(session, "run-legacy-newer", "scope-a", datetime(2026, 1, 2, tzinfo=timezone.utc))
        session.get(RunRecord, "run-legacy-older").created_at = None
        session.get(RunRecord, "run-legacy-newer").created_at = None
        session.commit()

        runs = repository.list_runs(session)

    assert [r.run_id for r in runs] == ["run-legacy-newer", "run-legacy-older"]


def test_chat_latest_report_prefers_trigger_recency_over_window_start(session_factory):
    """routes_chat.py::_latest_report is a third "most recent run" query,
    found missed by an independent review of this fix - without this
    same _RUN_RECENCY fix, the chat/Q&A endpoint would answer questions
    against a stale run whenever the actual most-recently-triggered run
    was given a large lookback window."""
    from culprit.api.routes_chat import _latest_report

    with session_factory() as session:
        _make_run(session, "run-small-window", "scope-a", datetime(2026, 10, 17, tzinfo=timezone.utc) - timedelta(hours=50))
        _make_run(session, "run-large-window", "scope-a", datetime(2026, 10, 18, tzinfo=timezone.utc) - timedelta(hours=200))

        report = _latest_report(session)

    assert report is not None
    assert report.run.run_id == "run-large-window"


def test_an_existing_sqlite_database_without_the_new_column_gets_it_added():
    """Simulates the exact real-world risk: a deployed culprit.db whose
    runs table predates created_at - same ALTER-TABLE gotcha already
    proven out for machine_outcomes columns."""
    tmp = tempfile.mkdtemp()
    try:
        db_path = Path(tmp) / "pre_existing.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE runs (
                run_id VARCHAR NOT NULL PRIMARY KEY,
                maintenance_configuration_id VARCHAR,
                subscription_id VARCHAR,
                scope_name VARCHAR,
                trigger_mode VARCHAR,
                started_at DATETIME,
                ended_at DATETIME,
                total_machines INTEGER,
                failed_machines INTEGER,
                stage VARCHAR,
                checkpoint JSON
            )
        """)
        conn.execute(
            "INSERT INTO runs (run_id, maintenance_configuration_id, subscription_id, scope_name, "
            "trigger_mode, started_at, total_machines, failed_machines, stage, checkpoint) "
            "VALUES ('run-old', 'mc-1', 'sub-1', 'scope-a', 'scheduled', '2026-01-01 00:00:00', 10, 0, 'complete', '{}')"
        )
        conn.commit()
        conn.close()

        engine = make_engine(f"sqlite:///{db_path}")
        session_factory = make_session_factory(engine)  # this is the call under test

        conn = sqlite3.connect(str(db_path))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
        conn.close()
        assert "created_at" in columns

        with session_factory() as session:
            record = session.get(RunRecord, "run-old")
            assert record is not None
            assert record.created_at is None  # pre-existing row, no backfill - falls back via COALESCE

            # A brand-new run on this same (now-migrated) database gets a
            # real created_at going forward.
            run = PatchRun(
                run_id="run-new", maintenance_configuration_id="mc-1", subscription_id="sub-1",
                scope_name="scope-a", started_at=datetime.now(timezone.utc), total_machines=5,
                trigger_mode=TriggerMode.AD_HOC,
            )
            repository.save_run(session, run, stage=RunStage.STARTED)
            assert session.get(RunRecord, "run-new").created_at is not None

        engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
