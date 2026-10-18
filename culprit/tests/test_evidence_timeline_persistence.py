"""Persistence of EvidenceBundle.timeline - MachineOutcomeRecord's own
`timeline_json` column (db/models.py), round-tripped through
repository.save_machine_outcomes/get_machine_detail, plus the same real
deployment risk patch_extension_status_json's own test file already
covers for its column: Base.metadata.create_all() only creates missing
tables, never alters an existing one, so an already-deployed SQLite
file's machine_outcomes table (from before this column existed) needs
db/engine.py::_ensure_columns to add it without a real migration tool."""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from culprit.db.engine import make_engine, make_session_factory
from culprit.db.repository import _MAX_PERSISTED_TIMELINE_EVENTS


def _machine_identity():
    from culprit.models.evidence import MachineIdentity, OSFamily

    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def _cluster(machine):
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import OSFamily

    return Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=[ClusterMember(vm_id=machine.vm_id, vm_name=machine.vm_name)],
        representative_vm_id=machine.vm_id,
    )


def _save_run(session):
    from culprit.db import repository
    from culprit.models.patch_run import PatchRun, TriggerMode

    repository.save_run(session, PatchRun(
        run_id="run-1", maintenance_configuration_id="cfg", subscription_id="s",
        scope_name="test", started_at=datetime.now(timezone.utc), total_machines=1,
        trigger_mode=TriggerMode.AD_HOC,
    ))


def test_evidence_timeline_round_trips_through_save_and_load():
    from culprit.db import repository
    from culprit.models.evidence import EvidenceBundle, PatchOutcome, Source, TimelineEvent

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    machine = _machine_identity()
    events = [
        TimelineEvent(
            ts=datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc), source=Source.AZURE_CONTROL_PLANE,
            kind="patch_assessment", summary="patchassessmentresults -> Succeeded, 3 patch(es) pending",
            detail={"status": "Succeeded"}, raw_ref="resourcegraph:x",
        ),
        TimelineEvent(
            ts=datetime(2026, 10, 18, 8, 5, tzinfo=timezone.utc), source=Source.GUEST_LINUX,
            kind="repo_diagnostics", summary="Repo diagnostics for mirror.example.com: dns_resolved=False",
            detail={"repo_unreachable": True}, raw_ref="guest:repo_diagnostics:vm-1",
        ),
    ]
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc), timeline=events,
    )

    with session_factory() as session:
        _save_run(session)
        repository.save_cluster(session, _cluster(machine))
        repository.save_machine_outcomes(session, "run-1", "key-1", [bundle])

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    _, _, _, _, _, _, timeline, _ = detail
    assert len(timeline) == 2
    # persisted as plain JSON-safe dicts, not pydantic objects
    assert timeline[0]["kind"] == "patch_assessment"
    assert timeline[0]["raw_ref"] == "resourcegraph:x"
    assert timeline[1]["summary"] == "Repo diagnostics for mirror.example.com: dns_resolved=False"


def test_timeline_is_capped_keeping_the_most_recent_events():
    """Same cap discipline as every new collector parser's own
    MAX_ANOMALY_EVENTS_PER_SECTION - applied once more where this data
    crosses from transient to persisted, so a long-running machine with
    many collected events can't bloat the DB row or the eventual page."""
    from culprit.db import repository
    from culprit.models.evidence import EvidenceBundle, PatchOutcome, Source, TimelineEvent

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    machine = _machine_identity()
    base = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc)
    total = _MAX_PERSISTED_TIMELINE_EVENTS + 10
    events = [
        TimelineEvent(
            ts=base + timedelta(minutes=i), source=Source.AZURE_CONTROL_PLANE,
            kind="activity_log", summary=f"event {i}", raw_ref=f"activitylog:{i}",
        )
        for i in range(total)
    ]
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc), timeline=events,
    )

    with session_factory() as session:
        _save_run(session)
        repository.save_cluster(session, _cluster(machine))
        repository.save_machine_outcomes(session, "run-1", "key-1", [bundle])

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    _, _, _, _, _, _, timeline, _ = detail
    assert len(timeline) == _MAX_PERSISTED_TIMELINE_EVENTS
    kept_refs = {e["raw_ref"] for e in timeline}
    # oldest events (lowest index) must be the ones dropped, most recent kept
    assert f"activitylog:{total - 1}" in kept_refs
    assert "activitylog:0" not in kept_refs


def test_a_row_predating_the_column_reads_back_as_an_empty_list_not_none():
    """Same ALTER-TABLE-has-no-data-side-default gotcha as
    patch_extension_status_json's own test - a row written before this
    column existed reads back as raw None, not []. get_machine_detail
    must normalize that."""
    from culprit.db import repository
    from culprit.db.models import MachineOutcomeRecord

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)
    machine = _machine_identity()

    with session_factory() as session:
        _save_run(session)
        repository.save_cluster(session, _cluster(machine))
        # Bypasses save_machine_outcomes (which always sets a list) to
        # simulate a row genuinely written before this column existed.
        session.add(MachineOutcomeRecord(
            run_id="run-1", vm_id=machine.vm_id, vm_name=machine.vm_name, cluster_key="key-1",
            status="Failed", timeline_json=None,
        ))
        session.commit()

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    _, _, _, _, _, _, timeline, _ = detail
    assert timeline == []


def test_an_existing_sqlite_database_without_the_new_column_gets_it_added():
    """Simulates the exact real-world risk: a deployed culprit.db whose
    machine_outcomes table was created before timeline_json existed."""
    from culprit.db import repository
    from culprit.models.evidence import EvidenceBundle, PatchOutcome

    tmp = tempfile.mkdtemp()
    try:
        db_path = Path(tmp) / "pre_existing.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE machine_outcomes (
                run_id VARCHAR NOT NULL,
                vm_id VARCHAR NOT NULL,
                vm_name VARCHAR,
                cluster_key VARCHAR,
                status VARCHAR,
                error_code VARCHAR,
                error_message TEXT,
                packages_failed_json JSON,
                kbs_failed_json JSON,
                reboot_status VARCHAR,
                started_at DATETIME,
                ended_at DATETIME,
                window_minutes INTEGER,
                collection_gaps_json JSON,
                patch_extension_status_json JSON,
                error_details_json JSON,
                PRIMARY KEY (run_id, vm_id)
            )
        """)
        conn.commit()
        conn.close()

        engine = make_engine(f"sqlite:///{db_path}")
        session_factory = make_session_factory(engine)  # this is the call under test

        conn = sqlite3.connect(str(db_path))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(machine_outcomes)")}
        conn.close()
        assert "timeline_json" in columns

        machine = _machine_identity()
        bundle = EvidenceBundle(
            run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
            collection_started_at=datetime.now(timezone.utc),
        )
        with session_factory() as session:
            _save_run(session)
            repository.save_machine_outcomes(session, "run-1", "key-1", [bundle])

        engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
