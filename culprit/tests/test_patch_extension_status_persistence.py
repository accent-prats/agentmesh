"""Persistence of patch_extension_status - MachineOutcomeRecord's own
`patch_extension_status_json` column (db/models.py), round-tripped through
repository.save_machine_outcomes/get_machine_detail, plus the real
deployment risk this surfaced: Base.metadata.create_all() only creates
missing tables, never alters an existing one, so an already-deployed
SQLite file's machine_outcomes table (from before this column existed)
needed db/engine.py::_ensure_columns to add it without a real migration
tool."""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from culprit.db.engine import make_engine, make_session_factory


def _machine_identity():
    from culprit.models.evidence import MachineIdentity, OSFamily

    return MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.LINUX,
    )


def test_patch_extension_status_round_trips_through_save_and_load():
    from culprit.db import repository
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    findings = [{"source": "guest_linux", "extension_name": "Microsoft.CPlat.Core.LinuxPatchExtension",
                 "status": "error", "code": 1, "message": "No space left on device", "substatus_name": None,
                 "raw_status_json": '[{"status": {}}]'}]
    machine = _machine_identity()
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc), patch_extension_status=findings,
    )
    cluster = Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.LINUX, failing_target=""),
        members=[ClusterMember(vm_id=machine.vm_id, vm_name=machine.vm_name)],
        representative_vm_id=machine.vm_id,
    )

    with session_factory() as session:
        repository.save_run(session, PatchRun(
            run_id="run-1", maintenance_configuration_id="cfg", subscription_id="s",
            scope_name="test", started_at=datetime.now(timezone.utc), total_machines=1,
            trigger_mode=TriggerMode.AD_HOC,
        ))
        repository.save_cluster(session, cluster)
        repository.save_machine_outcomes(session, "run-1", "key-1", [bundle])

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    _, _, _, _, _, patch_extension_status = detail
    assert patch_extension_status == findings


def test_an_existing_sqlite_database_without_the_new_column_gets_it_added():
    """Simulates the exact real-world risk: a deployed culprit.db whose
    machine_outcomes table was created before patch_extension_status_json
    existed. Base.metadata.create_all() alone would leave this table as-is
    (it only creates missing tables) - make_session_factory must still add
    the column via db/engine.py::_ensure_columns, or the very first real
    save_machine_outcomes call against this file would crash with
    "no such column"."""
    from culprit.db import repository
    from culprit.models.evidence import EvidenceBundle, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    # A plain mkdtemp + best-effort manual cleanup, not
    # tempfile.TemporaryDirectory - SQLite on Windows can leave a file
    # handle open slightly past engine.dispose() (an OS/GC timing quirk,
    # not a real resource leak), and TemporaryDirectory's own __exit__
    # treats a leftover file as a hard test failure instead of something
    # to shrug off the way a scratch temp directory should be.
    tmp = tempfile.mkdtemp()
    try:
        db_path = Path(tmp) / "pre_existing.db"

        # Build the OLD schema by hand - every machine_outcomes column
        # except the new one - mirroring exactly what a real deployment's
        # file looked like before this feature shipped.
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
                PRIMARY KEY (run_id, vm_id)
            )
        """)
        conn.commit()
        conn.close()

        engine = make_engine(f"sqlite:///{db_path}")
        # `runs` deliberately isn't pre-created - this test is about a
        # pre-existing table missing a *column*, not a missing table (that
        # case is already what create_all() handles correctly on its own).
        session_factory = make_session_factory(engine)  # this is the call under test

        # Confirm the column is really there, not just that create_all/
        # _ensure_columns ran without raising.
        conn = sqlite3.connect(str(db_path))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(machine_outcomes)")}
        conn.close()
        assert "patch_extension_status_json" in columns

        # And confirm a real save actually works against this file now.
        machine = _machine_identity()
        bundle = EvidenceBundle(
            run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
            collection_started_at=datetime.now(timezone.utc),
            patch_extension_status=[{"source": "guest_linux", "status": "error"}],
        )
        with session_factory() as session:
            repository.save_run(session, PatchRun(
                run_id="run-1", maintenance_configuration_id="cfg", subscription_id="s",
                scope_name="test", started_at=datetime.now(timezone.utc), total_machines=1,
                trigger_mode=TriggerMode.AD_HOC,
            ))
            repository.save_machine_outcomes(session, "run-1", "key-1", [bundle])

        engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_ensure_columns_is_idempotent_and_safe_on_a_fresh_database():
    """A brand-new database (create_all built machine_outcomes WITH the
    column already) must not error when _ensure_columns runs its own
    PRAGMA/ALTER check against it a second time (make_session_factory is
    called more than once in a process's lifetime in several places)."""
    engine = make_engine("sqlite:///:memory:")
    make_session_factory(engine)
    make_session_factory(engine)  # must not raise "duplicate column"
