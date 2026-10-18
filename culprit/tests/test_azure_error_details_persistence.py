"""Persistence of PatchOutcome.error_details - MachineOutcomeRecord's own
`error_details_json` column (db/models.py), round-tripped through
repository.save_machine_outcomes/get_machine_detail, plus the real
deployment risk this surfaced: Base.metadata.create_all() only creates
missing tables, never alters an existing one, so an already-deployed
SQLite file's machine_outcomes table (from before this column existed)
needed db/engine.py::_ensure_columns to add it without a real migration
tool - same risk already proven out for patch_extension_status_json
(test_patch_extension_status_persistence.py), now repeated for this
column."""
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
        vm_name="vm-1", resource_group="rg", subscription_id="s", os_family=OSFamily.WINDOWS,
    )


def test_error_details_round_trips_through_save_and_load():
    from culprit.db import repository
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import AzureApiErrorDetail, EvidenceBundle, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    machine = _machine_identity()
    outcome = PatchOutcome(
        status="Failed",
        error_details=[
            AzureApiErrorDetail(code="Error", message="There is no enough time left to continue applying the next update"),
        ],
    )
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=outcome,
        collection_started_at=datetime.now(timezone.utc),
    )
    cluster = Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.WINDOWS, failing_target=""),
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
    _, _, _, loaded_outcome, _, _, _ = detail
    assert len(loaded_outcome.error_details) == 1
    assert loaded_outcome.error_details[0].code == "Error"
    assert "no enough time left" in loaded_outcome.error_details[0].message


def test_a_row_predating_the_column_reads_back_as_an_empty_list_not_none():
    """Same ALTER-TABLE-has-no-data-side-default gotcha as
    patch_extension_status_json's own test - a row written before this
    migration reads error_details_json back as raw None."""
    from culprit.db import repository
    from culprit.db.models import MachineOutcomeRecord
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import OSFamily
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)
    machine = _machine_identity()
    cluster = Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="x", os_family=OSFamily.WINDOWS, failing_target=""),
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
        session.add(MachineOutcomeRecord(
            run_id="run-1", vm_id=machine.vm_id, vm_name=machine.vm_name, cluster_key="key-1",
            status="Failed", error_details_json=None,
        ))
        session.commit()

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    _, _, _, loaded_outcome, _, _, _ = detail
    assert loaded_outcome.error_details == []


def test_an_existing_sqlite_database_without_the_new_column_gets_it_added():
    """Simulates the exact real-world risk: a deployed culprit.db whose
    machine_outcomes table predates error_details_json."""
    from culprit.db import repository
    from culprit.models.evidence import AzureApiErrorDetail, EvidenceBundle, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

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
        assert "error_details_json" in columns

        machine = _machine_identity()
        bundle = EvidenceBundle(
            run_id="run-1", machine=machine,
            outcome=PatchOutcome(status="Failed", error_details=[AzureApiErrorDetail(code="Error", message="x")]),
            collection_started_at=datetime.now(timezone.utc),
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
