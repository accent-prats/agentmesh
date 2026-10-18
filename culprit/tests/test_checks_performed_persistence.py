"""Persistence of checks_performed - MachineOutcomeRecord's own
`checks_performed_json` column (db/models.py), round-tripped through
repository.save_machine_outcomes/get_machine_detail. Same already-deployed-
DB risk and same fix as patch_extension_status_json/timeline_json before
it (see that file's own docstring): Base.metadata.create_all() only
creates missing tables, never alters an existing one, so db/engine.py::
_ensure_columns must add this column to an already-deployed SQLite file."""
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


def test_checks_performed_round_trips_through_save_and_load():
    from culprit.db import repository
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    checks = ["subscription-manager (entitlement) status", "disk usage"]
    machine = _machine_identity()
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc), checks_performed=checks,
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
    checks_performed = detail.checks_performed
    assert checks_performed == checks


def test_checks_unavailable_and_sources_attempted_round_trip_through_save_and_load():
    """checks_unavailable (collectors/guest_linux.py's own tool-missing
    exclusion) and sources_attempted (which Source the fan-out actually
    dispatched a collector for) - both added the same day for the "show
    all logs used/not used" feature, same round-trip proof as
    checks_performed above."""
    from culprit.db import repository
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, OSFamily, PatchOutcome, Source
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    machine = _machine_identity()
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc),
        checks_unavailable=["subscription-manager (entitlement) status"],
        sources_attempted=[Source.AZURE_CONTROL_PLANE, Source.GUEST_LINUX],
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
    assert detail.checks_unavailable == ["subscription-manager (entitlement) status"]
    assert detail.sources_attempted == ["azure_control_plane", "guest_linux"]


def test_checks_finding_counts_round_trips_through_save_and_load():
    """checks_finding_counts (added by review 2026-10-19) - each guest
    check's TRUE, uncapped event count, needed because timeline_json is
    capped and could otherwise make a genuine finding read back as "no
    issues found." Same round-trip proof as the other fields above."""
    from culprit.db import repository
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import EvidenceBundle, OSFamily, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    engine = make_engine("sqlite:///:memory:")
    session_factory = make_session_factory(engine)

    machine = _machine_identity()
    bundle = EvidenceBundle(
        run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
        collection_started_at=datetime.now(timezone.utc),
        checks_finding_counts={"subscription-manager (entitlement) status": 1, "dpkg package manager log": 2},
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
    assert detail.checks_finding_counts == {"subscription-manager (entitlement) status": 1, "dpkg package manager log": 2}


def test_a_row_predating_the_column_reads_back_as_an_empty_list_not_none():
    """Same ALTER-TABLE-has-no-data-side-default gotcha as
    patch_extension_status_json's own test - a row written before this
    column existed reads back as raw None, not []. get_machine_detail must
    normalize that, since it's the one place this raw value reaches a
    caller outside this module."""
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
        # Bypasses save_machine_outcomes (which always sets a list) to
        # simulate a row genuinely written before this column existed.
        session.add(MachineOutcomeRecord(
            run_id="run-1", vm_id=machine.vm_id, vm_name=machine.vm_name, cluster_key="key-1",
            status="Failed", checks_performed_json=None, checks_unavailable_json=None,
            sources_attempted_json=None, checks_finding_counts_json=None,
        ))
        session.commit()

    with session_factory() as session:
        detail = repository.get_machine_detail(session, "run-1", "vm-1")

    assert detail is not None
    assert detail.checks_performed == []
    assert detail.checks_unavailable == []
    assert detail.sources_attempted == []
    assert detail.checks_finding_counts == {}


def test_an_existing_sqlite_database_without_the_new_column_gets_it_added():
    """Simulates the exact real-world risk: a deployed culprit.db whose
    machine_outcomes table was created before checks_performed_json
    existed. Base.metadata.create_all() alone would leave this table as-is
    (it only creates missing tables) - make_session_factory must still add
    the column via db/engine.py::_ensure_columns, or the very first real
    save_machine_outcomes call against this file would crash with
    "no such column"."""
    from culprit.db import repository
    from culprit.models.evidence import EvidenceBundle, PatchOutcome
    from culprit.models.patch_run import PatchRun, TriggerMode

    # A plain mkdtemp + best-effort manual cleanup, not
    # tempfile.TemporaryDirectory - see patch_extension_status_persistence's
    # own identical comment on why (a Windows SQLite file-handle timing
    # quirk, not a real resource leak).
    tmp = tempfile.mkdtemp()
    try:
        db_path = Path(tmp) / "pre_existing.db"

        # Build the OLD schema by hand - every machine_outcomes column
        # except the new one.
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
                timeline_json JSON,
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
        assert "checks_performed_json" in columns
        assert "checks_unavailable_json" in columns
        assert "sources_attempted_json" in columns
        assert "checks_finding_counts_json" in columns

        # And confirm a real save actually works against this file now.
        machine = _machine_identity()
        bundle = EvidenceBundle(
            run_id="run-1", machine=machine, outcome=PatchOutcome(status="Failed"),
            collection_started_at=datetime.now(timezone.utc),
            checks_performed=["disk usage"],
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
