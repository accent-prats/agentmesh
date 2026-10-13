"""Coverage for Phase 2 remediation execution (culprit/remediation/,
api/routes_remediation.py) - the one feature in this app that can mutate
real Azure infrastructure. Every test here is about the gate, not the
Azure call itself (RemediationRunner.run_disk_cleanup is monkeypatched,
same style as deps_module.build_live_collectors elsewhere in this suite) -
proving the six checks (flag, existence, phase2_candidate, live precision
bar, supported action type, vm_ids validity) each actually block execution
on their own, and that nothing bypasses them."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import culprit.config as config_module
from culprit.db import repository
from culprit.db.engine import make_engine, make_session_factory
from culprit.db.models import RunStage
from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
from culprit.models.evidence import OSFamily
from culprit.models.patch_run import PatchRun, TriggerMode
from culprit.models.rca import CausalStep, RCAResult, RemediationPlaybook, RemediationStep, ResultOrigin, RiskLevel
from culprit.models.taxonomy import CauseFamily
from culprit.models.verdict import Verdict, VerdictValue
from culprit.remediation.scripts import parse_remediation_result


def _seed_cluster(
    session, *, run_id="run-1", cluster_id="cluster-1", cause_family=CauseFamily.CAPACITY,
    phase2_candidate=True, with_machine_identity=True, member_count=2,
):
    run = PatchRun(
        run_id=run_id, maintenance_configuration_id="mc-1", subscription_id="sub-1",
        scope_name="scope-a", started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), total_machines=10,
        trigger_mode=TriggerMode.AD_HOC,
    )
    repository.save_run(session, run, stage=RunStage.STARTED)
    repository.update_run_stage(session, run_id, RunStage.COMPLETE, ended_at=run.started_at, failed_machines=member_count)

    members = [
        ClusterMember(
            vm_id=f"vm-{i}", vm_name=f"vm-{i}",
            resource_group="rg-1" if with_machine_identity else "",
            subscription_id="sub-1" if with_machine_identity else "",
        )
        for i in range(member_count)
    ]
    cluster = Cluster(
        cluster_id=cluster_id, run_id=run_id, cluster_key=f"key:{cluster_id}",
        fingerprint=Fingerprint(error_code_normalized="disk_full", os_family=OSFamily.LINUX, failing_target=""),
        members=members, representative_vm_id=members[0].vm_id,
    )
    repository.save_cluster(session, cluster)

    result = RCAResult(
        cluster_id=cluster_id, origin=ResultOrigin.RULE_ENGINE, cause_family=cause_family,
        title="Disk exhaustion", confidence=0.9,
        causal_chain=[CausalStep(order=1, statement="Low disk", evidence_refs=["ref-1"])],
        remediation=RemediationPlaybook(
            immediate_fix=[RemediationStep(order=1, instruction="Free space")],
            immediate_risk=RiskLevel.LOW, phase2_candidate=phase2_candidate,
            automation_params={"mount": "/"},
        ),
    )
    repository.save_rca_result(session, result)
    return run_id, cluster_id, members


def _submit_verdicts_to_clear_the_bar(session, cause_family=CauseFamily.CAPACITY, count=50):
    for i in range(count):
        repository.save_verdict(session, Verdict(
            cluster_id=f"verdict-seed-{i}", cause_family=cause_family, verdict=VerdictValue.CORRECT,
            reviewer="reviewer@example.com", reviewed_at=datetime.now(timezone.utc),
        ))


@pytest.fixture
def client(monkeypatch):
    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)

    import culprit.api.deps as deps_module

    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(config_module, "settings", dataclasses.replace(config_module.settings, remediation_enabled=True))

    from culprit.api.main import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def session_factory(client):
    import culprit.api.deps as deps_module

    return deps_module.get_session_factory()


def test_execute_404_when_remediation_disabled(client, monkeypatch, session_factory):
    monkeypatch.setattr(config_module, "settings", dataclasses.replace(config_module.settings, remediation_enabled=False))
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 404


def test_execute_404_when_run_or_cluster_not_found(client):
    resp = client.post("/remediation/runs/nope/clusters/nope/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 404


def test_execute_409_when_not_phase2_candidate(client, session_factory):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, phase2_candidate=False)
        _submit_verdicts_to_clear_the_bar(session)  # sufficient verdicts - still must be rejected

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_phase2_candidate"


def test_execute_409_when_promotion_bar_not_met(client, session_factory):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session)
        # No verdicts submitted at all.

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["reason"] == "promotion_bar_not_met"
    assert body["sample_size"] == 0
    assert body["min_sample"] == 50


def test_execute_409_when_action_type_not_supported_for_cause_family(client, session_factory):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, cause_family=CauseFamily.PACKAGE_MANAGER_STATE)
        _submit_verdicts_to_clear_the_bar(session, cause_family=CauseFamily.PACKAGE_MANAGER_STATE)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "action_type_not_supported_for_cause_family"


def test_execute_succeeds_and_persists_one_record_per_machine(client, session_factory, monkeypatch):
    with session_factory() as session:
        run_id, cluster_id, members = _seed_cluster(session, member_count=2)
        _submit_verdicts_to_clear_the_bar(session)

    def fake_run_disk_cleanup(self, subscription_id, resource_group, vm_name, os_family, mount):
        return {"status": "success", "message": f"Freed space on {vm_name}", "free_bytes_after": 999}

    monkeypatch.setattr("culprit.remediation.runner.RemediationRunner.run_disk_cleanup", fake_run_disk_cleanup)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["results"]) == 2
    assert body["succeeded_count"] == 2
    assert body["failed_count"] == 0

    with session_factory() as session:
        records = repository.list_remediation_actions(session)
    assert len(records) == 2
    assert {r.vm_name for r in records} == {m.vm_name for m in members}
    assert all(r.status.value == "success" for r in records)
    assert all(r.requested_by == "a@b.com" for r in records)


def test_execute_partial_failure_records_each_machine_outcome(client, session_factory, monkeypatch):
    with session_factory() as session:
        run_id, cluster_id, members = _seed_cluster(session, member_count=2)
        _submit_verdicts_to_clear_the_bar(session)

    def fake_run_disk_cleanup(self, subscription_id, resource_group, vm_name, os_family, mount):
        if vm_name == "vm-0":
            return {"status": "success", "message": "ok", "free_bytes_after": 999}
        return {"status": "failed", "message": "Run Command failed: timeout", "free_bytes_after": None}

    monkeypatch.setattr("culprit.remediation.runner.RemediationRunner.run_disk_cleanup", fake_run_disk_cleanup)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["succeeded_count"] == 1
    assert body["failed_count"] == 1

    with session_factory() as session:
        records = repository.list_remediation_actions(session)
    statuses = {r.vm_name: r.status.value for r in records}
    assert statuses["vm-0"] == "success"
    assert statuses["vm-1"] == "failed"


def test_execute_vm_ids_filters_to_requested_subset(client, session_factory, monkeypatch):
    with session_factory() as session:
        run_id, cluster_id, members = _seed_cluster(session, member_count=3)
        _submit_verdicts_to_clear_the_bar(session)

    called_with = []

    def fake_run_disk_cleanup(self, subscription_id, resource_group, vm_name, os_family, mount):
        called_with.append(vm_name)
        return {"status": "success", "message": "ok", "free_bytes_after": 999}

    monkeypatch.setattr("culprit.remediation.runner.RemediationRunner.run_disk_cleanup", fake_run_disk_cleanup)

    resp = client.post(
        f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute",
        json={"action_type": "disk_cleanup", "requested_by": "a@b.com", "vm_ids": ["vm-0"]},
    )
    assert resp.status_code == 200
    assert called_with == ["vm-0"]
    assert resp.json()["results"][0]["vm_id"] == "vm-0"


def test_execute_rejects_vm_id_not_in_cluster(client, session_factory):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session)
        _submit_verdicts_to_clear_the_bar(session)

    resp = client.post(
        f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute",
        json={"action_type": "disk_cleanup", "requested_by": "a@b.com", "vm_ids": ["not-a-real-vm"]},
    )
    assert resp.status_code == 400


def test_execute_rejects_blank_requested_by(client, session_factory):
    """min_length=1 alone counts characters, not content - "   " would
    otherwise pass. Found in review: a caller that skips the browser
    widget's client-side .trim() check (curl, a script) could execute a
    real remediation with no identifiable human attached."""
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session)
        _submit_verdicts_to_clear_the_bar(session)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "   "})
    assert resp.status_code == 422

    with session_factory() as session:
        assert repository.list_remediation_actions(session) == []


def test_execute_strips_requested_by(client, session_factory, monkeypatch):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, member_count=1)
        _submit_verdicts_to_clear_the_bar(session)

    monkeypatch.setattr(
        "culprit.remediation.runner.RemediationRunner.run_disk_cleanup",
        lambda self, subscription_id, resource_group, vm_name, os_family, mount: {"status": "success", "message": "ok", "free_bytes_after": 999},
    )
    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "  a@b.com  "})
    assert resp.status_code == 200
    assert resp.json()["requested_by"] == "a@b.com"


def test_execute_stops_processing_remaining_machines_when_gate_drops_mid_batch(client, session_factory, monkeypatch):
    """A cluster with many members loops sequentially, each Run Command
    call potentially taking real time - the gate must be re-checked before
    *every* machine, not just once for the whole batch. Simulates a
    reviewer correcting a wrong diagnosis (submitting disqualifying
    verdicts) in between two machines of the same in-flight request."""
    with session_factory() as session:
        run_id, cluster_id, members = _seed_cluster(session, member_count=3)
        _submit_verdicts_to_clear_the_bar(session)

    call_log = []

    def fake_run_disk_cleanup(self, subscription_id, resource_group, vm_name, os_family, mount):
        call_log.append(vm_name)
        if vm_name == "vm-0":
            with session_factory() as s:
                for i in range(50):
                    repository.save_verdict(s, Verdict(
                        cluster_id=f"disrupt-{i}", cause_family=CauseFamily.CAPACITY, verdict=VerdictValue.WRONG,
                        reviewer="auditor@example.com", reviewed_at=datetime.now(timezone.utc),
                    ))
        return {"status": "success", "message": "ok", "free_bytes_after": 999}

    monkeypatch.setattr("culprit.remediation.runner.RemediationRunner.run_disk_cleanup", fake_run_disk_cleanup)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()

    # Only vm-0 ever actually reached the Run Command call - the gate
    # re-check before vm-1/vm-2 correctly caught the mid-batch disruption
    # and skipped them rather than running the script anyway.
    assert call_log == ["vm-0"]
    statuses = {r["vm_name"]: r["status"] for r in body["results"]}
    assert statuses["vm-0"] == "success"
    assert statuses["vm-1"] == "failed"
    assert statuses["vm-2"] == "failed"
    assert "no longer held" in next(r["message"] for r in body["results"] if r["vm_name"] == "vm-1")


def test_execute_reflects_a_verdict_submitted_moments_earlier(client, session_factory, monkeypatch):
    """Proves there is no stale caching of the precision gate - a verdict
    submitted via POST /verdicts in the same test flips a previously-409
    execute call to 200, within the same process."""
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session)

    first = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert first.status_code == 409

    for i in range(50):
        client.post("/verdicts", json={"cluster_id": f"seed-{i}", "cause_family": "capacity", "verdict": "correct", "reviewer": "r@example.com"})

    monkeypatch.setattr(
        "culprit.remediation.runner.RemediationRunner.run_disk_cleanup",
        lambda self, subscription_id, resource_group, vm_name, os_family, mount: {"status": "success", "message": "ok", "free_bytes_after": 999},
    )

    second = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert second.status_code == 200


def test_execute_missing_resource_group_is_a_per_machine_failure_not_a_crash(client, session_factory, monkeypatch):
    """A cluster persisted before resource_group/subscription_id existed
    (or synthetic/demo data) must degrade to a per-machine failure, not
    crash the whole request."""
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, with_machine_identity=False, member_count=1)
        _submit_verdicts_to_clear_the_bar(session)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["failed_count"] == 1
    assert "resource_group" in body["results"][0]["message"]


def test_remediation_log_page_reads_back_persisted_actions(client, session_factory, monkeypatch):
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, member_count=1)
        _submit_verdicts_to_clear_the_bar(session)

    monkeypatch.setattr(
        "culprit.remediation.runner.RemediationRunner.run_disk_cleanup",
        lambda self, subscription_id, resource_group, vm_name, os_family, mount: {"status": "success", "message": "ok", "free_bytes_after": 999},
    )
    client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "someone@example.com"})

    html = client.get("/remediation/log.html").text
    assert "vm-0" in html
    assert "someone@example.com" in html

    json_log = client.get("/remediation/log").json()
    assert len(json_log) == 1
    assert json_log[0]["status"] == "success"


def test_remediation_log_page_empty_state(client):
    html = client.get("/remediation/log.html").text
    assert "No remediation actions recorded yet" in html


def test_parse_remediation_result_success_line():
    stdout = "---BEFORE---\n100\n---REMEDIATION_RESULT---\nstatus=success mount=/ free_bytes_after=314572800\n"
    result = parse_remediation_result(stdout)
    assert result == {"status": "success", "mount": "/", "free_bytes_after": 314572800}


def test_parse_remediation_result_failure_line():
    stdout = '---REMEDIATION_RESULT---\nstatus=failed reason="only 100 bytes free on /, target is 209715200" mount=/ free_bytes_after=100\n'
    result = parse_remediation_result(stdout)
    assert result["status"] == "failed"
    assert "only 100 bytes free" in result["reason"]


def test_parse_remediation_result_missing_block_is_a_failure():
    assert parse_remediation_result("nothing relevant here")["status"] == "failed"


def test_execute_stops_processing_remaining_machines_when_the_gate_value_itself_changes_mid_batch(client, session_factory, monkeypatch):
    """Same mechanism as test_execute_stops_processing_remaining_machines_when_gate_drops_mid_batch,
    but the disruption is a PUT /settings/gate call (tightening the
    threshold past what the cluster's own precision still clears) instead
    of a verdict change - found worth testing explicitly in review
    2026-10-14 since _check_gate's per-machine re-check doesn't
    distinguish the two causes, but nothing had exercised this one."""
    with session_factory() as session:
        run_id, cluster_id, members = _seed_cluster(session, member_count=3)
        _submit_verdicts_to_clear_the_bar(session)  # 100% precision, 50 reviewed - clears the default bar

    call_log = []

    def fake_run_disk_cleanup(self, subscription_id, resource_group, vm_name, os_family, mount):
        call_log.append(vm_name)
        if vm_name == "vm-0":
            # Tighten min_sample past what's actually been reviewed (50) -
            # precision can't be pushed past the already-perfect 100%, so
            # min_sample is the lever this test uses to flip the bar.
            client.put("/settings/gate", json={"threshold": 0.95, "min_sample": 51, "changed_by": "qa@example.com"})
        return {"status": "success", "message": "ok", "free_bytes_after": 999}

    monkeypatch.setattr("culprit.remediation.runner.RemediationRunner.run_disk_cleanup", fake_run_disk_cleanup)

    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    body = resp.json()

    assert call_log == ["vm-0"]
    statuses = {r["vm_name"]: r["status"] for r in body["results"]}
    assert statuses["vm-0"] == "success"
    assert statuses["vm-1"] == "failed"
    assert statuses["vm-2"] == "failed"
    assert "no longer held" in next(r["message"] for r in body["results"] if r["vm_name"] == "vm-1")


def test_execute_uses_a_saved_gate_override_not_just_the_config_default(client, session_factory, monkeypatch):
    """The "make the gate editable" feature (2026-10-14): PUT /settings/gate
    writes an append-only PromotionGateChangeRecord, and
    routes_remediation.py's _check_gate must read that override live, the
    same way it already re-reads verdict data live - not just the
    config.settings env-var default, and not a value cached from process
    start. 20 verdicts clears a min_sample=10 override but not the
    config default of 50, so this also proves the override, not some
    other change, is what flips the decision."""
    with session_factory() as session:
        run_id, cluster_id, _ = _seed_cluster(session, member_count=1)
        _submit_verdicts_to_clear_the_bar(session, count=20)

    # Still the config default (50) - 20 reviewed isn't enough yet.
    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["min_sample"] == 50

    gate_resp = client.put("/settings/gate", json={"threshold": 0.95, "min_sample": 10, "changed_by": "qa@example.com"})
    assert gate_resp.status_code == 200
    assert gate_resp.json()["is_default"] is False

    monkeypatch.setattr(
        "culprit.remediation.runner.RemediationRunner.run_disk_cleanup",
        lambda self, subscription_id, resource_group, vm_name, os_family, mount: {"status": "success", "message": "ok", "free_bytes_after": 999},
    )
    resp = client.post(f"/remediation/runs/{run_id}/clusters/{cluster_id}/execute", json={"action_type": "disk_cleanup", "requested_by": "a@b.com"})
    assert resp.status_code == 200
    assert resp.json()["succeeded_count"] == 1
