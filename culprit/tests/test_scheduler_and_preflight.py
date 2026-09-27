"""Coverage for the autonomy modes that were stub functions before the
2026-09-27 proposal audit: scheduled_cycle, pre_flight_check, and the
Event Grid handler's actual dispatch, plus the pre-flight scan itself and
its GET /preflight + chat-prediction read paths.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.models.evidence import MachineIdentity, OSFamily, Source


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    from culprit.demo.scripted_rca import ScriptedRCAAgent

    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())

    from culprit.api.main import app

    return TestClient(app)


def test_scheduled_cycle_is_a_clean_noop_when_unconfigured(client):
    """No Azure subscription configured yet - must skip quietly, not
    raise, so a misconfigured scheduler doesn't spam error logs forever."""
    from culprit.scheduler.cron import scheduled_cycle

    scheduled_cycle(scope_name="test-scope")  # must not raise


def test_pre_flight_check_is_a_clean_noop_when_unconfigured(client):
    from culprit.scheduler.cron import pre_flight_check

    pre_flight_check()  # must not raise


def test_pre_flight_check_does_not_raise_when_the_encryption_key_has_rotated(client, monkeypatch):
    """Mirrors test_live_run_gives_a_clean_error_when_the_encryption_key_has_rotated:
    load_azure_settings() can raise InvalidToken, and unlike an HTTP route
    there's no response to turn that into - it must be caught and logged,
    not left to propagate out of the scheduler job."""
    from culprit.scheduler.cron import pre_flight_check

    monkeypatch.setenv("CULPRIT_ENCRYPTION_KEY", "key-at-save-time")
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "a-real-secret"})

    monkeypatch.setenv("CULPRIT_ENCRYPTION_KEY", "a-completely-different-key")
    pre_flight_check()  # must not raise


def test_scheduled_cycle_runs_the_real_pipeline_with_mocked_discovery(client, monkeypatch):
    import culprit.api.deps as deps_module
    from culprit.collectors.base import CollectionResult
    from culprit.models.evidence import PatchOutcome

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class FakeControlPlaneCollector:
        def collect(self, request):
            return CollectionResult(events=[], outcome=PatchOutcome(status="Failed", error_code="UnknownError"))

    monkeypatch.setattr(
        deps_module, "build_live_collectors",
        lambda session: ({Source.AZURE_CONTROL_PLANE: FakeControlPlaneCollector()}, _FakeAzureCfg(), object()),
    )

    import culprit.pipeline.discovery as discovery_module

    monkeypatch.setattr(discovery_module, "discover_failed_machines", lambda *a, **k: [fake_machine])
    monkeypatch.setattr(discovery_module, "count_total_machines", lambda *a, **k: 7)

    from culprit.scheduler.cron import scheduled_cycle

    scheduled_cycle(scope_name="nightly")

    with deps_module.get_session_factory()() as session:
        from culprit.db import repository
        from culprit.db.models import RunRecord
        from sqlalchemy import select

        run = session.execute(select(RunRecord).order_by(RunRecord.started_at.desc())).scalars().first()
        assert run is not None
        assert run.scope_name == "nightly"
        assert run.trigger_mode == "scheduled"
        report = repository.load_fleet_report(session, run.run_id)
        assert report.total_failed == 1


def test_scheduled_cycle_notify_includes_a_report_link_when_public_url_is_set(client, monkeypatch):
    """CULPRIT_PUBLIC_URL is the scheduler's only way to build a working
    "Open full report" link, since there's no inbound HTTP request to
    build one from the way routes_runs.py's _report_url does."""
    import dataclasses

    import culprit.api.deps as deps_module
    import culprit.config as config_module
    import culprit.scheduler.cron as cron_module
    from culprit.collectors.base import CollectionResult
    from culprit.models.evidence import PatchOutcome

    # culprit.config.settings is a frozen dataclass whose fields are baked
    # in at import time from the environment - monkeypatch.setenv() alone
    # wouldn't reach it, since _notify() reads the already-constructed
    # module-level singleton, not the environment directly.
    monkeypatch.setattr(
        config_module, "settings",
        dataclasses.replace(
            config_module.settings,
            teams_webhook_url="https://example.invalid/webhook",
            public_url="https://portal.local/culprit",
        ),
    )

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-3",
        vm_name="vm-3", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class FakeControlPlaneCollector:
        def collect(self, request):
            return CollectionResult(events=[], outcome=PatchOutcome(status="Failed", error_code="UnknownError"))

    monkeypatch.setattr(
        deps_module, "build_live_collectors",
        lambda session: ({Source.AZURE_CONTROL_PLANE: FakeControlPlaneCollector()}, _FakeAzureCfg(), object()),
    )

    import culprit.pipeline.discovery as discovery_module

    monkeypatch.setattr(discovery_module, "discover_failed_machines", lambda *a, **k: [fake_machine])
    monkeypatch.setattr(discovery_module, "count_total_machines", lambda *a, **k: 1)

    captured = {}

    def fake_post_to_teams(webhook_url, report, report_url=None):
        captured["report_url"] = report_url
        captured["run_id"] = report.run.run_id

        class _Resp:
            status_code = 200

        return _Resp()

    monkeypatch.setattr("culprit.reporting.notify.post_to_teams", fake_post_to_teams)

    cron_module.scheduled_cycle(scope_name="nightly-notify")

    assert captured["report_url"] == f"https://portal.local/culprit/runs/{captured['run_id']}/report.html"


def test_event_grid_handler_dispatches_a_live_run_in_the_background(client, monkeypatch):
    """The webhook itself must respond immediately - the actual run is a
    background task, so this drives _handle_maintenance_event directly
    rather than asserting on request latency."""
    import culprit.api.deps as deps_module
    from culprit.collectors.base import CollectionResult
    from culprit.models.evidence import PatchOutcome

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2",
        vm_name="vm-2", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class FakeControlPlaneCollector:
        def collect(self, request):
            return CollectionResult(events=[], outcome=PatchOutcome(status="Failed", error_code="UnknownError"))

    monkeypatch.setattr(
        deps_module, "build_live_collectors",
        lambda session: ({Source.AZURE_CONTROL_PLANE: FakeControlPlaneCollector()}, _FakeAzureCfg(), object()),
    )

    import culprit.pipeline.discovery as discovery_module

    monkeypatch.setattr(discovery_module, "discover_failed_machines", lambda *a, **k: [fake_machine])
    monkeypatch.setattr(discovery_module, "count_total_machines", lambda *a, **k: 3)

    from culprit.scheduler.events import _handle_maintenance_event

    _handle_maintenance_event({"data": {"id": "evt-123"}})

    with deps_module.get_session_factory()() as session:
        from sqlalchemy import select

        from culprit.db.models import RunRecord

        run = session.execute(select(RunRecord).order_by(RunRecord.started_at.desc())).scalars().first()
        assert run is not None
        assert run.scope_name == "evt-123"
        assert run.trigger_mode == "event_driven"


def test_event_grid_subscription_validation_still_bypasses_background_dispatch(client):
    resp = client.post(
        "/webhooks/event-grid",
        json=[{"id": "1", "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent", "data": {"validationCode": "abc123"}}],
    )
    assert resp.status_code == 200
    assert resp.json() == {"validationResponse": "abc123"}


def test_preflight_scan_flags_a_machine_with_a_current_disk_precondition(client):
    from datetime import datetime, timezone

    from culprit.collectors.base import CollectionResult
    from culprit.models.evidence import TimelineEvent
    from culprit.pipeline.preflight import run_preflight_scan

    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/vm-low-disk",
        vm_name="vm-low-disk", resource_group="r", subscription_id="s", os_family=OSFamily.LINUX,
    )

    class FakeGuestCollector:
        def collect(self, request):
            now = datetime.now(timezone.utc)
            return CollectionResult(events=[
                TimelineEvent(
                    ts=now, source=Source.GUEST_LINUX, kind="disk_usage",
                    summary="No space left on device", raw_ref="guest:df:1",
                    detail={"disk_low": True, "write_failure": True, "mount": "/boot"},
                )
            ])

    findings = run_preflight_scan({Source.GUEST_LINUX: FakeGuestCollector()}, [machine])
    assert len(findings) == 1
    assert findings[0].machine.vm_name == "vm-low-disk"
    assert findings[0].result.cause_family.value == "capacity"


def test_preflight_scan_drops_machines_the_rules_have_nothing_to_say_about(client):
    from culprit.collectors.base import CollectionResult
    from culprit.pipeline.preflight import run_preflight_scan

    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/vm-healthy",
        vm_name="vm-healthy", resource_group="r", subscription_id="s", os_family=OSFamily.LINUX,
    )

    class QuietCollector:
        def collect(self, request):
            return CollectionResult(events=[])

    findings = run_preflight_scan({Source.GUEST_LINUX: QuietCollector()}, [machine])
    assert findings == []


def test_get_preflight_and_chat_prediction_read_the_persisted_scan(client, monkeypatch):
    import culprit.api.deps as deps_module
    from culprit.db import repository
    from culprit.models.preflight import PreflightFinding
    from culprit.pipeline.rules import evaluate_rules
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import TimelineEvent, PatchOutcome, EvidenceBundle
    from datetime import datetime, timezone

    machine = MachineIdentity(
        vm_id="/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/vm-predicted",
        vm_name="vm-predicted", resource_group="r", subscription_id="s", os_family=OSFamily.LINUX,
    )
    now = datetime.now(timezone.utc)
    bundle = EvidenceBundle(
        run_id="preflight", machine=machine, outcome=PatchOutcome(status="Unknown"),
        collection_started_at=now,
        timeline=[TimelineEvent(
            ts=now, source=Source.GUEST_LINUX, kind="disk_usage", summary="No space left on device",
            raw_ref="guest:df:1", detail={"disk_low": True, "write_failure": True, "mount": "/boot"},
        )],
    )
    cluster = Cluster(
        cluster_id="preflight:x", run_id="preflight", cluster_key="preflight:x",
        fingerprint=Fingerprint(error_code_normalized="preflight", os_family=OSFamily.LINUX, failing_target=""),
        members=[ClusterMember(vm_id=machine.vm_id, vm_name=machine.vm_name)],
        representative_vm_id=machine.vm_id,
    )
    result = evaluate_rules(cluster, bundle)
    finding = PreflightFinding(machine=machine, result=result, scanned_at=now)

    with deps_module.get_session_factory()() as session:
        repository.save_preflight_findings(session, [finding])

    resp = client.get("/preflight")
    assert resp.status_code == 200
    assert resp.json()["findings"][0]["machine"]["vm_name"] == "vm-predicted"

    chat_resp = client.post("/chat", json={"question": "which machines will fail next Tuesday?"})
    assert chat_resp.status_code == 200
    assert "vm-predicted" in chat_resp.json()["answer"]


def test_chat_prediction_with_no_scan_yet_says_so_without_crashing(client):
    resp = client.post("/chat", json={"question": "which machines are going to fail next?"})
    assert resp.status_code == 200
    assert "no pre-flight warnings" in resp.json()["answer"].lower()


class _FakeAzureCfg:
    subscription_ids = ["sub-1"]
    log_analytics_workspace_id = ""
    tenant_id = ""
    client_id = ""
    client_secret = ""
