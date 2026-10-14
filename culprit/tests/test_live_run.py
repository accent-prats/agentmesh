"""POST /runs/live - the real-pipeline trigger. Everything Azure-shaped is
mocked (discovery, collector construction) since this test suite runs
with no Azure SDK or credentials; what's under test is the route's own
wiring (fail fast when unconfigured, otherwise call discovery -> collect_all
-> Pipeline.run with whatever was discovered)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.models.evidence import MachineIdentity, OSFamily, PatchOutcome, Source


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


def test_live_run_without_configured_subscription_is_a_clean_400(client):
    """Must fail before touching azure-identity at all - this test
    deliberately runs with no Azure SDK installed to prove that."""
    resp = client.post("/runs/live")
    assert resp.status_code == 400
    assert "settings" in resp.json()["detail"].lower()


def test_live_run_reports_a_friendly_error_when_azure_sdk_missing(client, monkeypatch):
    import culprit.api.deps as deps_module

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"]})

    def fake_build_live_collectors(session):
        raise ImportError("No module named 'azure'")

    monkeypatch.setattr(deps_module, "build_live_collectors", fake_build_live_collectors)

    resp = client.post("/runs/live")
    assert resp.status_code == 500
    assert "culprit[azure]" in resp.json()["detail"]


def test_live_run_happy_path_with_mocked_discovery(client, monkeypatch):
    import culprit.api.deps as deps_module

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class FakeControlPlaneCollector:
        def collect(self, request):
            from culprit.collectors.base import CollectionResult

            return CollectionResult(events=[], outcome=PatchOutcome(status="Failed", error_code="UnknownError"))

    def fake_build_live_collectors(session):
        return {Source.AZURE_CONTROL_PLANE: FakeControlPlaneCollector()}, _FakeAzureCfg(), object()

    monkeypatch.setattr(deps_module, "build_live_collectors", fake_build_live_collectors)

    # discover_failed_machines / count_total_machines are imported inline inside
    # the route function body (`from culprit.pipeline.discovery import ...`),
    # which resolves against the module's *current* attributes at call time -
    # so patching them here, before the request fires, takes effect.
    import culprit.pipeline.discovery as discovery_module

    monkeypatch.setattr(discovery_module, "discover_failed_machines", lambda *a, **k: [fake_machine])
    monkeypatch.setattr(discovery_module, "count_total_machines", lambda *a, **k: 42)

    resp = client.post("/runs/live", json={"window_hours": 12, "scope_name": "live-test"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_machines"] == 42
    assert body["total_failed"] == 1
    assert body["run"]["scope_name"] == "live-test"


class _FakeAzureCfg:
    subscription_ids = ["sub-1"]
    log_analytics_workspace_id = ""
    tenant_id = ""
    client_id = ""
    client_secret = ""


def test_live_run_builds_and_persists_an_installation_report(client, monkeypatch):
    """Found in review: the happy-path test above never mocked
    `discover_all_patch_outcomes_with_identity`, so the live path's own
    installation-report wiring (pipeline/live_run.py's new block, right
    after pipeline.run()) silently hit the real, uninstalled azure SDK,
    got caught by that block's own best-effort try/except, and logged-
    and-swallowed every single run - zero real verification that any of
    it works. This mocks all three discovery calls and actually checks
    the installation report that comes out the other end."""
    import culprit.api.deps as deps_module

    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class FakeControlPlaneCollector:
        def collect(self, request):
            from culprit.collectors.base import CollectionResult

            return CollectionResult(events=[], outcome=PatchOutcome(status="Failed", error_code="UnknownError"))

    def fake_build_live_collectors(session):
        return {Source.AZURE_CONTROL_PLANE: FakeControlPlaneCollector()}, _FakeAzureCfg(), object()

    monkeypatch.setattr(deps_module, "build_live_collectors", fake_build_live_collectors)

    import culprit.pipeline.discovery as discovery_module

    monkeypatch.setattr(discovery_module, "discover_failed_machines", lambda *a, **k: [fake_machine])
    monkeypatch.setattr(discovery_module, "count_total_machines", lambda *a, **k: 5)
    # The real discover_all_patch_outcomes_with_identity has no status
    # filter - vm-1 (Failed) would genuinely appear here too alongside
    # vm-2, not just the latter; build_installation_report's own de-dup
    # (tested separately) is what resolves the overlap with
    # failed_bundles, so the mock has to include it to be realistic.
    monkeypatch.setattr(
        discovery_module, "discover_all_patch_outcomes_with_identity",
        lambda *a, **k: [
            {
                "vm_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                "vm_name": "vm-1", "resource_group": "rg", "subscription_id": "sub-1",
                "status": "Failed", "started_at": None, "ended_at": None,
            },
            {
                "vm_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2",
                "vm_name": "vm-2", "resource_group": "rg", "subscription_id": "sub-1",
                "status": "Succeeded", "started_at": None, "ended_at": None,
            },
        ],
    )

    resp = client.post("/runs/live", json={"window_hours": 12, "scope_name": "live-test"})
    assert resp.status_code == 200
    run_id = resp.json()["run"]["run_id"]

    ir = client.get(f"/runs/{run_id}/installation-report").json()
    # 1 failed (the real machine the fleet pipeline diagnosed) + 1 succeeded
    # (from the mocked bulk query) + 3 excluded (total_machines=5 - 2 reported).
    assert ir["failed_count"] == 1
    assert ir["succeeded_count"] == 1
    assert ir["excluded_count"] == 3
    failed_row = next(r for r in ir["rows"] if r["status"] == "failed")
    assert failed_row["error_code"] == "UnknownError"


def test_live_run_gives_a_clean_error_when_the_encryption_key_has_rotated(client, monkeypatch):
    """Found in review 2026-09-27: decrypt() raising InvalidToken (e.g.
    CULPRIT_ENCRYPTION_KEY changed since settings were saved) was outside
    every try/except in this route - an unhandled 500 traceback instead of
    a clear, fixable error message."""
    monkeypatch.setenv("CULPRIT_ENCRYPTION_KEY", "key-at-save-time")
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "a-real-secret"})

    monkeypatch.setenv("CULPRIT_ENCRYPTION_KEY", "a-completely-different-key")
    resp = client.post("/runs/live")

    assert resp.status_code == 500
    assert "CULPRIT_ENCRYPTION_KEY" in resp.json()["detail"]
    assert "/culprit/settings" in resp.json()["detail"]
