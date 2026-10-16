"""API tests. Uses a fresh in-memory DB per test (via monkeypatching the
cached session factory) so tests never share state with each other or
with a real culprit.db file."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    # Force the scripted agent regardless of the environment the test
    # suite runs in - API tests should never depend on network credentials.
    from culprit.demo.scripted_rca import ScriptedRCAAgent

    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())

    # routes_runs.py imports get_session_factory/get_rca_agent by name at
    # call time from culprit.api.deps, so patching the module attributes
    # above is sufficient - no need to patch the routes module too.
    from culprit.api.main import app

    return TestClient(app)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_console_landing_page(client):
    """The AgentMesh launcher's 'Launch' target - must render, and must
    call the demo trigger via a *relative* path (`runs/demo`, not
    `/runs/demo`) so it still resolves correctly when nginx serves this
    app under a path prefix like /culprit/."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Culprit" in resp.text
    assert "fetch('runs/demo'" in resp.text
    assert "fetch('/runs/demo'" not in resp.text


def test_live_run_failure_is_logged_with_a_real_traceback_and_not_double_prefixed(client, caplog, monkeypatch):
    """Found 2026-10-16, debugging a real deployment: a live run failing
    with e.g. "The read operation timed out" (an Azure call, a Run
    Command poll, or an RCA provider's own HTTP call - several candidates
    exist in one run) used to surface only a flattened one-line message
    to the UI with nothing logged server-side to tell which one it was.
    Separately, the UI's own catch block already prepends "Live run
    failed: " for every error branch, so this route's own generic-
    exception branch doubling that prefix into "Live run failed: Live
    run failed: ..." was a second, independent bug in the same code."""
    import culprit.pipeline.live_run as live_run_module

    def _boom(**kwargs):
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(live_run_module, "execute_live_run", _boom)

    with caplog.at_level("ERROR"):
        resp = client.post("/runs/live", json={})

    assert resp.status_code == 502
    assert resp.json()["detail"] == "The read operation timed out"
    assert any(
        r.levelname == "ERROR" and "Live run failed" in r.message and r.exc_info
        for r in caplog.records
    )


def test_trigger_demo_run_and_read_back_report(client):
    resp = client.post("/runs/demo")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_machines"] == 312
    assert body["total_failed"] == 47
    assert body["total_clusters"] == 6

    run_id = body["run"]["run_id"]
    resp2 = client.get(f"/runs/{run_id}/report")
    assert resp2.status_code == 200
    assert resp2.json()["total_clusters"] == 6

    resp3 = client.get(f"/runs/{run_id}/report.html")
    assert resp3.status_code == 200
    assert "Culprit" in resp3.text


def test_report_404_for_unknown_run(client):
    resp = client.get("/runs/does-not-exist/report")
    assert resp.status_code == 404


def test_submit_verdict_and_read_precision(client):
    client.post("/runs/demo")
    resp = client.post(
        "/verdicts",
        json={
            "cluster_id": "some-cluster",
            "cause_family": "capacity",
            "verdict": "correct",
            "reviewer": "alice@example.com",
        },
    )
    assert resp.status_code == 200

    resp2 = client.get("/precision")
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["families"]["capacity"]["sample_size"] == 1
    assert body["families"]["capacity"]["precision"] == 1.0
    assert body["families"]["capacity"]["meets_promotion_bar"] is False  # sample size too small


def test_chat_fleet_summary_fallback(client):
    client.post("/runs/demo")
    resp = client.post("/chat", json={"question": "what's failing across the fleet?"})
    assert resp.status_code == 200
    assert "machines failed" in resp.json()["answer"]


def test_chat_scoped_to_a_specific_machine(client):
    client.post("/runs/demo")
    resp = client.post("/chat", json={"question": "why did vm-prd-app-0100 fail?"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["matched_cluster_id"] is not None
    assert "cluster" in body["answer"]


def test_event_grid_subscription_validation_handshake(client):
    resp = client.post(
        "/webhooks/event-grid",
        json=[
            {
                "id": "1",
                "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent",
                "data": {"validationCode": "abc123"},
            }
        ],
    )
    assert resp.status_code == 200
    assert resp.json() == {"validationResponse": "abc123"}
