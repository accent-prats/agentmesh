"""Tests the /settings/azure and /settings/datadog routes end to end
against a real (in-memory) DB, with the actual Azure/Datadog SDK calls
mocked out - this test is about the save/mask/blank-preserves-existing
contract, not about whether Azure or Datadog themselves are reachable."""
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

    from culprit.api.main import app

    return TestClient(app)


def test_azure_settings_default_view_is_unconfigured(client):
    resp = client.get("/settings/azure")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["client_secret_configured"] is False
    assert body["subscription_ids"] == []


def test_azure_settings_save_and_reload_masks_the_secret(client):
    resp = client.put(
        "/settings/azure",
        json={
            "subscription_ids": ["sub-1", "sub-2"],
            "log_analytics_workspace_id": "workspace-1",
            "tenant_id": "tenant-1",
            "client_id": "client-1",
            "client_secret": "super-secret-value",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["subscription_ids"] == ["sub-1", "sub-2"]
    assert body["client_secret_configured"] is True
    assert "super-secret-value" not in resp.text
    assert body["configured"] is True

    reloaded = client.get("/settings/azure").json()
    assert reloaded["subscription_ids"] == ["sub-1", "sub-2"]
    assert reloaded["client_secret_configured"] is True


def test_blank_secret_on_update_preserves_the_existing_one(client):
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "first-secret"})

    # Update everything except the secret, leaving it blank.
    resp = client.put(
        "/settings/azure",
        json={"subscription_ids": ["sub-1", "sub-2"], "tenant_id": "new-tenant", "client_secret": ""},
    )
    body = resp.json()
    assert body["subscription_ids"] == ["sub-1", "sub-2"]
    assert body["tenant_id"] == "new-tenant"
    assert body["client_secret_configured"] is True  # still true - not wiped by the blank field

    # Confirm the underlying stored secret is genuinely still the first one.
    from culprit.db import repository
    from culprit.api.deps import get_session_factory

    with get_session_factory()() as session:
        decrypted = repository.load_azure_settings(session)
    assert decrypted.client_secret == "first-secret"


def test_clear_credentials_actually_forgets_a_previously_saved_secret(client):
    """The settings screen's "Managed identity" radio sends clear_credentials
    on an explicit switch away from a service principal - unlike a plain
    blank client_secret (see test_blank_secret_on_update_preserves_the_existing_one),
    this one is supposed to wipe it. Added 2026-10-10 alongside the toggle."""
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "tenant_id": "t", "client_id": "c", "client_secret": "a-real-secret"})

    resp = client.put(
        "/settings/azure",
        json={"subscription_ids": ["sub-1"], "tenant_id": "", "client_id": "", "client_secret": "", "clear_credentials": True},
    )
    body = resp.json()
    assert body["client_secret_configured"] is False

    from culprit.db import repository
    from culprit.api.deps import get_session_factory

    with get_session_factory()() as session:
        decrypted = repository.load_azure_settings(session)
    assert decrypted.client_secret == ""


def test_azure_settings_with_only_subscription_ids_is_configured(client):
    """A managed-identity setup never has a secret to save - tenant/client/
    secret all stay blank by design (azure_auth.py::build_credential falls
    back to DefaultAzureCredential). `configured` used to require a saved
    secret too, so this exact setup showed "Not configured yet." on the
    settings screen forever despite being complete and working - found
    2026-10-10 while adding a managed-identity toggle to that screen."""
    resp = client.put("/settings/azure", json={"subscription_ids": ["sub-1"]})
    body = resp.json()
    assert body["client_secret_configured"] is False
    assert body["configured"] is True


def test_datadog_settings_save_and_mask(client):
    resp = client.put("/settings/datadog", json={"site": "datadoghq.eu", "api_key": "abc", "app_key": "def"})
    body = resp.json()
    assert body["site"] == "datadoghq.eu"
    assert body["api_key_configured"] is True
    assert body["app_key_configured"] is True
    assert "abc" not in resp.text
    assert "def" not in resp.text


def test_azure_test_connection_uses_the_body_when_given(client, monkeypatch):
    calls = []

    def fake_test(cfg):
        calls.append(cfg)
        return True, "looks good"

    monkeypatch.setattr("culprit.api.routes_settings.test_azure_credentials", fake_test)

    resp = client.post("/settings/azure/test", json={"subscription_ids": ["sub-x"], "tenant_id": "t"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "message": "looks good"}
    assert calls[0].subscription_ids == ["sub-x"]


def test_azure_test_connection_persists_the_result(client, monkeypatch):
    monkeypatch.setattr("culprit.api.routes_settings.test_azure_credentials", lambda cfg: (False, "auth failed"))
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})
    client.post("/settings/azure/test", json={})

    view = client.get("/settings/azure").json()
    assert view["last_test_ok"] is False
    assert view["last_test_message"] == "auth failed"
    assert view["last_tested_at"] is not None


def test_datadog_test_connection(client, monkeypatch):
    monkeypatch.setattr("culprit.api.routes_settings.test_datadog_credentials", lambda cfg: (True, "API key validated"))
    resp = client.post("/settings/datadog/test", json={"api_key": "abc"})
    assert resp.json() == {"ok": True, "message": "API key validated"}

    view = client.get("/settings/datadog").json()
    assert view["last_test_ok"] is True
