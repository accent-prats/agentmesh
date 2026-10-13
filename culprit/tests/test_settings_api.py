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


def test_datadog_settings_with_only_a_pat_is_configured(client):
    """Mirrors test_azure_settings_with_only_subscription_ids_is_configured -
    a Personal Access Token alone is a complete, working configuration, so
    `configured` must not require the api_key/app_key pair too. Added
    2026-10-11 alongside PAT support."""
    resp = client.put("/settings/datadog", json={"personal_access_token": "pat-1", "use_personal_access_token": True})
    body = resp.json()
    assert body["personal_access_token_configured"] is True
    assert body["api_key_configured"] is False
    assert body["configured"] is True


def test_datadog_blank_pat_on_update_preserves_the_existing_one(client):
    """Same leave-alone-if-blank contract as api_key/app_key, as long as
    use_personal_access_token says PAT mode is still active - this is the
    "just updating the site, didn't retype the token" case."""
    client.put("/settings/datadog", json={"personal_access_token": "first-pat", "use_personal_access_token": True})

    resp = client.put(
        "/settings/datadog",
        json={"site": "datadoghq.eu", "personal_access_token": "", "use_personal_access_token": True},
    )
    body = resp.json()
    assert body["site"] == "datadoghq.eu"
    assert body["personal_access_token_configured"] is True

    from culprit.db import repository
    from culprit.api.deps import get_session_factory

    with get_session_factory()() as session:
        decrypted = repository.load_datadog_settings(session)
    assert decrypted.personal_access_token == "first-pat"


def test_datadog_switching_to_pat_forgets_the_api_and_app_key(client):
    """The bidirectional equivalent of Azure's clear_credentials test -
    switching the settings screen's toggle to "Personal Access Token" and
    saving must actually forget a previously-saved API/App key, not just
    leave them as orphaned ciphertext."""
    client.put("/settings/datadog", json={"api_key": "a-real-api-key", "app_key": "a-real-app-key"})

    resp = client.put(
        "/settings/datadog",
        json={"api_key": "", "app_key": "", "personal_access_token": "new-pat", "use_personal_access_token": True},
    )
    body = resp.json()
    assert body["api_key_configured"] is False
    assert body["app_key_configured"] is False
    assert body["personal_access_token_configured"] is True


def test_datadog_switching_back_to_api_key_forgets_the_pat(client):
    """The reverse direction - switching away from PAT mode must forget the
    PAT, not leave it stored alongside the newly-active API key."""
    client.put("/settings/datadog", json={"personal_access_token": "a-real-pat", "use_personal_access_token": True})

    resp = client.put(
        "/settings/datadog",
        json={"api_key": "new-api-key", "app_key": "new-app-key", "personal_access_token": "", "use_personal_access_token": False},
    )
    body = resp.json()
    assert body["personal_access_token_configured"] is False
    assert body["api_key_configured"] is True


def test_datadog_test_connection_uses_a_fresh_pat_not_stale_stored_settings(client, monkeypatch):
    """Found while adding PAT support: the route only checked body.api_key
    to decide whether to trust the submitted form over stored settings, so
    testing a brand-new, not-yet-saved PAT (api_key blank) would silently
    fall back to whatever was already in the database instead."""
    client.put("/settings/datadog", json={"api_key": "old-stored-key"})

    calls = []
    monkeypatch.setattr("culprit.api.routes_settings.test_datadog_credentials", lambda cfg: (calls.append(cfg), (True, "ok"))[1])

    client.post("/settings/datadog/test", json={"personal_access_token": "brand-new-pat", "use_personal_access_token": True})
    assert calls[0].personal_access_token == "brand-new-pat"
    assert calls[0].api_key == ""


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


def test_schedule_settings_default_view_is_disabled_with_no_live_scheduler(client):
    """No CULPRIT_SCHEDULER_ENABLED in this test process - app.state.scheduler
    is never set, so scheduler_running must honestly report False rather
    than implying a save here is actually live."""
    resp = client.get("/settings/schedule")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["cron_expression"] == "0 4 * * *"
    assert body["window_hours"] == 192
    assert body["scope_name"] == "scheduled"
    assert body["scheduler_running"] is False
    assert body["next_run_at"] is None


def test_schedule_settings_save_and_reload(client):
    resp = client.put(
        "/settings/schedule",
        json={"enabled": True, "cron_expression": "0 */6 * * *", "window_hours": 48, "scope_name": "nightly"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["cron_expression"] == "0 */6 * * *"
    assert body["window_hours"] == 48
    assert body["scope_name"] == "nightly"
    # No live scheduler in this test process to apply it to - saved for
    # whenever one starts, not acted on immediately.
    assert body["scheduler_running"] is False
    assert body["next_run_at"] is None

    reloaded = client.get("/settings/schedule").json()
    assert reloaded["enabled"] is True
    assert reloaded["cron_expression"] == "0 */6 * * *"
    assert reloaded["window_hours"] == 48
    assert reloaded["scope_name"] == "nightly"


def test_schedule_settings_rejects_a_malformed_cron_expression(client):
    resp = client.put("/settings/schedule", json={"enabled": True, "cron_expression": "not a cron"})
    assert resp.status_code == 422
