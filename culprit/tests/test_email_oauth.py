"""Coverage for the Microsoft 365 (OAuth) email delivery method -
culprit/notifications/m365_oauth.py, email_sender.py::send_email_oauth,
security/credential_test.py::test_email_oauth_credentials, the
/settings/email/oauth and /settings/email/method routes, and
routes_notifications.py's method-based branch. Mirrors test_notifications.py's
exact conventions for its SMTP sibling - `smtplib.SMTP` and
`msal.PublicClientApplication` are both monkeypatched throughout; no real
network connection or Azure AD tenant involved anywhere in this file.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.retrieval.corpus import default_retrieval_store


class FakeSMTP:
    """Same shape as test_notifications.py's own FakeSMTP, plus docmd()
    for the XOAUTH2 AUTH command neither plain SMTP.login() nor the
    original fake needed."""

    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=None, fail_on: str | None = None):
        self.host = host
        self.port = port
        self.calls: list[str] = []
        self.sent_message = None
        self._fail_on = fail_on
        FakeSMTP.instances.append(self)

    def starttls(self):
        self.calls.append("starttls")

    def docmd(self, cmd, arg):
        self.calls.append(f"docmd:{cmd}")
        if self._fail_on == "auth":
            return 535, b"5.7.3 Authentication unsuccessful"
        return 235, b"2.7.0 Authentication successful"

    def send_message(self, msg):
        if self._fail_on == "send":
            raise Exception("connection reset by peer")
        self.sent_message = msg
        self.calls.append("send_message")

    def quit(self):
        self.calls.append("quit")


class FakePublicClientApplication:
    """Stands in for msal.PublicClientApplication - records the
    authority/client_id it was constructed with and returns a scripted
    result from acquire_token_by_username_password, the same shape MSAL's
    real token endpoint returns on success ({"access_token": ...}) or
    failure ({"error": ..., "error_description": ...})."""

    result: dict = {"access_token": "fake-access-token"}
    instances: list["FakePublicClientApplication"] = []

    def __init__(self, client_id, authority=None):
        self.client_id = client_id
        self.authority = authority
        FakePublicClientApplication.instances.append(self)

    def acquire_token_by_username_password(self, username, password, scopes=None):
        return FakePublicClientApplication.result


@pytest.fixture(autouse=True)
def _reset_fakes():
    FakeSMTP.instances = []
    FakePublicClientApplication.instances = []
    FakePublicClientApplication.result = {"access_token": "fake-access-token"}
    yield
    FakeSMTP.instances = []
    FakePublicClientApplication.instances = []


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())
    deps_module.get_retrieval_store.cache_clear()
    monkeypatch.setattr(deps_module, "get_retrieval_store", lambda: default_retrieval_store())

    from culprit.api.main import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def seeded_run_id(client) -> str:
    resp = client.post("/runs/demo")
    assert resp.status_code == 200
    return resp.json()["run"]["run_id"]


def _patch_msal(monkeypatch):
    import culprit.notifications.m365_oauth as m365_oauth

    monkeypatch.setattr(m365_oauth, "msal", type("msal", (), {"PublicClientApplication": FakePublicClientApplication}))
    monkeypatch.setattr(m365_oauth, "_MSAL_AVAILABLE", True)


# ── Email OAuth settings CRUD ────────────────────────────────────────────────

def test_email_oauth_settings_default_view_is_unconfigured(client):
    resp = client.get("/settings/email/oauth")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["password_configured"] is False
    assert body["default_recipients"] == []
    assert body["from_name"] == "Culprit"


def test_email_oauth_settings_save_and_reload_masks_the_password(client):
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "culprit@contoso.com", "password": "super-secret-value", "from_name": "Culprit",
        "default_recipients": ["ops@example.com"],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "contoso.onmicrosoft.com"
    assert body["password_configured"] is True
    assert "super-secret-value" not in resp.text
    assert body["configured"] is True

    reloaded = client.get("/settings/email/oauth").json()
    assert reloaded["username"] == "culprit@contoso.com"
    assert reloaded["password_configured"] is True


def test_email_oauth_blank_password_on_update_preserves_the_existing_one(client):
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "first-secret",
    })
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "",
    })
    assert resp.json()["password_configured"] is True

    from culprit.api.deps import get_session_factory
    from culprit.db import repository

    with get_session_factory()() as session:
        decrypted = repository.load_email_oauth_settings(session)
    assert decrypted.password == "first-secret"


def test_email_oauth_settings_configured_requires_all_three_fields():
    """Found by review: email_oauth_settings_view's `configured` flag
    AND-combines tenant_id/client_id/username (a real ROPC token request
    needs all three) - pins that this is a genuine AND, not an OR a
    regression could quietly loosen it to (which would falsely report
    "configured" the moment just one field is saved)."""
    from culprit.db import repository
    from culprit.db.engine import make_engine, make_session_factory
    from culprit.models.settings import EmailOAuthSettingsInput

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    with factory() as session:
        repository.save_email_oauth_settings(session, EmailOAuthSettingsInput(tenant_id="contoso.onmicrosoft.com"))
        assert repository.email_oauth_settings_view(session).configured is False

        repository.save_email_oauth_settings(
            session,
            EmailOAuthSettingsInput(
                tenant_id="contoso.onmicrosoft.com", client_id="11111111-1111-1111-1111-111111111111"
            ),
        )
        assert repository.email_oauth_settings_view(session).configured is False

        repository.save_email_oauth_settings(
            session,
            EmailOAuthSettingsInput(
                tenant_id="contoso.onmicrosoft.com", client_id="11111111-1111-1111-1111-111111111111",
                username="u@example.com",
            ),
        )
        assert repository.email_oauth_settings_view(session).configured is True


def test_email_oauth_settings_rejects_a_malformed_username(client):
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "not-an-email",
    })
    assert resp.status_code == 422


# Added 2026-10-23: a real preprod deployment entered "tcxppreprod" (an
# internal short nickname) as the Tenant ID and "tcxppreprod-email-techuser"
# (a display name) as the Client ID. Both are rejected by MSAL's own
# authority-discovery call, but only after a live round-trip to Azure AD -
# these tests pin that the exact same mistake is now caught instantly by
# EmailOAuthSettingsInput's own validators, on both Save and Test, before
# any network call happens.

def test_email_oauth_settings_rejects_a_short_tenant_nickname(client):
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": "tcxppreprod", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com",
    })
    assert resp.status_code == 422
    assert "tcxppreprod" in resp.text


def test_email_oauth_settings_rejects_a_client_id_that_is_not_a_guid(client):
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "tcxppreprod-email-techuser",
        "username": "u@example.com",
    })
    assert resp.status_code == 422
    assert "tcxppreprod-email-techuser" in resp.text


@pytest.mark.parametrize("tenant_id", [
    "11111111-1111-1111-1111-111111111111",  # a real tenant GUID
    "contoso.onmicrosoft.com",  # a verified domain
    "contoso.com",  # a verified custom domain - any dot qualifies
    "common",  # the three documented multi-tenant aliases
    "organizations",
    "consumers",
    "",  # blank is still a valid "not configured yet" value
])
def test_email_oauth_settings_accepts_every_real_tenant_id_shape(client, tenant_id):
    resp = client.put("/settings/email/oauth", json={
        "tenant_id": tenant_id, "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com",
    })
    assert resp.status_code == 200


def test_email_oauth_test_connection_success(client, monkeypatch):
    _patch_msal(monkeypatch)
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)

    resp = client.post("/settings/email/oauth/test", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "p",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "u@example.com" in body["message"]
    assert FakeSMTP.instances[0].calls == ["starttls", "docmd:AUTH", "quit"]
    assert FakePublicClientApplication.instances[0].client_id == "11111111-1111-1111-1111-111111111111"
    assert FakePublicClientApplication.instances[0].authority == "https://login.microsoftonline.com/contoso.onmicrosoft.com"

    view = client.get("/settings/email/oauth").json()
    assert view["last_test_ok"] is True


def test_email_oauth_test_connection_failure_from_azure_ad(client, monkeypatch):
    """A token request Azure AD itself rejects (bad password, Conditional
    Access blocking ROPC, consent not granted) - never reaches smtplib at
    all, same as test_smtp's own login-failure case never reaching
    send_message."""
    _patch_msal(monkeypatch)
    FakePublicClientApplication.result = {
        "error": "invalid_grant", "error_description": "AADSTS50126: Invalid username or password.",
    }
    resp = client.post("/settings/email/oauth/test", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "wrong",
    })
    body = resp.json()
    assert body["ok"] is False
    assert "AADSTS50126" in body["message"]
    assert FakeSMTP.instances == []  # never even tried to connect


def test_email_oauth_test_connection_failure_from_smtp_auth(client, monkeypatch):
    """Token acquisition succeeds but the XOAUTH2 handshake itself is
    rejected (e.g. SMTP.Send not actually consented) - a distinct failure
    mode from the Azure AD rejection above."""
    _patch_msal(monkeypatch)
    monkeypatch.setattr("smtplib.SMTP", lambda host, port, timeout=None: FakeSMTP(host, port, fail_on="auth"))

    resp = client.post("/settings/email/oauth/test", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "p",
    })
    body = resp.json()
    assert body["ok"] is False
    assert "535" in body["message"]


def test_email_oauth_test_connection_without_msal_installed(client, monkeypatch):
    import culprit.notifications.m365_oauth as m365_oauth

    monkeypatch.setattr(m365_oauth, "_MSAL_AVAILABLE", False)
    resp = client.post("/settings/email/oauth/test", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "p",
    })
    body = resp.json()
    assert body["ok"] is False
    assert "msal is not installed" in body["message"]
    assert "culprit[oauth]" in body["message"]


def test_email_oauth_test_connection_after_save_uses_the_stored_password_not_a_blank_one(client, monkeypatch):
    """Same bug class, same fix, as SMTP's identical test - the OAuth
    panel's password field is never re-populated after a save either."""
    _patch_msal(monkeypatch)
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "the-real-password",
    })

    resp = client.post("/settings/email/oauth/test", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "",
    })
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ── Active email method ──────────────────────────────────────────────────────

def test_email_method_defaults_to_smtp(client):
    assert client.get("/settings/email/method").json()["method"] == "smtp"


def test_email_method_can_be_switched_to_oauth_and_back(client):
    resp = client.put("/settings/email/method", json={"method": "oauth"})
    assert resp.status_code == 200
    assert resp.json()["method"] == "oauth"
    assert client.get("/settings/email/method").json()["method"] == "oauth"

    client.put("/settings/email/method", json={"method": "smtp"})
    assert client.get("/settings/email/method").json()["method"] == "smtp"


def test_email_method_rejects_an_unknown_value(client):
    resp = client.put("/settings/email/method", json={"method": "carrier_pigeon"})
    assert resp.status_code == 422


# ── Send-report route, OAuth method active ──────────────────────────────────

def test_send_email_409_when_oauth_active_but_not_configured(client, seeded_run_id):
    client.put("/settings/email/method", json={"method": "oauth"})
    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "a@b.com"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "email_oauth_not_configured"


def test_send_email_via_oauth_method_uses_the_oauth_default_dl(client, seeded_run_id, monkeypatch):
    _patch_msal(monkeypatch)
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "culprit@contoso.com", "password": "p",
        "default_recipients": ["ops@example.com"],
    })
    client.put("/settings/email/method", json={"method": "oauth"})

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["recipients"] == ["ops@example.com"]
    assert FakeSMTP.instances[0].calls == ["starttls", "docmd:AUTH", "send_message", "quit"]
    sent = FakeSMTP.instances[0].sent_message
    assert "culprit@contoso.com" in sent["From"]

    log = client.get("/settings/smtp/log").json()
    assert len(log) == 1
    assert log[0]["status"] == "success"


def test_send_email_does_not_use_oauth_dl_when_smtp_method_is_active(client, seeded_run_id, monkeypatch):
    """The two methods' default recipient lists are independent settings -
    configuring OAuth's DL must not leak into an SMTP-method send, and
    vice versa (each is read from its own settings row)."""
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "oauth@contoso.com",
        "default_recipients": ["oauth-dl@example.com"],
    })
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["smtp-dl@example.com"]})
    # method stays at its default ("smtp") - never switched

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    assert resp.json()["recipients"] == ["smtp-dl@example.com"]


def test_send_email_via_oauth_failure_still_returns_200_with_a_readable_message(client, seeded_run_id, monkeypatch):
    _patch_msal(monkeypatch)
    FakePublicClientApplication.result = {"error": "invalid_grant", "error_description": "AADSTS50126: bad password"}
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "u@example.com", "password": "p",
        "default_recipients": ["ops@example.com"],
    })
    client.put("/settings/email/method", json={"method": "oauth"})

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert "AADSTS50126" in body["message"]

    log = client.get("/settings/smtp/log").json()
    assert log[0]["status"] == "failed"


# ── Fleet Report page's "Email report" widget ────────────────────────────────
# Found by review 2026-10-22: GET /runs/{run_id}/report.html used to gate
# the whole widget on SMTP's own configured-state unconditionally, so it
# vanished entirely for a deployment that adopts OAuth as its sole method
# and never configures SMTP - exactly the "later we switch to this option"
# end state this feature was built for. No test anywhere exercised this
# route at all before these two.

def test_fleet_report_shows_the_email_widget_when_only_oauth_is_configured(client, seeded_run_id):
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "culprit@contoso.com",
        "default_recipients": ["oauth-dl@example.com"],
    })
    client.put("/settings/email/method", json={"method": "oauth"})
    # SMTP is deliberately left completely unconfigured.

    resp = client.get(f"/runs/{seeded_run_id}/report.html")
    assert resp.status_code == 200
    assert '<div class="email-report-widget' in resp.text
    assert "oauth-dl@example.com" in resp.text  # the ACTIVE method's own DL, not SMTP's (there isn't one)


def test_fleet_report_hides_the_email_widget_when_neither_method_is_configured(client, seeded_run_id):
    resp = client.get(f"/runs/{seeded_run_id}/report.html")
    assert resp.status_code == 200
    assert '<div class="email-report-widget' not in resp.text
