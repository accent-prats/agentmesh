"""Coverage for the tcx-mailer email delivery method - culprit/notifications/
tcx_mailer_adapter.py, email_sender.py's attachment support and shared
resolve_active_email_*/is_email_method_configured helpers, reporting/
report_bundle.py, notifications/auto_report_email.py, and the
/settings/email/tcx-mailer routes. Mirrors test_email_oauth.py's exact
conventions - `_mailer.mailer` is monkeypatched throughout via a fake
object; no real network connection or IT token/email API involved anywhere
in this file.
"""
from __future__ import annotations

import os
import zipfile

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.retrieval.corpus import default_retrieval_store


class FakeVendorMailer:
    """Stands in for `_mailer.mailer` - the real vendor module's public
    shape is `send_email(to, subject, body, attachments=None)` and
    `_get_token()`, plus the module-global `_TOKEN` cache
    tcx_mailer_adapter.py deliberately resets before every call."""

    def __init__(self):
        self.send_calls: list[dict] = []
        self.token_calls = 0
        self._TOKEN = None
        self.fail_send: Exception | None = None
        self.fail_token: Exception | None = None

    def send_email(self, to, subject, body, attachments=None):
        if self.fail_send:
            raise self.fail_send
        self.send_calls.append({"to": to, "subject": subject, "body": body, "attachments": list(attachments or [])})

    def _get_token(self):
        self.token_calls += 1
        if self.fail_token:
            raise self.fail_token
        self._TOKEN = "fake-token"
        return self._TOKEN


@pytest.fixture
def fake_vendor(monkeypatch):
    import culprit.notifications.tcx_mailer_adapter as tcx_mailer_adapter

    fake = FakeVendorMailer()
    monkeypatch.setattr(tcx_mailer_adapter, "_vendor_mailer", fake, raising=False)
    monkeypatch.setattr(tcx_mailer_adapter, "_MAILER_AVAILABLE", True)
    return fake


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


# ── Settings CRUD ─────────────────────────────────────────────────────────

def test_tcx_mailer_settings_default_view_is_unconfigured(client):
    resp = client.get("/settings/email/tcx-mailer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["password_configured"] is False
    assert body["default_recipients"] == []
    assert body["from_name"] == "Culprit"


def test_tcx_mailer_settings_save_and_reload_masks_the_password(client):
    resp = client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc-culprit", "password": "super-secret-value",
        "from_name": "Culprit", "default_recipients": ["ops@example.com"],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant"] == "acme-prod"
    assert body["password_configured"] is True
    assert "super-secret-value" not in resp.text
    assert body["configured"] is True

    reloaded = client.get("/settings/email/tcx-mailer").json()
    assert reloaded["username"] == "svc-culprit"
    assert reloaded["password_configured"] is True


def test_tcx_mailer_blank_password_on_update_preserves_the_existing_one(client):
    client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc-culprit", "password": "first-secret",
    })
    resp = client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc-culprit", "password": "",
    })
    assert resp.json()["password_configured"] is True

    from culprit.api.deps import get_session_factory
    from culprit.db import repository

    with get_session_factory()() as session:
        decrypted = repository.load_tcx_mailer_settings(session)
    assert decrypted.password == "first-secret"


def test_tcx_mailer_settings_configured_requires_tenant_and_username(client):
    from culprit.db import repository
    from culprit.db.engine import make_engine, make_session_factory
    from culprit.models.settings import TcxMailerSettingsInput

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    with factory() as session:
        repository.save_tcx_mailer_settings(session, TcxMailerSettingsInput(tenant="acme-prod"))
        assert repository.tcx_mailer_settings_view(session).configured is False

        repository.save_tcx_mailer_settings(session, TcxMailerSettingsInput(tenant="acme-prod", username="svc"))
        assert repository.tcx_mailer_settings_view(session).configured is True


def test_tcx_mailer_settings_rejects_a_malformed_recipient(client):
    resp = client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc", "default_recipients": ["not-an-email"],
    })
    assert resp.status_code == 422


# ── Credential test (POST /settings/email/tcx-mailer/test) ─────────────────

def test_tcx_mailer_test_connection_success(client, fake_vendor):
    resp = client.post("/settings/email/tcx-mailer/test", json={
        "tenant": "acme-prod", "username": "svc", "password": "p",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert fake_vendor.token_calls == 1

    view = client.get("/settings/email/tcx-mailer").json()
    assert view["last_test_ok"] is True


def test_tcx_mailer_test_connection_failure(client, fake_vendor):
    fake_vendor.fail_token = ValueError("invalid tenant")
    resp = client.post("/settings/email/tcx-mailer/test", json={
        "tenant": "acme-prod", "username": "svc", "password": "wrong",
    })
    body = resp.json()
    assert body["ok"] is False
    assert "invalid tenant" in body["message"]


def test_tcx_mailer_test_connection_without_the_package_installed(client, monkeypatch):
    import culprit.notifications.tcx_mailer_adapter as tcx_mailer_adapter

    monkeypatch.setattr(tcx_mailer_adapter, "_MAILER_AVAILABLE", False)
    resp = client.post("/settings/email/tcx-mailer/test", json={
        "tenant": "acme-prod", "username": "svc", "password": "p",
    })
    body = resp.json()
    assert body["ok"] is False
    assert "_mailer is not installed" in body["message"]


def test_tcx_mailer_test_connection_after_save_uses_the_stored_password_not_a_blank_one(client, fake_vendor):
    client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc", "password": "the-real-password",
    })
    resp = client.post("/settings/email/tcx-mailer/test", json={
        "tenant": "acme-prod", "username": "svc", "password": "",
    })
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ── The adapter's own vendor-workaround behavior (direct, no HTTP) ─────────

def test_send_tcx_mailer_pushes_and_restores_env_vars(fake_vendor, monkeypatch):
    from culprit.models.settings import TcxMailerSettingsInput
    from culprit.notifications.tcx_mailer_adapter import send_tcx_mailer

    monkeypatch.delenv("EMAIL_OAUTH_TENANT", raising=False)
    monkeypatch.setenv("EMAIL_FROM_NAME", "pre-existing-value")

    cfg = TcxMailerSettingsInput(tenant="acme-prod", username="svc", password="p", from_name="Culprit")
    ok, _ = send_tcx_mailer(cfg, ["a@b.com"], "subject", "body")
    assert ok is True

    # Restored exactly - the key that didn't exist before is gone again, the
    # key that did have a value is back to it, not left as "Culprit".
    assert "EMAIL_OAUTH_TENANT" not in os.environ
    assert os.environ["EMAIL_FROM_NAME"] == "pre-existing-value"


def test_send_tcx_mailer_restores_env_vars_even_when_the_send_itself_raises(fake_vendor, monkeypatch):
    from culprit.models.settings import TcxMailerSettingsInput
    from culprit.notifications.tcx_mailer_adapter import send_tcx_mailer

    monkeypatch.delenv("EMAIL_OAUTH_TENANT", raising=False)
    fake_vendor.fail_send = RuntimeError("gateway unreachable")

    cfg = TcxMailerSettingsInput(tenant="acme-prod", username="svc", password="p")
    ok, message = send_tcx_mailer(cfg, ["a@b.com"], "subject", "body")
    assert ok is False
    assert "gateway unreachable" in message
    assert "EMAIL_OAUTH_TENANT" not in os.environ


def test_send_tcx_mailer_resets_the_cached_token_before_every_call(fake_vendor):
    """The vendor's own _get_token() caches its result in _TOKEN forever,
    with no expiry check - send_tcx_mailer resets it before every call so a
    credential change or an expired token can't silently keep being reused."""
    from culprit.models.settings import TcxMailerSettingsInput
    from culprit.notifications.tcx_mailer_adapter import send_tcx_mailer

    fake_vendor._TOKEN = "a-stale-token-from-an-earlier-call"
    cfg = TcxMailerSettingsInput(tenant="acme-prod", username="svc", password="p")
    send_tcx_mailer(cfg, ["a@b.com"], "subject", "body")
    # send_email() itself doesn't touch _TOKEN in this fake (only a real
    # _get_token() call would) - this pins that the adapter cleared it
    # BEFORE calling send_email, not that send_email reset it itself.
    assert fake_vendor._TOKEN is None


def test_send_tcx_mailer_writes_and_cleans_up_attachment_temp_files(fake_vendor):
    from culprit.models.settings import TcxMailerSettingsInput
    from culprit.notifications.tcx_mailer_adapter import send_tcx_mailer

    cfg = TcxMailerSettingsInput(tenant="acme-prod", username="svc", password="p")
    ok, _ = send_tcx_mailer(cfg, ["a@b.com"], "subject", "body", attachments=[("report.zip", b"zip-bytes-here")])
    assert ok is True
    assert len(fake_vendor.send_calls) == 1
    paths = fake_vendor.send_calls[0]["attachments"]
    assert len(paths) == 1
    # The file existed (with the right content) during the call - the fake
    # records the path, so re-reading it here would only prove it if the
    # adapter hadn't already cleaned it up; assert it's gone now instead.
    assert not os.path.exists(paths[0])


def test_send_tcx_mailer_not_installed(monkeypatch):
    import culprit.notifications.tcx_mailer_adapter as tcx_mailer_adapter
    from culprit.models.settings import TcxMailerSettingsInput

    monkeypatch.setattr(tcx_mailer_adapter, "_MAILER_AVAILABLE", False)
    cfg = TcxMailerSettingsInput(tenant="acme-prod", username="svc", password="p")
    ok, message = tcx_mailer_adapter.send_tcx_mailer(cfg, ["a@b.com"], "s", "b")
    assert ok is False
    assert "_mailer is not installed" in message


def test_send_tcx_mailer_not_configured(fake_vendor):
    from culprit.models.settings import TcxMailerSettingsInput
    from culprit.notifications.tcx_mailer_adapter import send_tcx_mailer

    ok, message = send_tcx_mailer(TcxMailerSettingsInput(), ["a@b.com"], "s", "b")
    assert ok is False
    assert "not configured" in message
    assert fake_vendor.send_calls == []


# ── Email method switch ──────────────────────────────────────────────────

def test_email_method_can_be_switched_to_tcx_mailer_and_back(client):
    client.put("/settings/email/method", json={"method": "smtp"})
    resp = client.put("/settings/email/method", json={"method": "tcx_mailer"})
    assert resp.status_code == 200
    assert resp.json()["method"] == "tcx_mailer"
    assert client.get("/settings/email/method").json()["method"] == "tcx_mailer"


# Found by review 2026-11-02, reproduced directly: a deployment that
# configured SMTP (or OAuth) before tcx_mailer existed, and never
# separately visited the method radio, got silently switched to
# tcx_mailer the moment this feature shipped - breaking the
# already-working manual "Send Report" button with a 409
# email_tcx_mailer_not_configured instead of sending via the SMTP server
# that was already set up. This app has no data-migration mechanism, so
# load_email_method's own fallback has to make this distinction itself.

def test_email_method_preserves_smtp_default_for_a_pre_existing_smtp_deployment(client):
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})
    # Deliberately never touch /settings/email/method - the exact shape of
    # a deployment that configured email before this feature existed.
    assert client.get("/settings/email/method").json()["method"] == "smtp"


def test_email_method_preserves_smtp_default_for_a_pre_existing_oauth_deployment(client):
    client.put("/settings/email/oauth", json={
        "tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-1111-1111-1111-111111111111",
        "username": "culprit@contoso.com",
    })
    assert client.get("/settings/email/method").json()["method"] == "smtp"


def test_email_method_defaults_to_tcx_mailer_only_for_a_genuinely_fresh_deployment(client):
    """Neither SMTP nor OAuth has ever been touched - the one case the new
    default is actually meant for."""
    assert client.get("/settings/email/method").json()["method"] == "tcx_mailer"


def test_send_report_email_still_works_via_smtp_for_a_pre_existing_deployment(client, seeded_run_id, monkeypatch):
    """The regression reproduced end-to-end: the existing manual "Send
    Report" button must keep working via SMTP for a deployment that
    configured it before this feature existed, with no 409."""
    import smtplib

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def starttls(self):
            pass

        def send_message(self, msg):
            pass

        def quit(self):
            pass

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ── Offline report bundle (reporting/report_bundle.py) ──────────────────────

def test_build_offline_report_bundle_contains_every_linked_page(client, seeded_run_id):
    from culprit.api.deps import get_session_factory
    from culprit.db import repository
    from culprit.reporting.report_bundle import build_offline_report_bundle

    with get_session_factory()() as session:
        report = repository.load_fleet_report(session, seeded_run_id)
        zip_bytes = build_offline_report_bundle(session, report)

    with zipfile.ZipFile(__import__("io").BytesIO(zip_bytes)) as zf:
        names = set(zf.namelist())
        assert f"runs/{seeded_run_id}/report.html" in names
        assert "static/tailwind.js" in names
        # Found by review 2026-11-02: lucide.min.js was missing (only
        # tailwind.js was hardcoded) - base.html.j2's shared inline script
        # calls lucide.createIcons() as its FIRST statement, with no
        # try/catch, before the .eg-detail-toggle click handlers it wires
        # up right after - a missing lucide there means every "Show full
        # error/status/timeline" disclosure is permanently stuck hidden in
        # the offline bundle, not just missing icons.
        assert "static/lucide.min.js" in names
        from culprit.reporting.report_bundle import _STATIC_DIR

        assert zf.read("static/lucide.min.js") == (_STATIC_DIR / "lucide.min.js").read_bytes()
        # Every machine the Fleet Report's own table links to has its own page.
        for row in report.machine_rows:
            assert f"runs/{seeded_run_id}/machines/{row.vm_name}.html" in names

        # The relative link fleet_report.html.j2 actually renders for a
        # machine really does resolve to a real entry in this same zip -
        # proves the chosen "replicate the live route's folder depth"
        # approach, not just that files with plausible names exist.
        report_html = zf.read(f"runs/{seeded_run_id}/report.html").decode()
        if report.machine_rows:
            sample_vm = report.machine_rows[0].vm_name
            assert f"machines/{sample_vm}.html" in report_html
            assert f"runs/{seeded_run_id}/machines/{sample_vm}.html" in names


# ── send_report_on_completion (notifications/auto_report_email.py) ─────────

def test_send_report_on_completion_skips_quietly_with_no_recipients(client, seeded_run_id):
    from culprit.api.deps import get_session_factory
    from culprit.db import repository
    from culprit.models.patch_run import TriggerMode
    from culprit.notifications.auto_report_email import send_report_on_completion

    with get_session_factory()() as session:
        report = repository.load_fleet_report(session, seeded_run_id)

    send_report_on_completion(get_session_factory(), report, TriggerMode.AD_HOC)  # must not raise

    with get_session_factory()() as session:
        assert repository.list_email_log(session) == []


def test_send_report_on_completion_sends_via_the_active_method_and_logs_it(client, seeded_run_id, fake_vendor):
    from culprit.api.deps import get_session_factory
    from culprit.db import repository
    from culprit.models.patch_run import TriggerMode
    from culprit.notifications.auto_report_email import send_report_on_completion

    client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc", "password": "p",
        "default_recipients": ["ops@example.com"],
    })
    client.put("/settings/email/method", json={"method": "tcx_mailer"})

    with get_session_factory()() as session:
        report = repository.load_fleet_report(session, seeded_run_id)

    send_report_on_completion(get_session_factory(), report, TriggerMode.SCHEDULED)

    assert len(fake_vendor.send_calls) == 1
    call = fake_vendor.send_calls[0]
    assert call["to"] == ["ops@example.com"]
    assert seeded_run_id in call["subject"] or report.run.scope_name in call["subject"]
    assert len(call["attachments"]) == 1

    with get_session_factory()() as session:
        log = repository.list_email_log(session)
    assert len(log) == 1
    assert log[0].requested_by == "system (auto-send on completion)"
    assert log[0].status.value == "success"


def test_build_subject_and_body_formats_the_window_cleanly_not_a_raw_repr(client, seeded_run_id):
    """Found by review 2026-11-02: a bare str(datetime) in the Window line
    left a real run reading like "...12:13:48.373324" (raw UTC,
    microseconds and all) - nowhere near as clean as the subject line's own
    date_str, and inconsistent with how every other timestamp in this app
    (reporting/timezone_display.py's `localtime` filter) is formatted."""
    import datetime as datetime_module

    from culprit.api.deps import get_session_factory
    from culprit.db import repository
    from culprit.models.patch_run import TriggerMode
    from culprit.notifications.auto_report_email import _build_subject_and_body

    with get_session_factory()() as session:
        report = repository.load_fleet_report(session, seeded_run_id)

    messy_ended_at = datetime_module.datetime(2026, 11, 2, 12, 13, 48, 373324, tzinfo=datetime_module.timezone.utc)
    report = report.model_copy(update={"run": report.run.model_copy(update={"ended_at": messy_ended_at})})

    _subject, plain_text_body, html_body = _build_subject_and_body(report, TriggerMode.SCHEDULED, "UTC")
    for body in (plain_text_body, html_body):
        assert "373324" not in body
        assert ".373324" not in body
    assert "2026-11-02 12:13" in plain_text_body


# ── End-to-end: the real scheduler hook (pipeline/live_run.py) ─────────────

def test_scheduled_cycle_auto_sends_the_report_via_tcx_mailer(client, fake_vendor, monkeypatch):
    """Exercises the REAL hook in pipeline/live_run.py::execute_live_run,
    not just send_report_on_completion in isolation - sabotage-provable by
    removing that hook and confirming this specific test (not just the
    unit test above) fails."""
    import culprit.api.deps as deps_module
    from culprit.collectors.base import CollectionResult
    from culprit.models.evidence import MachineIdentity, OSFamily, PatchOutcome, Source

    client.put("/settings/email/tcx-mailer", json={
        "tenant": "acme-prod", "username": "svc", "password": "p",
        "default_recipients": ["ops@example.com"],
    })
    client.put("/settings/email/method", json={"method": "tcx_mailer"})
    client.put("/settings/azure", json={"subscription_ids": ["sub-1"], "client_secret": "x"})

    fake_machine = MachineIdentity(
        vm_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        vm_name="vm-1", resource_group="rg", subscription_id="sub-1", os_family=OSFamily.LINUX,
    )

    class _FakeAzureCfg:
        subscription_ids = ["sub-1"]
        log_analytics_workspace_id = ""
        tenant_id = ""
        client_id = ""
        client_secret = ""

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

    from culprit.scheduler.cron import scheduled_cycle

    scheduled_cycle(scope_name="nightly")

    assert len(fake_vendor.send_calls) == 1
    assert fake_vendor.send_calls[0]["to"] == ["ops@example.com"]
