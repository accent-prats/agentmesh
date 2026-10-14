"""Coverage for emailing a run's report (culprit/notifications/,
api/routes_notifications.py, SMTP settings in api/routes_settings.py) -
the one feature in this app that sends outbound mail. `smtplib.SMTP`/
`SMTP_SSL` are monkeypatched throughout - no real network connection or
SMTP server involved anywhere in this file.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory
from culprit.demo.scripted_rca import ScriptedRCAAgent
from culprit.retrieval.corpus import default_retrieval_store


class FakeSMTP:
    """Records every call instead of opening a real connection. Raises on
    `.login()` or `.send_message()` when constructed with `fail_on` set,
    to exercise the failure path without a real broken server."""

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

    def login(self, username, password):
        if self._fail_on == "login":
            raise Exception("535 authentication failed")
        self.calls.append(f"login:{username}")

    def send_message(self, msg):
        if self._fail_on == "send":
            raise Exception("connection reset by peer")
        self.sent_message = msg
        self.calls.append("send_message")

    def quit(self):
        self.calls.append("quit")


@pytest.fixture(autouse=True)
def _reset_fake_smtp_instances():
    FakeSMTP.instances = []
    yield
    FakeSMTP.instances = []


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
    """A real run, seeded through the actual pipeline (POST /runs/demo) -
    same technique as test_report_completeness.py, simpler than hand-
    assembling a Cluster/RCAResult pair when all this feature needs is
    *a* loadable FleetReport, not any particular diagnosis content."""
    resp = client.post("/runs/demo")
    assert resp.status_code == 200
    return resp.json()["run"]["run_id"]


# ── SMTP settings CRUD ──────────────────────────────────────────────────────

def test_smtp_settings_default_view_is_unconfigured(client):
    resp = client.get("/settings/smtp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["password_configured"] is False
    assert body["default_recipients"] == []
    assert body["encryption"] == "starttls"


def test_smtp_settings_save_and_reload_masks_the_password(client):
    resp = client.put("/settings/smtp", json={
        "host": "smtp.example.com", "port": 587, "username": "bot@example.com",
        "password": "super-secret-value", "encryption": "starttls",
        "from_address": "culprit@example.com", "from_name": "Culprit",
        "default_recipients": ["ops@example.com", "qa@example.com"],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["host"] == "smtp.example.com"
    assert body["password_configured"] is True
    assert "super-secret-value" not in resp.text
    assert body["configured"] is True
    assert body["default_recipients"] == ["ops@example.com", "qa@example.com"]

    reloaded = client.get("/settings/smtp").json()
    assert reloaded["host"] == "smtp.example.com"
    assert reloaded["password_configured"] is True


def test_smtp_blank_password_on_update_preserves_the_existing_one(client, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "password": "first-secret", "username": "u"})

    resp = client.put("/settings/smtp", json={"host": "smtp.example.com", "username": "u", "password": ""})
    body = resp.json()
    assert body["password_configured"] is True  # still true - not wiped by the blank field

    from culprit.api.deps import get_session_factory
    from culprit.db import repository

    with get_session_factory()() as session:
        decrypted = repository.load_smtp_settings(session)
    assert decrypted.password == "first-secret"


def test_smtp_settings_rejects_a_malformed_email(client):
    resp = client.put("/settings/smtp", json={"host": "smtp.example.com", "from_address": "not-an-email"})
    assert resp.status_code == 422

    resp = client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["not-an-email"]})
    assert resp.status_code == 422


def test_smtp_settings_rejects_html_metacharacters_in_a_recipient(client):
    """Found in review 2026-10-14: the original regex only excluded '@'
    and whitespace, so '"><script>alert(1)</script>@evil.com' passed as
    a "valid" recipient - combined with a since-fixed autoescape bug, a
    saved default recipient like this rendered live, unescaped script
    into every Fleet Report page's pre-filled "To" field. The tightened
    pattern structurally cannot admit '<', '>', '"', or a second '@'."""
    resp = client.put("/settings/smtp", json={
        "host": "smtp.example.com",
        "default_recipients": ['"><script>alert(document.cookie)</script>@evil.com'],
    })
    assert resp.status_code == 422


def test_smtp_test_connection_success(client, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    resp = client.post("/settings/smtp/test", json={"host": "smtp.example.com", "port": 587, "username": "u", "password": "p", "encryption": "starttls"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "authenticated" in body["message"]
    assert FakeSMTP.instances[0].calls == ["starttls", "login:u", "quit"]

    view = client.get("/settings/smtp").json()
    assert view["last_test_ok"] is True


def test_smtp_test_connection_failure(client, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", lambda host, port, timeout=None: FakeSMTP(host, port, fail_on="login"))
    resp = client.post("/settings/smtp/test", json={"host": "smtp.example.com", "port": 587, "username": "u", "password": "wrong", "encryption": "starttls"})
    body = resp.json()
    assert body["ok"] is False
    assert "authentication failed" in body["message"]


def test_smtp_test_connection_uses_the_body_when_given(client, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    resp = client.post("/settings/smtp/test", json={"host": "from-body.example.com", "port": 25})
    assert resp.status_code == 200
    assert FakeSMTP.instances[0].host == "from-body.example.com"


# ── Send-report route ────────────────────────────────────────────────────────

def test_send_email_404_when_run_not_found(client):
    resp = client.post("/runs/nope/email", json={"requested_by": "a@b.com"})
    assert resp.status_code == 404


def test_send_email_409_when_smtp_not_configured(client, seeded_run_id):
    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "a@b.com"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "smtp_not_configured"


def test_send_email_400_when_no_recipients_and_no_default_dl(client, seeded_run_id):
    client.put("/settings/smtp", json={"host": "smtp.example.com"})
    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "a@b.com"})
    assert resp.status_code == 400


def test_send_email_rejects_blank_requested_by(client, seeded_run_id):
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})
    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "   "})
    assert resp.status_code == 422


def test_send_email_uses_the_default_dl_when_no_recipients_given(client, seeded_run_id, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={
        "host": "smtp.example.com", "from_address": "culprit@example.com",
        "default_recipients": ["ops@example.com", "qa@example.com"],
    })

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["recipients"] == ["ops@example.com", "qa@example.com"]
    assert FakeSMTP.instances[0].calls == ["starttls", "send_message", "quit"]  # no username set -> no login attempted
    sent = FakeSMTP.instances[0].sent_message
    assert sent["To"] == "ops@example.com, qa@example.com"
    assert "failed" in sent["Subject"]


def test_send_email_overrides_the_default_dl_when_recipients_given(client, seeded_run_id, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})

    resp = client.post(
        f"/runs/{seeded_run_id}/email",
        json={"requested_by": "alice@example.com", "recipients": ["bob@example.com"]},
    )
    assert resp.status_code == 200
    assert resp.json()["recipients"] == ["bob@example.com"]


def test_send_email_persists_one_audit_log_record(client, seeded_run_id, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})
    client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com", "note": "FYI"})

    log = client.get("/settings/smtp/log").json()
    assert len(log) == 1
    assert log[0]["run_id"] == seeded_run_id
    assert log[0]["recipients"] == ["ops@example.com"]
    assert log[0]["requested_by"] == "alice@example.com"
    assert log[0]["status"] == "success"


def test_send_email_failure_still_returns_200_with_a_readable_message(client, seeded_run_id, monkeypatch):
    monkeypatch.setattr("smtplib.SMTP", lambda host, port, timeout=None: FakeSMTP(host, port, fail_on="send"))
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})

    resp = client.post(f"/runs/{seeded_run_id}/email", json={"requested_by": "alice@example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert "connection reset" in body["message"]

    log = client.get("/settings/smtp/log").json()
    assert log[0]["status"] == "failed"


def test_send_email_rejects_a_crlf_in_a_per_send_recipient(client, seeded_run_id):
    """Found in review 2026-10-14: SendReportRequest.recipients had no
    format validation at all (unlike the stored default DL), so a
    recipient containing \\r\\n reached email.message.EmailMessage's
    header-setting unvalidated, which raises a bare ValueError there -
    outside send_email's own try/except at the time - producing an
    unhandled 500 with zero audit-log row, breaking both the "always 200,
    report failure in the body" contract and the append-only audit
    trail's promise to record every attempt. Must now be a clean 422,
    before send_email (and therefore smtplib) is ever reached."""
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})

    resp = client.post(
        f"/runs/{seeded_run_id}/email",
        json={"requested_by": "alice@example.com", "recipients": ["a@b.com\r\nBcc: evil@attacker.com"]},
    )
    assert resp.status_code == 422

    assert client.get("/settings/smtp/log").json() == []


def test_email_note_is_html_escaped_in_the_sent_message(client, seeded_run_id, monkeypatch):
    """The one genuinely freeform field in this whole feature (note has
    no format restriction, by design) - this is what actually proves
    reporting/render.py::_env()'s autoescape fix (found in the same
    review: select_autoescape(["html"]) never matched any "*.html.j2"
    template name, so autoescaping was silently off app-wide) rather than
    just that the one exploitable field (default_recipients) now happens
    to be blocked earlier by its own stricter email-shape validator."""
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "default_recipients": ["ops@example.com"]})

    resp = client.post(
        f"/runs/{seeded_run_id}/email",
        json={"requested_by": "alice@example.com", "note": "<script>alert(document.cookie)</script>"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    html_part = FakeSMTP.instances[0].sent_message.get_body(preferencelist=("html",)).get_content()
    assert "<script>alert(document.cookie)</script>" not in html_part
    assert "&lt;script&gt;" in html_part


def test_smtp_test_connection_after_save_uses_the_stored_password_not_a_blank_one(client, monkeypatch):
    """Found in review 2026-10-14: the Email tab's password field is
    never re-populated after a save (passwords are never echoed back),
    so clicking "Test connection" right after "Save" - the one natural
    flow this button exists for - submitted a body with password="",
    which the route tested literally, making authentication fail against
    almost any real server immediately after a successful save."""
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    client.put("/settings/smtp", json={"host": "smtp.example.com", "username": "bot", "password": "the-real-password"})

    # Same shape the Settings page's smtpFormBody() submits right after a
    # save: host/username present, password blank (never re-populated).
    resp = client.post("/settings/smtp/test", json={"host": "smtp.example.com", "username": "bot", "password": ""})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert FakeSMTP.instances[0].calls == ["starttls", "login:bot", "quit"]
