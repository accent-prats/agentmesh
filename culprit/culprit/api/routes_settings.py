"""Azure and Datadog connection settings - the API behind /culprit/settings.

Every value round-trips through culprit/db/repository.py, which is the
only layer that knows about encryption; nothing here ever handles
ciphertext directly, and nothing here ever echoes a secret back once
saved - GET responses report `configured: bool`, never the value.

The deep RCA agent's own AI provider is configured on the Portal's admin
AI Providers screen instead, not here - see
`portal/api/routers/ai_providers.py` and `api/deps.py::get_rca_agent`.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from culprit.api import deps
from culprit.models.email import EmailLogEntry
from culprit.models.settings import (
    AzureSettingsInput,
    AzureSettingsView,
    DatadogSettingsInput,
    DatadogSettingsView,
    DisplayTimezoneSettingsInput,
    DisplayTimezoneSettingsView,
    EmailMethodSettingsInput,
    EmailMethodSettingsView,
    EmailOAuthSettingsInput,
    EmailOAuthSettingsView,
    GateChangeEntry,
    GateSettingsInput,
    GateSettingsView,
    ScheduleSettingsInput,
    ScheduleSettingsView,
    SmtpSettingsInput,
    SmtpSettingsView,
)
from culprit.security.credential_test import (
    test_azure_credentials,
    test_datadog_credentials,
    test_email_oauth_credentials,
    test_smtp_credentials,
)

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/azure", response_model=AzureSettingsView)
def get_azure_settings() -> AzureSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.azure_settings_view(session)


@router.put("/azure", response_model=AzureSettingsView)
def put_azure_settings(body: AzureSettingsInput) -> AzureSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_azure_settings(session, body)
        return repository.azure_settings_view(session)


@router.post("/azure/test")
def test_azure(body: AzureSettingsInput | None = None) -> dict:
    """Tests the given values if provided (so you can verify before
    saving), otherwise re-tests whatever is already stored - either way
    the result is persisted so the settings screen shows when this was
    last checked and whether it passed."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        cfg = body if body and (body.subscription_ids or body.tenant_id) else repository.load_azure_settings(session)
        ok, message = test_azure_credentials(cfg)
        repository.record_settings_test_result(session, "azure", ok, message)
        return {"ok": ok, "message": message}


@router.get("/datadog", response_model=DatadogSettingsView)
def get_datadog_settings() -> DatadogSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.datadog_settings_view(session)


@router.put("/datadog", response_model=DatadogSettingsView)
def put_datadog_settings(body: DatadogSettingsInput) -> DatadogSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_datadog_settings(session, body)
        return repository.datadog_settings_view(session)


@router.post("/datadog/test")
def test_datadog(body: DatadogSettingsInput | None = None) -> dict:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        cfg = body if body and (body.api_key or body.personal_access_token) else repository.load_datadog_settings(session)
        ok, message = test_datadog_credentials(cfg)
        repository.record_settings_test_result(session, "datadog", ok, message)
        return {"ok": ok, "message": message}


@router.get("/schedule", response_model=ScheduleSettingsView)
def get_schedule_settings(request: Request) -> ScheduleSettingsView:
    from culprit.db import repository

    scheduler = getattr(request.app.state, "scheduler", None)
    with deps.get_session_factory()() as session:
        return repository.schedule_settings_view(session, scheduler=scheduler)


@router.put("/schedule", response_model=ScheduleSettingsView)
def put_schedule_settings(body: ScheduleSettingsInput, request: Request) -> ScheduleSettingsView:
    """Takes effect on the live in-process scheduler immediately, not just
    in the DB - see culprit/scheduler/cron.py::apply_schedule. A deployment
    where CULPRIT_SCHEDULER_ENABLED is off has no live scheduler to apply
    to; this still saves the config for whenever it's next turned on -
    the response's scheduler_running=False is what tells the settings
    screen to say so, rather than implying this is live when it isn't.

    Validates cron_expression *before* saving anything - found in review
    2026-10-13: ScheduleSettingsInput's own validator only checks the
    field count (e.g. "60 99 * * *" passes it and is still nonsense), and
    without this, a bad value could be accepted here with a 200 whenever
    no live scheduler happened to be attached, sit in the DB unnoticed,
    and only surface as a crash at the next process start with the
    scheduler enabled - see validate_cron_expression's own docstring."""
    from culprit.db import repository
    from culprit.scheduler.cron import validate_cron_expression

    try:
        validate_cron_expression(body.cron_expression)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid cron_expression: {exc}") from exc

    scheduler = getattr(request.app.state, "scheduler", None)
    with deps.get_session_factory()() as session:
        repository.save_schedule_settings(session, body)
        if scheduler is not None:
            from culprit.scheduler.cron import apply_schedule

            apply_schedule(scheduler, body)
        return repository.schedule_settings_view(session, scheduler=scheduler)


@router.get("/display-timezone", response_model=DisplayTimezoneSettingsView)
def get_display_timezone_settings() -> DisplayTimezoneSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.display_timezone_settings_view(session)


@router.put("/display-timezone", response_model=DisplayTimezoneSettingsView)
def put_display_timezone_settings(body: DisplayTimezoneSettingsInput) -> DisplayTimezoneSettingsView:
    """Every stored datetime stays UTC regardless - this only changes how
    report/console/email timestamps are *displayed* (reporting/
    timezone_display.py). Validation (a real IANA name) already happened
    in DisplayTimezoneSettingsInput's own field_validator before this
    body was accepted."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_display_timezone_settings(session, body)
        return repository.display_timezone_settings_view(session)


@router.get("/gate", response_model=GateSettingsView)
def get_gate_settings() -> GateSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.gate_settings_view(session)


@router.put("/gate", response_model=GateSettingsView)
def put_gate_settings(body: GateSettingsInput) -> GateSettingsView:
    """Floor enforcement (threshold >= GATE_THRESHOLD_FLOOR, min_sample >=
    GATE_MIN_SAMPLE_FLOOR) already happened in GateSettingsInput's own
    Field constraints before this body ever parsed - a request outside
    that range never reaches this function at all, it's a 422. Takes
    effect on the very next gate check (culprit/db/repository.py::
    get_current_promotion_gate reads fresh, no caching, no restart
    needed) - same immediacy as every other live-checked gate condition
    in culprit/api/routes_remediation.py."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_promotion_gate_change(
            session, threshold=body.threshold, min_sample=body.min_sample, changed_by=body.changed_by,
        )
        return repository.gate_settings_view(session)


@router.get("/gate/history", response_model=list[GateChangeEntry])
def get_gate_settings_history() -> list[GateChangeEntry]:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        rows = repository.list_promotion_gate_changes(session, limit=20)
    return [
        GateChangeEntry(
            id=r.id, changed_at=r.changed_at, changed_by=r.changed_by,
            threshold=r.threshold, min_sample=r.min_sample,
        )
        for r in rows
    ]


@router.get("/smtp", response_model=SmtpSettingsView)
def get_smtp_settings() -> SmtpSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.smtp_settings_view(session)


@router.put("/smtp", response_model=SmtpSettingsView)
def put_smtp_settings(body: SmtpSettingsInput) -> SmtpSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_smtp_settings(session, body)
        return repository.smtp_settings_view(session)


@router.post("/smtp/test")
def test_smtp(body: SmtpSettingsInput | None = None) -> dict:
    """Tests the given values if provided (so you can verify before
    saving), otherwise re-tests whatever is already stored - mirrors
    test_azure/test_datadog, but with one deliberate difference (found in
    review 2026-10-14): the Email tab's password field is never
    re-populated after a page load or a save (passwords are never echoed
    back - see SmtpSettingsView), so a body submitted from that form
    always carries password="" except in the one moment right after
    someone typed a new one. Testing the submitted body's blank password
    literally would make "Save" then "Test connection" - the one natural
    flow this whole button exists for - fail authentication against
    almost any real server, immediately after a successful save. A blank
    submitted password falls back to whatever's already stored, the same
    "blank preserves existing" rule save_smtp_settings already applies."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        if body and body.host:
            cfg = body if body.password else body.model_copy(update={"password": repository.load_smtp_settings(session).password})
        else:
            cfg = repository.load_smtp_settings(session)
        ok, message = test_smtp_credentials(cfg)
        repository.record_settings_test_result(session, "smtp", ok, message)
        return {"ok": ok, "message": message}


@router.get("/smtp/log", response_model=list[EmailLogEntry])
def get_smtp_log() -> list[EmailLogEntry]:
    """Every report email ever sent, most recent first - the compact
    "Recent sends" list on the Email tab."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.list_email_log(session, limit=50)


@router.get("/email/oauth", response_model=EmailOAuthSettingsView)
def get_email_oauth_settings() -> EmailOAuthSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return repository.email_oauth_settings_view(session)


@router.put("/email/oauth", response_model=EmailOAuthSettingsView)
def put_email_oauth_settings(body: EmailOAuthSettingsInput) -> EmailOAuthSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_email_oauth_settings(session, body)
        return repository.email_oauth_settings_view(session)


@router.post("/email/oauth/test")
def test_email_oauth(body: EmailOAuthSettingsInput | None = None) -> dict:
    """Same shape as POST /settings/smtp/test, same blank-password-falls-
    back-to-stored reasoning - see that route's own docstring for why."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        if body and body.tenant_id:
            cfg = body if body.password else body.model_copy(
                update={"password": repository.load_email_oauth_settings(session).password}
            )
        else:
            cfg = repository.load_email_oauth_settings(session)
        ok, message = test_email_oauth_credentials(cfg)
        repository.record_settings_test_result(session, "email_oauth", ok, message)
        return {"ok": ok, "message": message}


@router.get("/email/method", response_model=EmailMethodSettingsView)
def get_email_method() -> EmailMethodSettingsView:
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        return EmailMethodSettingsView(method=repository.load_email_method(session))


@router.put("/email/method", response_model=EmailMethodSettingsView)
def put_email_method(body: EmailMethodSettingsInput) -> EmailMethodSettingsView:
    """Which of the two configured email methods (SMTP or Microsoft 365
    OAuth) api/routes_notifications.py actually sends through - a
    deliberate, explicit switch, not an automatic one; see
    EmailMethodSettingsInput's own docstring."""
    from culprit.db import repository

    with deps.get_session_factory()() as session:
        repository.save_email_method(session, body.method)
        return EmailMethodSettingsView(method=body.method)
