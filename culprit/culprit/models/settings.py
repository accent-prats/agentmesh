"""Azure and Datadog connection settings - what the /culprit/settings
screen reads and writes.

Two shapes per provider: an `*Input` the settings form submits (may
contain a secret in plain text over the wire, same as any credentials
form), and a `*View` the API returns afterwards, which never echoes a
secret back - only whether one is configured, plus the last
connection-test result.

The deep RCA agent's own AI provider (which model it calls) is a
platform-level, admin-managed setting owned by the Portal instead - see
`portal/db.py::AIProviderSetting` and `portal/api/routers/ai_providers.py`
- so it isn't modeled here at all.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class AzureSettingsInput(BaseModel):
    subscription_ids: list[str] = Field(default_factory=list)
    log_analytics_workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    # Blank on an update means "leave the currently-stored secret alone" -
    # routes_settings.py is what implements that merge; this model itself
    # doesn't know whether blank means "unset" or "unchanged".
    client_secret: str = ""
    # The one deliberate exception to the rule above: the settings screen's
    # "Managed identity" radio sets this to actually forget a previously-
    # saved secret when the admin explicitly switches away from a service
    # principal, instead of leaving it as an orphaned, unused ciphertext
    # (found 2026-10-10 - harmless functionally since build_credential never
    # reads it once tenant/client are blank, but confusing to leave behind).
    # A blank client_secret alone must never trigger this on its own, or
    # the anti-lockout protection above stops meaning anything.
    clear_credentials: bool = False


class AzureSettingsView(BaseModel):
    subscription_ids: list[str] = Field(default_factory=list)
    log_analytics_workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret_configured: bool = False
    configured: bool = False
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""


class DatadogSettingsInput(BaseModel):
    site: str = "datadoghq.com"
    api_key: str = ""
    app_key: str = ""
    # A Personal Access Token - Datadog's own documented alternative to the
    # api_key/app_key pair for everything except telemetry submission (see
    # collectors/datadog_auth.py::configure_datadog_client for exactly how
    # this reaches the wire). Blank on an update means "leave whatever's
    # stored alone", same rule as api_key/app_key - which side that rule
    # actually applies to is decided by use_personal_access_token below,
    # not by this field being blank on its own.
    personal_access_token: str = ""
    # Which of the two mutually-exclusive credential shapes the settings
    # screen's toggle has selected. Needed because, unlike Azure's single
    # "managed identity has no secret of its own" case, Datadog has two
    # independently-securable secrets - a blank field alone can't tell
    # "preserve the existing PAT, I'm just updating the site" apart from
    # "forget the API/App key, PAT mode is active now" (or the reverse).
    # See repository.py::save_datadog_settings for how this resolves it.
    use_personal_access_token: bool = False


class DatadogSettingsView(BaseModel):
    site: str = "datadoghq.com"
    api_key_configured: bool = False
    app_key_configured: bool = False
    personal_access_token_configured: bool = False
    configured: bool = False
    last_tested_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""


class ScheduleSettingsInput(BaseModel):
    """The recurring, unattended counterpart to POST /runs/live - same
    discover -> collect -> diagnose path (pipeline/live_run.py), just
    fired by cron instead of a button. See scheduler/cron.py for how this
    reaches an already-running in-process scheduler without a restart."""

    enabled: bool = False
    # 5 space-separated fields (minute hour day month weekday), UTC -
    # apscheduler.triggers.cron.CronTrigger.from_crontab's own format.
    # Not fully cron-validated here (that needs apscheduler, which this
    # model must stay free of - see save_schedule_settings's own note on
    # why that import has to stay lazy); this is just the field-count
    # sanity check that catches an empty or malformed string early,
    # before it reaches a process that actually has a live scheduler.
    cron_expression: str = "0 4 * * *"
    window_hours: int = Field(default=192, ge=1, le=720)
    scope_name: str = "scheduled"

    @field_validator("cron_expression")
    @classmethod
    def _validate_field_count(cls, v: str) -> str:
        if len(v.split()) != 5:
            raise ValueError('cron_expression must have exactly 5 space-separated fields: "minute hour day month weekday"')
        return v


class ScheduleSettingsView(ScheduleSettingsInput):
    # Whether *this process* actually has an in-process scheduler running
    # (CULPRIT_SCHEDULER_ENABLED) - a save always persists to the DB
    # regardless, but only a running scheduler can act on it immediately;
    # see repository.py::schedule_settings_view.
    scheduler_running: bool = False
    next_run_at: datetime | None = None


# The precision gate's editable floor - deliberately conservative and not
# itself configurable: this is what keeps "the gate can be tuned" from
# turning into "the gate can be switched off" via a careless or malicious
# save. A deployment that genuinely needs looser values makes that case
# in a code review of this constant, not through the settings screen.
GATE_THRESHOLD_FLOOR = 0.80
GATE_MIN_SAMPLE_FLOOR = 10


class GateSettingsInput(BaseModel):
    """What PUT /settings/gate accepts. `threshold`/`min_sample` can only
    be tightened or loosened within [floor, 1.0] / [floor, +inf) - Field's
    own ge/le raise a 422 automatically, same mechanism already used for
    ScheduleSettingsInput.window_hours, before this ever reaches the
    repository layer. `changed_by` is required and blank-rejected for the
    same reason RemediationActionRequest.requested_by is: every change to
    a setting that gates real infrastructure mutation needs an
    identifiable human attached, not just a truthy string."""

    threshold: float = Field(..., ge=GATE_THRESHOLD_FLOOR, le=1.0)
    min_sample: int = Field(..., ge=GATE_MIN_SAMPLE_FLOOR)
    changed_by: str = Field(..., min_length=1)

    @field_validator("changed_by")
    @classmethod
    def _changed_by_must_not_be_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("changed_by must not be blank")
        return stripped


class GateSettingsView(BaseModel):
    threshold: float
    min_sample: int
    # True when nothing has ever been saved via PUT /settings/gate - the
    # values shown are config.py's env-var defaults, not a stored override.
    is_default: bool = True
    updated_at: datetime | None = None
    updated_by: str = ""


class GateChangeEntry(BaseModel):
    """One row of GET /settings/gate/history - the audit trail behind the
    current value, most recent first."""

    id: int
    changed_at: datetime
    changed_by: str
    threshold: float
    min_sample: int
