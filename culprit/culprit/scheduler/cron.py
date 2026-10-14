"""Scheduled and pre-flight triggers (proposal Section 10).

Two jobs:
  - `scheduled_cycle`: runs shortly after each maintenance window closes,
    on a cron aligned to the window's own schedule.
  - `pre_flight_check`: runs continuously between cycles, evaluating the
    *rule engine only* (no deep RCA, no cost) against each machine's
    *current* state to predict which ones will fail the next window -
    "the shortest path from 'interesting analysis' to 'our failure rate
    went down'" per Section 10.

Both read whatever's configured on /culprit/settings at fire time (not a
subscription id baked into the job args), so turning this on is just
"set Azure settings, then start the scheduler" - see build_scheduler's own
docstring for why the *_id args below don't do that lookup themselves.

Uses APScheduler's BackgroundScheduler so this can run in-process
alongside the FastAPI app, or as its own worker process in production.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

log = logging.getLogger(__name__)

# How far back a scheduled cycle looks for failed patch results - the
# window between two runs of the same maintenance configuration is
# normally under a week; a day of slack either side covers a late-running
# job without re-diagnosing an entire prior cycle's failures again. Still
# the default shown on /culprit/settings' "Scheduled runs" card - editable
# there (ScheduleSettingsInput.window_hours) without a redeploy.
_SCHEDULED_WINDOW_HOURS = 24 * 8

# Fixed regardless of scope_name, unlike build_scheduler's old
# per-scope-name id - there is exactly one scheduled-run config now (the
# Settings screen edits one row, not one per scope), so apply_schedule can
# always find and replace/remove this same job.
SCHEDULED_JOB_ID = "scheduled_cycle"


def scheduled_cycle(scope_name: str = "scheduled", window_hours: int = _SCHEDULED_WINDOW_HOURS) -> None:
    """Fires after a maintenance window closes. Exactly the same
    discover -> collect -> diagnose path `POST /runs/live` uses
    (culprit/pipeline/live_run.py), just triggered by cron instead of an
    HTTP request - there's no inbound request here to build a report link
    from the way reporting/notify.py's report_url_from_request does, so the digest's link
    (if any) comes from CULPRIT_PUBLIC_URL instead (see _notify below).

    `window_hours` defaults to the module constant for any direct caller
    (e.g. this file's own tests) but is always passed explicitly by
    apply_schedule, from whatever's saved on /culprit/settings."""
    from culprit.models.patch_run import TriggerMode
    from culprit.pipeline.live_run import NoSubscriptionConfigured, execute_live_run

    log.info("Scheduled cycle firing for scope=%s", scope_name)
    try:
        report = execute_live_run(
            window_hours=window_hours, scope_name=scope_name, trigger_mode=TriggerMode.SCHEDULED
        )
    except NoSubscriptionConfigured:
        log.info("Scheduled cycle skipped - no Azure subscription configured on /culprit/settings yet")
        return
    except Exception:  # noqa: BLE001 - a scheduler job crashing must not kill the scheduler thread
        log.exception("Scheduled cycle failed for scope=%s", scope_name)
        return

    log.info(
        "Scheduled cycle complete: %d/%d failed, %d distinct causes",
        report.total_failed, report.total_machines, report.total_clusters,
    )
    _notify(report)


def pre_flight_check() -> None:
    """Rule-engine-only prediction: for every in-scope machine, build a
    lightweight EvidenceBundle from *current* state (not a completed run)
    and check it against the same deterministic rules used post-hoc. A
    positive hit here (e.g. disk already low, agent already stale, a
    pending reboot already set) is exactly the kind of failure a real
    patch window would produce - flag it now, while there's still time to
    fix it before the window opens. Findings replace the previous scan's
    (culprit/db/repository.py::save_preflight_findings) and are read back
    by GET /preflight and the "which machines will fail next" chat query
    (culprit/api/routes_chat.py)."""
    from culprit.api import deps
    from culprit.db import repository
    from culprit.pipeline.discovery import discover_all_machines
    from culprit.pipeline.preflight import run_preflight_scan

    session_factory = deps.get_session_factory()

    try:
        with session_factory() as session:
            azure_cfg = repository.load_azure_settings(session)
        if not azure_cfg.subscription_ids:
            log.info("Pre-flight check skipped - no Azure subscription configured on /culprit/settings yet")
            return

        with session_factory() as session:
            collectors, azure_cfg, credential = deps.build_live_collectors(session)
        machines = discover_all_machines(credential, azure_cfg.subscription_ids)
        findings = run_preflight_scan(collectors, machines)
    except Exception:  # noqa: BLE001 - a scheduler job crashing must not kill the scheduler thread
        # Covers the same failure modes execute_live_run's caller guards
        # against (rotated CULPRIT_ENCRYPTION_KEY -> InvalidToken, missing
        # azure-identity -> ImportError) - there's no HTTP response here to
        # translate them into, so they're all just logged and skipped.
        log.exception("Pre-flight check failed")
        return

    with session_factory() as session:
        repository.save_preflight_findings(session, findings)
    log.info("Pre-flight check complete: %d/%d machines flagged", len(findings), len(machines))


def _notify(report) -> None:
    from culprit.config import settings

    webhook = settings.teams_webhook_url or settings.slack_webhook_url
    if not webhook:
        return
    try:
        from culprit.reporting.notify import post_to_slack, post_to_teams

        report_url = f"{settings.public_url}/runs/{report.run.run_id}/report.html" if settings.public_url else None
        poster = post_to_teams if settings.teams_webhook_url else post_to_slack
        response = poster(webhook, report, report_url=report_url)
        log.info("Posted digest for run %s to webhook - status %s", report.run.run_id, response.status_code)
    except Exception:  # noqa: BLE001 - a notification failure must not fail the cycle
        log.exception("Failed to post digest for run %s to webhook", report.run.run_id)


def validate_cron_expression(cron_expression: str) -> None:
    """Raises ValueError (CronTrigger's own message) when `cron_expression`
    isn't a semantically valid 5-field cron string - ScheduleSettingsInput's
    own Pydantic validator only checks the field COUNT, not that each
    field is a legal value (e.g. "60 99 * * *" has 5 fields and is still
    nonsense). Called by PUT /settings/schedule *before* persisting -
    found in review 2026-10-13: without this, a bad value saved while no
    live scheduler was attached (the common case - CULPRIT_SCHEDULER_ENABLED
    defaults to false) would sit in the DB unnoticed (200 OK,
    scheduler_running: false) until the next process start with that env
    var true, at which point build_scheduler -> apply_schedule's then-bare
    CronTrigger.from_crontab call raised with nothing to catch it and no
    request to turn it into a 4xx - that crashed the entire app's startup,
    not just one PUT."""
    CronTrigger.from_crontab(cron_expression)


def apply_schedule(scheduler: BackgroundScheduler, cfg) -> None:
    """(Re)applies `cfg` (a culprit.models.settings.ScheduleSettingsInput,
    as saved on /culprit/settings) to an already-running scheduler -
    called once at startup (main.py's lifespan, seeded from whatever the
    DB already has) and again every time PUT /settings/schedule saves a
    change, so editing the cron expression, window, scope, or the enabled
    toggle itself all take effect immediately, with no restart - the same
    "DB is authoritative, takes effect live" contract Azure/Datadog
    settings already have.

    The try/except below should be unreachable for anything saved through
    PUT /settings/schedule, which validates first (routes_settings.py,
    via validate_cron_expression) - it's a second line of defense for a
    row written before that validation existed, or edited directly in the
    DB, so a bad value still can't take the whole process down at startup
    the way it did before this guard existed (see validate_cron_expression's
    own docstring)."""
    if cfg.enabled:
        try:
            trigger = CronTrigger.from_crontab(cfg.cron_expression)
        except ValueError:
            log.exception(
                "Scheduled run is misconfigured - cron_expression %r is invalid, leaving it disabled",
                cfg.cron_expression,
            )
            if scheduler.get_job(SCHEDULED_JOB_ID):
                scheduler.remove_job(SCHEDULED_JOB_ID)
            return
        scheduler.add_job(
            scheduled_cycle,
            trigger=trigger,
            kwargs={"scope_name": cfg.scope_name, "window_hours": cfg.window_hours},
            id=SCHEDULED_JOB_ID,
            replace_existing=True,
        )
    elif scheduler.get_job(SCHEDULED_JOB_ID):
        scheduler.remove_job(SCHEDULED_JOB_ID)


def build_scheduler(schedule_cfg, pre_flight_interval_minutes: int = 60) -> BackgroundScheduler:
    """Both jobs read Azure settings from /culprit/settings at fire time
    (see scheduled_cycle/pre_flight_check above) rather than taking a
    subscription id here - that's the whole point of the settings screen:
    change it without a redeploy. `schedule_cfg` is whatever's saved there
    at process startup (culprit/db/repository.py::load_schedule_settings);
    main.py's lifespan handler is what loads it and re-applies live edits
    afterwards via apply_schedule() - this function only builds the
    scheduler once, at process start."""
    scheduler = BackgroundScheduler(timezone=timezone.utc)
    apply_schedule(scheduler, schedule_cfg)
    scheduler.add_job(
        pre_flight_check,
        trigger="interval",
        minutes=pre_flight_interval_minutes,
        id="pre_flight_check",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    return scheduler
