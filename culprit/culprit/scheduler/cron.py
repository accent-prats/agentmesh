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
# job without re-diagnosing an entire prior cycle's failures again.
_SCHEDULED_WINDOW_HOURS = 24 * 8


def scheduled_cycle(scope_name: str = "scheduled") -> None:
    """Fires after a maintenance window closes. Exactly the same
    discover -> collect -> diagnose path `POST /runs/live` uses
    (culprit/pipeline/live_run.py), just triggered by cron instead of an
    HTTP request - there's no inbound request here to build a report link
    from the way routes_runs.py's _report_url does, so the digest's link
    (if any) comes from CULPRIT_PUBLIC_URL instead (see _notify below)."""
    from culprit.models.patch_run import TriggerMode
    from culprit.pipeline.live_run import NoSubscriptionConfigured, execute_live_run

    log.info("Scheduled cycle firing for scope=%s", scope_name)
    try:
        report = execute_live_run(
            window_hours=_SCHEDULED_WINDOW_HOURS, scope_name=scope_name, trigger_mode=TriggerMode.SCHEDULED
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


def build_scheduler(
    scope_name: str = "scheduled",
    cron_expression: str = "0 4 * * *",
    pre_flight_interval_minutes: int = 60,
) -> BackgroundScheduler:
    """Both jobs read Azure settings from /culprit/settings at fire time
    (see scheduled_cycle/pre_flight_check above) rather than taking a
    subscription id here - that's the whole point of the settings screen:
    change it without a redeploy. `cron_expression` defaults to a nightly
    4am run; point it at whatever actually matches this environment's
    maintenance window schedule."""
    scheduler = BackgroundScheduler(timezone=timezone.utc)
    scheduler.add_job(
        scheduled_cycle,
        trigger=CronTrigger.from_crontab(cron_expression),
        args=[scope_name],
        id=f"scheduled_cycle:{scope_name}",
        replace_existing=True,
    )
    scheduler.add_job(
        pre_flight_check,
        trigger="interval",
        minutes=pre_flight_interval_minutes,
        id="pre_flight_check",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    return scheduler
