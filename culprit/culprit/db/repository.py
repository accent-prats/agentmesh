"""Thin repository layer over the SQLAlchemy models - keeps the
orchestrator and API routes from hand-writing queries, and is the one
place that knows how domain models (Cluster, RCAResult, Verdict) map to
rows."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from culprit.db.models import (
    ClusterRecord,
    MachineOutcomeRecord,
    PreflightFindingRecord,
    RCAResultRecord,
    RunRecord,
    RunStage,
    SettingsRecord,
    VerdictRecord,
)
from culprit.models.cluster import Cluster
from culprit.models.evidence import EvidenceBundle
from culprit.models.patch_run import PatchRun, RunSummary
from culprit.models.rca import RCAResult
from culprit.models.taxonomy import CauseFamily
from culprit.models.verdict import Verdict, VerdictValue


def save_run(session: Session, run: PatchRun, stage: RunStage = RunStage.STARTED) -> RunRecord:
    record = session.get(RunRecord, run.run_id)
    if record is None:
        record = RunRecord(
            run_id=run.run_id,
            maintenance_configuration_id=run.maintenance_configuration_id,
            subscription_id=run.subscription_id,
            scope_name=run.scope_name,
            trigger_mode=run.trigger_mode.value,
            started_at=run.started_at,
            total_machines=run.total_machines,
            stage=stage.value,
        )
        session.add(record)
    else:
        record.stage = stage.value
    session.commit()
    return record


def update_run_stage(session: Session, run_id: str, stage: RunStage, **fields) -> None:
    record = session.get(RunRecord, run_id)
    if record is None:
        return
    record.stage = stage.value
    for k, v in fields.items():
        setattr(record, k, v)
    session.commit()


def save_cluster(session: Session, cluster: Cluster) -> ClusterRecord:
    record = session.get(ClusterRecord, cluster.cluster_id)
    if record is None:
        record = ClusterRecord(
            cluster_id=cluster.cluster_id,
            run_id=cluster.run_id,
            cluster_key=cluster.cluster_key,
            size=cluster.size,
            representative_vm_id=cluster.representative_vm_id,
            fingerprint_json=cluster.fingerprint.model_dump(mode="json"),
            members_json=[m.model_dump(mode="json") for m in cluster.members],
        )
        session.add(record)
        session.commit()
    return record


def save_rca_result(session: Session, result: RCAResult, consecutive_cycles: int = 1) -> RCAResultRecord:
    record = session.get(RCAResultRecord, result.cluster_id)
    payload = result.model_dump(mode="json")
    if record is None:
        record = RCAResultRecord(
            cluster_id=result.cluster_id,
            cause_family=result.cause_family.value,
            origin=result.origin.value,
            confidence=result.confidence,
            result_json=payload,
            consecutive_cycles=consecutive_cycles,
        )
        session.add(record)
    else:
        record.cause_family = result.cause_family.value
        record.origin = result.origin.value
        record.confidence = result.confidence
        record.result_json = payload
        record.consecutive_cycles = consecutive_cycles
    session.commit()
    return record


def save_machine_outcomes(session: Session, run_id: str, cluster_key: str, bundles: list[EvidenceBundle]) -> None:
    """Upserts one row per bundle, keyed on MachineOutcomeRecord's real
    composite primary key (run_id, vm_id) - the same get-or-create shape
    `save_cluster`/`save_rca_result` already use, and for the same
    reason: the demo scenario's fixed RUN_ID means `POST /runs/demo`
    re-diagnoses the same run_id on every call, and a blind insert here
    would leave duplicate rows per machine (a real bug this replaced -
    see MachineOutcomeRecord's docstring)."""
    for bundle in bundles:
        record = session.get(MachineOutcomeRecord, (run_id, bundle.machine.vm_id))
        if record is None:
            record = MachineOutcomeRecord(run_id=run_id, vm_id=bundle.machine.vm_id)
            session.add(record)
        record.vm_name = bundle.machine.vm_name
        record.cluster_key = cluster_key
        record.status = bundle.outcome.status
        record.error_code = bundle.outcome.error_code
        record.error_message = bundle.outcome.error_message
        record.packages_failed_json = bundle.outcome.packages_failed
        record.kbs_failed_json = bundle.outcome.kbs_failed
        record.reboot_status = bundle.outcome.reboot_status
        record.started_at = bundle.outcome.started_at
        record.ended_at = bundle.outcome.ended_at
        record.window_minutes = bundle.outcome.window_minutes
        record.collection_gaps_json = bundle.collection_gaps
    session.commit()


def historical_cluster_keys(session: Session, before_run_id: str, limit: int = 12) -> list[list[str]]:
    """Cluster keys seen in previous runs, most-recent-first - what
    advisor.compute_recurrence() needs to detect a repeat offender."""
    run = session.get(RunRecord, before_run_id)
    if run is None:
        return []
    stmt = (
        select(RunRecord)
        .where(RunRecord.started_at < run.started_at)
        .order_by(RunRecord.started_at.desc())
        .limit(limit)
    )
    prior_runs = session.execute(stmt).scalars().all()
    out = []
    for prior in prior_runs:
        keys_stmt = select(ClusterRecord.cluster_key).where(ClusterRecord.run_id == prior.run_id)
        out.append(list(session.execute(keys_stmt).scalars().all()))
    return out


def save_verdict(session: Session, verdict: Verdict) -> VerdictRecord:
    record = VerdictRecord(
        cluster_id=verdict.cluster_id,
        cause_family=verdict.cause_family.value,
        verdict=verdict.verdict.value,
        reviewer=verdict.reviewer,
        reviewed_at=verdict.reviewed_at,
        correction_note=verdict.correction_note,
    )
    session.add(record)
    session.commit()
    return record


def _load_fleet_report_core(session: Session, run_id: str):
    """The actual reconstruction, with no trend attached - split out from
    `load_fleet_report` purely so trend computation (which needs to load
    the *previous* run's report) doesn't recursively attach a trend to
    that previous report too."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import PatchOutcome
    from culprit.models.report import ClusterReportEntry, FleetReport, MachineRow
    from culprit.pipeline.advisor import compute_recurrence

    run_record = session.get(RunRecord, run_id)
    if run_record is None:
        return None

    run = PatchRun(
        run_id=run_record.run_id,
        maintenance_configuration_id=run_record.maintenance_configuration_id,
        subscription_id=run_record.subscription_id,
        scope_name=run_record.scope_name,
        started_at=run_record.started_at,
        ended_at=run_record.ended_at,
        total_machines=run_record.total_machines,
    )

    history = historical_cluster_keys(session, run_id)
    entries = []
    for cr in run_record.clusters:
        cluster = Cluster(
            cluster_id=cr.cluster_id,
            run_id=cr.run_id,
            cluster_key=cr.cluster_key,
            fingerprint=Fingerprint(**cr.fingerprint_json),
            members=[ClusterMember(**m) for m in cr.members_json],
            representative_vm_id=cr.representative_vm_id,
        )
        if cr.rca_result is None:
            continue
        result = RCAResult.model_validate(cr.rca_result.result_json)
        recurrence = compute_recurrence(cr.cluster_key, history)
        entries.append(
            ClusterReportEntry(
                cluster=cluster,
                result=result,
                recurrence_badge=recurrence.badge,
                consecutive_cycles=recurrence.consecutive_cycles,
            )
        )

    entries.sort(key=lambda e: -e.cluster.size)
    total_failed = sum(e.cluster.size for e in entries)
    from culprit.models.taxonomy import CauseFamily

    unresolved = sum(e.cluster.size for e in entries if e.result.cause_family == CauseFamily.UNRESOLVED)
    repeat_offenders = sum(1 for e in entries if e.recurrence_badge)

    # One query for the whole run, not one per machine - get_machine_detail
    # does this same MachineOutcomeRecord join per machine for the
    # single-machine page, which is fine there (one machine per request)
    # but would be an N+1 query here (one fleet report can cover hundreds
    # of machines).
    outcomes_by_vm_id = {
        rec.vm_id: rec
        for rec in session.execute(select(MachineOutcomeRecord).where(MachineOutcomeRecord.run_id == run_id)).scalars()
    }

    machine_rows = []
    for e in entries:
        has_immediate_fix = bool(e.result.remediation and e.result.remediation.immediate_fix)
        for m in e.cluster.members:
            rec = outcomes_by_vm_id.get(m.vm_id)
            outcome = (
                PatchOutcome(
                    status=rec.status,
                    error_code=rec.error_code,
                    error_message=rec.error_message,
                    packages_failed=rec.packages_failed_json,
                    kbs_failed=rec.kbs_failed_json,
                    reboot_status=rec.reboot_status,
                    started_at=rec.started_at,
                    ended_at=rec.ended_at,
                    window_minutes=rec.window_minutes,
                )
                if rec is not None
                else None
            )
            machine_rows.append(
                MachineRow(
                    vm_id=m.vm_id,
                    vm_name=m.vm_name,
                    cluster_id=e.cluster.cluster_id,
                    cause_family=e.result.cause_family,
                    title=e.result.title,
                    confidence=e.result.confidence,
                    is_actionable=e.result.is_actionable,
                    has_immediate_fix=has_immediate_fix,
                    outcome=outcome,
                )
            )

    return FleetReport(
        run=run,
        total_machines=run_record.total_machines,
        total_failed=total_failed,
        total_clusters=len(entries),
        entries=entries,
        machine_rows=machine_rows,
        unresolved_count=unresolved,
        repeat_offender_count=repeat_offenders,
    )


def _previous_completed_run(session: Session, run_record: RunRecord) -> RunRecord | None:
    stmt = (
        select(RunRecord)
        .where(
            RunRecord.scope_name == run_record.scope_name,
            RunRecord.started_at < run_record.started_at,
            RunRecord.stage == RunStage.COMPLETE.value,
        )
        .order_by(RunRecord.started_at.desc())
        .limit(1)
    )
    return session.execute(stmt).scalars().first()


def compute_trend(session: Session, run_id: str, current_report=None):
    """The prior-cycle comparison for the same scope_name (proposal
    Section 8: "trend against previous cycles"). None when there's no
    earlier *completed* run to compare against - an in-progress or failed
    prior run isn't a fair baseline, so it's skipped rather than compared
    against.

    `current_report`, if the caller already has one (as `load_fleet_report`
    always does), is reused instead of reconstructing the exact same
    run's clusters/RCAResults a second time just to read two scalars off
    it - found 2026-10-16 while removing a *different*, dashboard-only
    redundancy; this one benefits every caller, including the fleet
    report page, since the value is identical either way, just cheaper
    to get. The previous run still needs its own reconstruction -
    repeat_offender_count has no cheaper equivalent (it isn't a plain
    column anywhere)."""
    from culprit.models.report import FleetTrend

    run_record = session.get(RunRecord, run_id)
    if run_record is None:
        return None
    previous = _previous_completed_run(session, run_record)
    if previous is None:
        return None
    previous_report = _load_fleet_report_core(session, previous.run_id)
    if previous_report is None:
        return None

    if current_report is None:
        current_report = _load_fleet_report_core(session, run_id)
    if current_report is None:
        return None

    return FleetTrend(
        previous_run_id=previous.run_id,
        previous_total_failed=previous_report.total_failed,
        previous_compliance_pct=previous_report.compliance_pct,
        previous_repeat_offender_count=previous_report.repeat_offender_count,
        failed_delta=current_report.total_failed - previous_report.total_failed,
        compliance_delta_pct=round(current_report.compliance_pct - previous_report.compliance_pct, 1),
    )


def load_fleet_report(session: Session, run_id: str):
    """Reconstruct a FleetReport purely from persisted rows, with its
    cycle-over-cycle trend attached - what the API layer uses to serve a
    report after the process that ran the pipeline has exited, without
    needing the in-memory PipelineOutput."""
    report = _load_fleet_report_core(session, run_id)
    if report is None:
        return None
    trend = compute_trend(session, run_id, current_report=report)
    return report.model_copy(update={"trend": trend})


def latest_completed_run_id(session: Session) -> str | None:
    """The single most recent RunStage.COMPLETE run, across every
    scope_name - unlike `_previous_completed_run`, this needs no existing
    run to compare against (the Console dashboard's starting point: "what
    should it show with nothing else to go on"). None when nothing has
    ever completed yet."""
    stmt = (
        select(RunRecord.run_id)
        .where(RunRecord.stage == RunStage.COMPLETE.value)
        .order_by(RunRecord.started_at.desc())
        .limit(1)
    )
    return session.execute(stmt).scalars().first()


def compliance_trend(session: Session, scope_name: str, limit: int = 10):
    """The last `limit` completed runs for one scope_name, oldest first
    (left-to-right charting order) - the Console dashboard's trend line.

    Deliberately NOT built on `_load_fleet_report_core`/`compute_trend`
    (which reconstruct every Cluster and RCAResult just to read two
    scalars) - total_machines/failed_machines are plain columns already
    on RunRecord, so this is a single flat query with no cluster walk at
    all, cheap enough to run for N points instead of the 1 `compute_trend`
    needs."""
    from culprit.models.dashboard import ComplianceTrendPoint

    stmt = (
        select(RunRecord)
        .where(RunRecord.scope_name == scope_name, RunRecord.stage == RunStage.COMPLETE.value)
        .order_by(RunRecord.started_at.desc())
        .limit(limit)
    )
    records = session.execute(stmt).scalars().all()
    points = [
        ComplianceTrendPoint(
            run_id=r.run_id,
            started_at=r.started_at,
            failed_machines=r.failed_machines,
            compliance_pct=round(100.0 * (r.total_machines - r.failed_machines) / r.total_machines, 1)
            if r.total_machines
            else 100.0,
        )
        for r in records
    ]
    points.reverse()  # the query above is newest-first (for LIMIT to keep the *latest* N); charting wants oldest-first
    return points


def top_causes(session: Session, run_id: str, limit: int = len(CauseFamily)):
    """Which cause families account for the most failed machines in one
    run, ranked - the Console dashboard's "what's actually breaking
    things" list. A cheap aggregate over RCAResultRecord.cause_family
    (its own indexed column) and ClusterRecord.size - no
    RCAResult.model_validate, no title/remediation/evidence read at all,
    since only the label and a count are needed here.

    `limit` defaults to every possible CauseFamily value (11, as of this
    writing) - there is no pathological case to truncate against (a run
    can never have more distinct cause families than the enum has
    values), and silently cutting off the smallest one looked actively
    wrong next to the dashboard's own "N distinct causes" stat tile
    (found 2026-10-15 reviewing the dashboard with the demo scenario's
    6-cause run showing only 5 rows)."""
    from culprit.models.dashboard import CauseBreakdownEntry

    stmt = (
        select(RCAResultRecord.cause_family, func.sum(ClusterRecord.size))
        .join(ClusterRecord, ClusterRecord.cluster_id == RCAResultRecord.cluster_id)
        .where(ClusterRecord.run_id == run_id)
        .group_by(RCAResultRecord.cause_family)
        .order_by(func.sum(ClusterRecord.size).desc())
        .limit(limit)
    )
    return [CauseBreakdownEntry(cause_family=CauseFamily(family), machines=machines) for family, machines in session.execute(stmt).all()]


def build_dashboard_summary(session: Session):
    """Everything the Console page's dashboard needs, in one call - see
    models/dashboard.py::DashboardSummary for what each piece means and
    why "no completed runs yet" isn't an error.

    Uses `_load_fleet_report_core` directly, not `load_fleet_report` -
    deliberately skips `compute_trend` (which would reconstruct the
    *previous* run's clusters/RCAResults purely to compute
    previous_repeat_offender_count, a number this dashboard never shows -
    see DashboardSummary's own docstring). failed_delta/compliance_delta_pct
    are read off compliance_trend's own last two points instead, which
    were already fetched for the chart at effectively no extra cost."""
    from culprit.models.dashboard import DashboardSummary

    run_id = latest_completed_run_id(session)
    if run_id is None:
        return DashboardSummary()

    latest_run = _load_fleet_report_core(session, run_id)
    trend = compliance_trend(session, latest_run.run.scope_name)
    causes = top_causes(session, run_id)

    failed_delta = compliance_delta_pct = None
    if len(trend) >= 2:
        failed_delta = trend[-1].failed_machines - trend[-2].failed_machines
        compliance_delta_pct = round(trend[-1].compliance_pct - trend[-2].compliance_pct, 1)

    return DashboardSummary(
        latest_run=latest_run,
        compliance_trend=trend,
        top_causes=causes,
        failed_delta=failed_delta,
        compliance_delta_pct=compliance_delta_pct,
    )


def get_machine_detail(session: Session, run_id: str, vm_name: str):
    """One machine's own record within a run - its cluster, its deviation
    from that cluster's representative member (proposal Section 8: the
    third, "Machine" altitude, "for the awkward machine that didn't fit
    its cluster"), the RCAResult diagnosed for its cluster, and its own
    `PatchOutcome`/collection gaps if this run saved one (see
    MachineOutcomeRecord - runs diagnosed before that table existed won't
    have one; `outcome` is None in that case, not an error). Returns None
    if the run, or a member with this vm_name inside it, doesn't exist.

    Keyed by vm_name rather than vm_id (a full Azure resource ID, which
    contains slashes and can't be a clean URL path segment) - the same
    identifier culprit/api/routes_chat.py's ad-hoc "why did vm-x fail"
    queries already use to find a machine."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import PatchOutcome

    run_record = session.get(RunRecord, run_id)
    if run_record is None:
        return None

    for cr in run_record.clusters:
        member = next((m for m in cr.members_json if m.get("vm_name", "").lower() == vm_name.lower()), None)
        if member is None:
            continue
        cluster = Cluster(
            cluster_id=cr.cluster_id,
            run_id=cr.run_id,
            cluster_key=cr.cluster_key,
            fingerprint=Fingerprint(**cr.fingerprint_json),
            members=[ClusterMember(**m) for m in cr.members_json],
            representative_vm_id=cr.representative_vm_id,
        )
        result = RCAResult.model_validate(cr.rca_result.result_json) if cr.rca_result else None

        outcome_record = session.get(MachineOutcomeRecord, (run_id, member["vm_id"]))
        outcome, collection_gaps = None, []
        if outcome_record is not None:
            outcome = PatchOutcome(
                status=outcome_record.status,
                error_code=outcome_record.error_code,
                error_message=outcome_record.error_message,
                packages_failed=outcome_record.packages_failed_json,
                kbs_failed=outcome_record.kbs_failed_json,
                reboot_status=outcome_record.reboot_status,
                started_at=outcome_record.started_at,
                ended_at=outcome_record.ended_at,
                window_minutes=outcome_record.window_minutes,
            )
            collection_gaps = outcome_record.collection_gaps_json

        return cluster, ClusterMember(**member), result, outcome, collection_gaps

    return None


def list_runs(session: Session, limit: int = 50) -> list[RunSummary]:
    """Every run Culprit has diagnosed, most recent first - "which update
    jobs is Culprit monitoring" (the Runs list page). `total_clusters`
    counts however many distinct causes that run collapsed its failures
    into; `failed_machines` is the count `Pipeline.run()` recorded at
    RunStage.COMPLETE, not recomputed here."""
    records = session.execute(
        select(RunRecord).order_by(RunRecord.started_at.desc()).limit(limit)
    ).scalars().all()
    return [
        RunSummary(
            run_id=r.run_id,
            scope_name=r.scope_name,
            maintenance_configuration_id=r.maintenance_configuration_id,
            trigger_mode=r.trigger_mode,
            stage=r.stage,
            started_at=r.started_at,
            ended_at=r.ended_at,
            total_machines=r.total_machines,
            failed_machines=r.failed_machines,
            total_clusters=len(r.clusters),
        )
        for r in records
    ]


def get_rca_result(session: Session, cluster_id: str):
    """The (cluster_key, RCAResult) pair for a cluster_id, or None if it
    doesn't exist - used by the verdict route to turn a confirmed-correct
    verdict into a resolved-incident retrieval document (proposal Section
    7: "every RCA an engineer confirms becomes a retrieval target"),
    which needs the cluster_key (stable across runs), not the cluster_id
    (unique to the run it was diagnosed in)."""
    cluster_record = session.get(ClusterRecord, cluster_id)
    if cluster_record is None or cluster_record.rca_result is None:
        return None
    result = RCAResult.model_validate(cluster_record.rca_result.result_json)
    return cluster_record.cluster_key, result


def all_verdicts(session: Session) -> list[Verdict]:
    records = session.execute(select(VerdictRecord)).scalars().all()
    return [
        Verdict(
            cluster_id=r.cluster_id,
            cause_family=CauseFamily(r.cause_family),
            verdict=VerdictValue(r.verdict),
            reviewer=r.reviewer,
            reviewed_at=r.reviewed_at,
            correction_note=r.correction_note,
        )
        for r in records
    ]


# ── Pre-flight predictions ─────────────────────────────────────────────────────
# Only the most recent scan is ever meaningful (proposal Section 10: this
# runs continuously between cycles) - each save wholesale replaces the
# previous scan's rows rather than accumulating a history.

def save_preflight_findings(session: Session, findings: list) -> None:
    from datetime import datetime, timezone

    session.execute(delete(PreflightFindingRecord))
    scanned_at = findings[0].scanned_at if findings else datetime.now(timezone.utc)
    for f in findings:
        session.add(
            PreflightFindingRecord(
                vm_id=f.machine.vm_id,
                vm_name=f.machine.vm_name,
                subscription_id=f.machine.subscription_id,
                cause_family=f.result.cause_family.value,
                scanned_at=f.scanned_at or scanned_at,
                finding_json=f.model_dump(mode="json"),
            )
        )
    session.commit()


def latest_preflight_findings(session: Session) -> list:
    from culprit.models.preflight import PreflightFinding

    records = session.execute(select(PreflightFindingRecord).order_by(PreflightFindingRecord.vm_name)).scalars().all()
    return [PreflightFinding.model_validate(r.finding_json) for r in records]


# ── Provider settings (Azure / Datadog) ───────────────────────────────────────
# The repository layer is deliberately the only place that touches
# culprit.security.crypto - every caller (routes_settings.py, api/deps.py's
# live-collector wiring) works with plain-text values in memory only,
# never with the stored ciphertext directly.

def get_settings_row(session: Session, provider: str) -> SettingsRecord | None:
    return session.get(SettingsRecord, provider)


def save_azure_settings(session: Session, cfg) -> SettingsRecord:
    """`cfg` is a culprit.models.settings.AzureSettingsInput. A blank
    `client_secret` means 'leave whatever is already stored alone' - the
    settings form never re-sends a secret it didn't just receive from the
    user, so overwriting a real secret with an accidental blank would be a
    silent lockout. `clear_credentials` is the one deliberate exception -
    the settings screen's "Managed identity" radio sets it to actually
    forget a previously-saved secret on an explicit mode switch, rather
    than leaving it stored-but-unused forever."""
    from culprit.security.crypto import encrypt

    record = session.get(SettingsRecord, "azure")
    existing_secret_ciphertext = record.data_json.get("client_secret_ciphertext", "") if record else ""

    if cfg.client_secret:
        new_secret_ciphertext = encrypt(cfg.client_secret)
    elif cfg.clear_credentials:
        new_secret_ciphertext = ""
    else:
        new_secret_ciphertext = existing_secret_ciphertext

    data = {
        "subscription_ids": cfg.subscription_ids,
        "log_analytics_workspace_id": cfg.log_analytics_workspace_id,
        "tenant_id": cfg.tenant_id,
        "client_id": cfg.client_id,
        "client_secret_ciphertext": new_secret_ciphertext,
    }
    if record is None:
        record = SettingsRecord(provider="azure", data_json=data)
        session.add(record)
    else:
        record.data_json = data
    session.commit()
    return record


def save_datadog_settings(session: Session, cfg) -> SettingsRecord:
    """`cfg` is a culprit.models.settings.DatadogSettingsInput. Same
    leave-alone-if-blank rule as `save_azure_settings` for api_key/app_key,
    applied independently (you can rotate the API key without re-entering
    the app key, and vice versa) - but the api_key/app_key pair and
    personal_access_token are mutually exclusive auth shapes, not three
    independent secrets: `use_personal_access_token` says which one the
    settings screen's toggle actually has active, so switching shapes
    forgets the inactive one's secret(s) instead of leaving them as
    orphaned ciphertext, while a blank field that belongs to the *active*
    shape still keeps the normal preserve-on-blank behavior (found
    2026-10-11 while adding PAT support - the same class of bug as
    Azure's clear_credentials, but bidirectional since there are two
    secretable shapes here instead of one)."""
    from culprit.security.crypto import encrypt

    record = session.get(SettingsRecord, "datadog")
    existing = record.data_json if record else {}

    if cfg.personal_access_token:
        pat_ciphertext = encrypt(cfg.personal_access_token)
    elif cfg.use_personal_access_token:
        pat_ciphertext = existing.get("personal_access_token_ciphertext", "")
    else:
        pat_ciphertext = ""

    if cfg.api_key:
        api_key_ciphertext = encrypt(cfg.api_key)
    elif not cfg.use_personal_access_token:
        api_key_ciphertext = existing.get("api_key_ciphertext", "")
    else:
        api_key_ciphertext = ""

    if cfg.app_key:
        app_key_ciphertext = encrypt(cfg.app_key)
    elif not cfg.use_personal_access_token:
        app_key_ciphertext = existing.get("app_key_ciphertext", "")
    else:
        app_key_ciphertext = ""

    data = {
        "site": cfg.site or "datadoghq.com",
        "api_key_ciphertext": api_key_ciphertext,
        "app_key_ciphertext": app_key_ciphertext,
        "personal_access_token_ciphertext": pat_ciphertext,
    }
    if record is None:
        record = SettingsRecord(provider="datadog", data_json=data)
        session.add(record)
    else:
        record.data_json = data
    session.commit()
    return record


def record_settings_test_result(session: Session, provider: str, ok: bool, message: str) -> None:
    """Upserts - a 'Test connection' can legitimately be run against values
    that were never saved (the settings screen tests before saving), so
    there may be no row yet. Recording nothing in that case would make the
    test button silently do nothing from the user's point of view."""
    record = session.get(SettingsRecord, provider)
    if record is None:
        record = SettingsRecord(provider=provider, data_json={})
        session.add(record)
    record.last_tested_at = datetime.now(timezone.utc)
    record.last_test_ok = ok
    record.last_test_message = message
    session.commit()


def load_azure_settings(session: Session):
    """Returns a fully decrypted `AzureSettingsInput` (secret in plain
    text, in memory only) for handing to a real Azure SDK call - used by
    the settings screen's 'Test connection' button and by
    api/deps.py::build_live_collectors, never persisted or logged.

    Falls back to the `CULPRIT_SUBSCRIPTION_IDS`/`CULPRIT_LOG_ANALYTICS_WORKSPACE_ID`
    env vars (culprit/config.py) only when nothing has ever been saved on
    the settings screen - once a row exists, the DB is authoritative and
    env vars are not consulted, so saving a blank subscription list on
    purpose behaves as "unconfigured", not "fall back silently"."""
    from culprit.config import settings as env_settings
    from culprit.models.settings import AzureSettingsInput
    from culprit.security.crypto import decrypt

    record = session.get(SettingsRecord, "azure")
    if record is None:
        return AzureSettingsInput(
            subscription_ids=list(env_settings.subscription_ids),
            log_analytics_workspace_id=env_settings.log_analytics_workspace_id,
        )
    d = record.data_json
    return AzureSettingsInput(
        subscription_ids=d.get("subscription_ids", []),
        log_analytics_workspace_id=d.get("log_analytics_workspace_id", ""),
        tenant_id=d.get("tenant_id", ""),
        client_id=d.get("client_id", ""),
        client_secret=decrypt(d.get("client_secret_ciphertext", "")),
    )


def load_datadog_settings(session: Session):
    from culprit.models.settings import DatadogSettingsInput
    from culprit.security.crypto import decrypt

    record = session.get(SettingsRecord, "datadog")
    if record is None:
        return DatadogSettingsInput()
    d = record.data_json
    return DatadogSettingsInput(
        site=d.get("site", "datadoghq.com"),
        api_key=decrypt(d.get("api_key_ciphertext", "")),
        app_key=decrypt(d.get("app_key_ciphertext", "")),
        personal_access_token=decrypt(d.get("personal_access_token_ciphertext", "")),
    )


def azure_settings_view(session: Session):
    from culprit.models.settings import AzureSettingsView

    record = session.get(SettingsRecord, "azure")
    if record is None:
        return AzureSettingsView()
    d = record.data_json
    return AzureSettingsView(
        subscription_ids=d.get("subscription_ids", []),
        log_analytics_workspace_id=d.get("log_analytics_workspace_id", ""),
        tenant_id=d.get("tenant_id", ""),
        client_id=d.get("client_id", ""),
        client_secret_configured=bool(d.get("client_secret_ciphertext")),
        # Subscription ids are the only thing every auth mode needs - a
        # service principal's secret is not, since blank tenant/client/secret
        # is a deliberate, complete configuration (managed identity; see
        # azure_auth.py::build_credential). Gating this on a saved secret
        # (found 2026-10-10) meant the settings screen showed "Not configured
        # yet." forever for a fully-working managed-identity setup.
        configured=bool(d.get("subscription_ids")),
        last_tested_at=record.last_tested_at,
        last_test_ok=record.last_test_ok,
        last_test_message=record.last_test_message,
    )


def load_schedule_settings(session: Session):
    """Returns the saved scheduled-run config, or - if nothing's ever been
    saved on /culprit/settings - the CULPRIT_SCHEDULER_ENABLED/
    CULPRIT_SCHEDULED_CRON env var defaults (culprit/config.py), same
    "DB is authoritative once a row exists, env vars only seed the very
    first read" convention as load_azure_settings. Read by main.py's
    lifespan handler to build the initial in-process scheduler, and by
    schedule_settings_view for the Settings screen."""
    from culprit.config import settings as env_settings
    from culprit.models.settings import ScheduleSettingsInput

    record = session.get(SettingsRecord, "schedule")
    if record is None:
        return ScheduleSettingsInput(enabled=env_settings.scheduler_enabled, cron_expression=env_settings.scheduled_cron)
    d = record.data_json
    return ScheduleSettingsInput(
        enabled=d.get("enabled", False),
        cron_expression=d.get("cron_expression", "0 4 * * *"),
        window_hours=d.get("window_hours", 192),
        scope_name=d.get("scope_name", "scheduled"),
    )


def save_schedule_settings(session: Session, cfg) -> SettingsRecord:
    """`cfg` is a culprit.models.settings.ScheduleSettingsInput. No secrets
    here (unlike Azure/Datadog), so this is a plain overwrite - nothing to
    preserve-on-blank."""
    data = {
        "enabled": cfg.enabled,
        "cron_expression": cfg.cron_expression,
        "window_hours": cfg.window_hours,
        "scope_name": cfg.scope_name,
    }
    record = session.get(SettingsRecord, "schedule")
    if record is None:
        record = SettingsRecord(provider="schedule", data_json=data)
        session.add(record)
    else:
        record.data_json = data
    session.commit()
    return record


def schedule_settings_view(session: Session, scheduler=None):
    """`scheduler` is the live in-process APScheduler instance
    (app.state.scheduler - None whenever CULPRIT_SCHEDULER_ENABLED is off
    on this process). Its own next_run_time is the only honest source for
    "when does this actually fire next" - a saved cron expression alone
    doesn't say whether anything is actually listening to it right now."""
    from culprit.models.settings import ScheduleSettingsView

    cfg = load_schedule_settings(session)
    next_run_at = None
    if scheduler is not None:
        # Deferred: culprit.scheduler.cron imports apscheduler at module
        # level, so this must stay inside the "a live scheduler already
        # exists" branch - a non-None scheduler means apscheduler was
        # already successfully imported once, in main.py's lifespan, so
        # this is safe precisely when it's reached.
        from culprit.scheduler.cron import SCHEDULED_JOB_ID

        job = scheduler.get_job(SCHEDULED_JOB_ID)
        if job is not None:
            next_run_at = job.next_run_time
    return ScheduleSettingsView(
        enabled=cfg.enabled,
        cron_expression=cfg.cron_expression,
        window_hours=cfg.window_hours,
        scope_name=cfg.scope_name,
        scheduler_running=scheduler is not None,
        next_run_at=next_run_at,
    )


def datadog_settings_view(session: Session):
    from culprit.models.settings import DatadogSettingsView

    record = session.get(SettingsRecord, "datadog")
    if record is None:
        return DatadogSettingsView()
    d = record.data_json
    return DatadogSettingsView(
        site=d.get("site", "datadoghq.com"),
        api_key_configured=bool(d.get("api_key_ciphertext")),
        app_key_configured=bool(d.get("app_key_ciphertext")),
        personal_access_token_configured=bool(d.get("personal_access_token_ciphertext")),
        # A PAT alone is a complete, working configuration - same reasoning
        # as Azure's configured fix (2026-10-10), this must not require the
        # *other* credential shape's secret to also be present.
        configured=bool(d.get("api_key_ciphertext") or d.get("personal_access_token_ciphertext")),
        last_tested_at=record.last_tested_at,
        last_test_ok=record.last_test_ok,
        last_test_message=record.last_test_message,
    )
