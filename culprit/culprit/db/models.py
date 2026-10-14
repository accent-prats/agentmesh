"""SQLAlchemy persistence models.

SQLite by default (zero-config for the demo and the test suite) - point
`CULPRIT_DATABASE_URL` at Postgres for production; nothing above this
module cares which one is in use. This is where the state that makes the
pipeline "durable" lives (proposal Section 4: the pipeline must survive a
restart mid-cycle) and where the cross-run history the recurrence and
precision-gate logic depend on is read from.
"""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class RunStage(str, enum.Enum):
    """Checkpoint stage for durable resume - if the process dies mid-cycle,
    the orchestrator resumes from the last completed stage instead of
    re-running collection (expensive, and re-hits guest VMs) from scratch."""

    STARTED = "started"
    COLLECTED = "collected"
    CLUSTERED = "clustered"
    DIAGNOSED = "diagnosed"
    REPORTED = "reported"
    COMPLETE = "complete"
    FAILED = "failed"


class RunRecord(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String, primary_key=True)
    maintenance_configuration_id: Mapped[str] = mapped_column(String)
    subscription_id: Mapped[str] = mapped_column(String)
    scope_name: Mapped[str] = mapped_column(String)
    trigger_mode: Mapped[str] = mapped_column(String)
    started_at: Mapped[datetime] = mapped_column(DateTime)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_machines: Mapped[int] = mapped_column(Integer)
    failed_machines: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String, default=RunStage.STARTED.value)
    checkpoint: Mapped[dict] = mapped_column(JSON, default=dict)

    clusters: Mapped[list["ClusterRecord"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    machine_outcomes: Mapped[list["MachineOutcomeRecord"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class ClusterRecord(Base):
    __tablename__ = "clusters"

    cluster_id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"))
    cluster_key: Mapped[str] = mapped_column(String, index=True)
    size: Mapped[int] = mapped_column(Integer)
    representative_vm_id: Mapped[str] = mapped_column(String)
    fingerprint_json: Mapped[dict] = mapped_column(JSON)
    members_json: Mapped[list] = mapped_column(JSON)

    run: Mapped[RunRecord] = relationship(back_populates="clusters")
    rca_result: Mapped["RCAResultRecord | None"] = relationship(back_populates="cluster", uselist=False, cascade="all, delete-orphan")
    verdicts: Mapped[list["VerdictRecord"]] = relationship(back_populates="cluster", cascade="all, delete-orphan")


class RCAResultRecord(Base):
    __tablename__ = "rca_results"

    cluster_id: Mapped[str] = mapped_column(ForeignKey("clusters.cluster_id"), primary_key=True)
    cause_family: Mapped[str] = mapped_column(String, index=True)
    origin: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column()
    result_json: Mapped[dict] = mapped_column(JSON)
    consecutive_cycles: Mapped[int] = mapped_column(Integer, default=1)

    cluster: Mapped[ClusterRecord] = relationship(back_populates="rca_result")


class MachineOutcomeRecord(Base):
    """One machine's `PatchOutcome` (proposal Section 8's "which update
    failed, and how" - status, error code/message, the specific failed
    KB(s)/package(s)) plus its collection gaps, persisted per run so the
    per-machine page can show it after the run that produced it has
    exited. Added later than the rest of this schema - the EvidenceBundle
    it's drawn from was previously discarded once `Pipeline.run()`
    returned, and the deviation-only `ClusterMember` never carried these
    fields (see `culprit/models/cluster.py`). Rows for runs diagnosed
    before this table existed simply have none - the machine page falls
    back to its old text-only view for those.

    One row per (run_id, vm_id) - a composite primary key, not an
    autoincrement one, because that pair genuinely is the natural key:
    `repository.save_machine_outcomes` upserts on it (get-or-create, same
    pattern as `save_cluster`/`save_rca_result`), so re-diagnosing the
    same run_id (the demo scenario's fixed RUN_ID does exactly this on
    every `POST /runs/demo`) replaces the row instead of duplicating it.
    Found in review: an earlier version used a separate autoincrement id
    and blindly inserted every call, so a second demo run left two rows
    per machine and crashed `get_machine_detail` with
    `MultipleResultsFound` - a 500 on every machine page after that."""

    __tablename__ = "machine_outcomes"

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), primary_key=True)
    vm_id: Mapped[str] = mapped_column(String, primary_key=True)
    vm_name: Mapped[str] = mapped_column(String, index=True)
    cluster_key: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String)
    error_code: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    packages_failed_json: Mapped[list] = mapped_column(JSON, default=list)
    kbs_failed_json: Mapped[list] = mapped_column(JSON, default=list)
    reboot_status: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    window_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    collection_gaps_json: Mapped[list] = mapped_column(JSON, default=list)

    run: Mapped[RunRecord] = relationship(back_populates="machine_outcomes")


class VerdictRecord(Base):
    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cluster_id: Mapped[str] = mapped_column(ForeignKey("clusters.cluster_id"))
    cause_family: Mapped[str] = mapped_column(String, index=True)
    verdict: Mapped[str] = mapped_column(String)
    reviewer: Mapped[str] = mapped_column(String)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime)
    correction_note: Mapped[str] = mapped_column(Text, default="")

    cluster: Mapped[ClusterRecord] = relationship(back_populates="verdicts")


class PreflightFindingRecord(Base):
    """One machine's current-state rule hit from the most recent
    pre-flight scan (proposal Section 10). Rows are wholesale replaced on
    every scan (see repository.save_preflight_findings) - only the latest
    prediction is ever meaningful, unlike a completed run's history."""

    __tablename__ = "preflight_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vm_id: Mapped[str] = mapped_column(String, index=True)
    vm_name: Mapped[str] = mapped_column(String, index=True)
    subscription_id: Mapped[str] = mapped_column(String)
    cause_family: Mapped[str] = mapped_column(String)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    finding_json: Mapped[dict] = mapped_column(JSON)


class RemediationActionRecord(Base):
    """One row per machine targeted by a Phase 2 remediation attempt
    (culprit/remediation/, api/routes_remediation.py) - an append-only
    audit log, not an upsert-by-natural-key table like MachineOutcomeRecord,
    since the same VM can legitimately be remediated more than once over
    time and each attempt is its own distinct event worth keeping.
    `status`/`cause_family`/`action_type` are plain indexed String columns
    holding each enum's `.value` (this file's house style - see
    VerdictRecord.cause_family/.verdict) rather than a native SQL Enum
    type, since nothing here needs that extra constraint and every other
    enum-shaped column in this file is stored the same way."""

    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), index=True)
    cluster_id: Mapped[str] = mapped_column(ForeignKey("clusters.cluster_id"), index=True)
    vm_id: Mapped[str] = mapped_column(String, index=True)
    vm_name: Mapped[str] = mapped_column(String)
    cause_family: Mapped[str] = mapped_column(String, index=True)
    action_type: Mapped[str] = mapped_column(String)
    requested_by: Mapped[str] = mapped_column(String)
    requested_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    status: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text, default="")


class PromotionGateChangeRecord(Base):
    """Every change ever made to the precision gate's threshold/min_sample
    (culprit/api/routes_settings.py's GET/PUT /settings/gate) - an
    append-only audit log, same reasoning as RemediationActionRecord: this
    setting decides when automated remediation is allowed to run at all,
    so who changed it and when has to stay visible, not just the current
    value. The current effective value is simply the latest row (highest
    id) - no separate "current settings" row to keep in sync with this
    history, see repository.py::get_current_promotion_gate. No rows yet
    means nothing has ever been overridden - callers fall back to
    config.settings' env-var defaults in that case."""

    __tablename__ = "promotion_gate_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    changed_by: Mapped[str] = mapped_column(String)
    threshold: Mapped[float] = mapped_column(Float)
    min_sample: Mapped[int] = mapped_column(Integer)


class EmailLogRecord(Base):
    """One row per report-email send attempt (api/routes_notifications.py)
    - an append-only audit log, same reasoning as RemediationActionRecord:
    the same run can legitimately be re-sent (a new stakeholder, a retry
    after a bounce), so each attempt is its own distinct event worth
    keeping, not an upsert-by-run-id table. `recipients_json` is a JSON
    list rather than a joined string so the exact recipient set of each
    historical send stays queryable/displayable without re-parsing."""

    __tablename__ = "email_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), index=True)
    recipients_json: Mapped[list] = mapped_column(JSON)
    requested_by: Mapped[str] = mapped_column(String)
    sent_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    status: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text, default="")


class SettingsRecord(Base):
    """One row per provider ("azure" | "datadog"). `data_json` holds
    plain-text fields as-is and secret fields (client_secret, api_key,
    app_key) as Fernet ciphertext produced by culprit/security/crypto.py -
    the repository layer is what encrypts on the way in and decrypts on
    the way out, so nothing else in the codebase ever sees a raw secret
    that didn't come straight from the settings form."""

    __tablename__ = "settings"

    provider: Mapped[str] = mapped_column(String, primary_key=True)
    data_json: Mapped[dict] = mapped_column(JSON, default=dict)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[str] = mapped_column(Text, default="")
