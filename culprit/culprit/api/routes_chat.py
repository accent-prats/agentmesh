"""Ad-hoc query mode (proposal Section 10): "Why did vm-x fail?" and
"What's failing across the fleet?" without waiting for the next scheduled
cycle.

This does lightweight, regex-based scoping (extract a VM name, or fall
back to "show me the fleet") rather than full NL intent parsing - it is
the same underlying data every other route reads, just entered as a
question. A production deployment can swap `_extract_vm_name` for a
Claude-based interpreter (the same `claude-opus-5` client already used in
rca_agent.py) without changing anything below it; the regex path is kept
as the dependency-free default so this route works even without model
credentials configured.
"""
from __future__ import annotations

import re

from fastapi import APIRouter
from pydantic import BaseModel

from culprit.api import deps

router = APIRouter(tags=["chat"])

_VM_NAME_RE = re.compile(r"\b(vm-[a-z0-9-]+)\b", re.IGNORECASE)
_PREDICTION_RE = re.compile(r"\b(will|going to|next|before|predict)\b.*\b(fail|break)\b|\bfail\b.*\bnext\b", re.IGNORECASE)


class ChatQuery(BaseModel):
    question: str
    run_id: str | None = None


class ChatAnswer(BaseModel):
    answer: str
    matched_cluster_id: str | None = None
    confidence: float | None = None


@router.post("/chat", response_model=ChatAnswer)
def ask(query: ChatQuery) -> ChatAnswer:
    from culprit.db import repository

    # "Which machines will fail next Tuesday?" - the pre-flight prediction
    # mode (proposal Section 10), answered from *current* preconditions
    # (culprit/scheduler/cron.py::pre_flight_check), not from completed-run
    # history - checked first since a forward-looking question has nothing
    # to do with any past FleetReport.
    if _PREDICTION_RE.search(query.question):
        with deps.get_session_factory()() as session:
            findings = repository.latest_preflight_findings(session)
        return _preflight_answer(findings)

    with deps.get_session_factory()() as session:
        report = repository.load_fleet_report(session, query.run_id) if query.run_id else _latest_report(session)

    if report is None:
        return ChatAnswer(answer="No completed runs found yet.")

    vm_match = _VM_NAME_RE.search(query.question)
    if vm_match:
        vm_name = vm_match.group(1)
        for entry in report.entries:
            if any(m.vm_name.lower() == vm_name.lower() for m in entry.cluster.members):
                return ChatAnswer(
                    answer=(
                        f"{vm_name} is in a {entry.cluster.size}-machine cluster: {entry.result.title}. "
                        f"Confidence {entry.result.confidence:.0%}."
                        + (f" This is a repeat: {entry.recurrence_badge}." if entry.recurrence_badge else "")
                    ),
                    matched_cluster_id=entry.cluster.cluster_id,
                    confidence=entry.result.confidence,
                )
        return ChatAnswer(answer=f"{vm_name} was not found among the failed machines in this run.")

    # Fleet-level summary fallback.
    lines = [f"{report.total_failed}/{report.total_machines} machines failed, across {report.total_clusters} distinct causes:"]
    for entry in report.entries[:6]:
        lines.append(f"- {entry.cluster.size} machines: {entry.result.title} ({entry.result.confidence:.0%} confidence)")
    return ChatAnswer(answer="\n".join(lines))


def _preflight_answer(findings: list) -> ChatAnswer:
    if not findings:
        return ChatAnswer(
            answer="No pre-flight warnings right now - nothing currently shows a precondition the rule "
            "engine recognizes as likely to fail the next window. (This reflects the most recent "
            "pre-flight scan, not a guarantee - it only catches the preconditions the rule engine knows "
            "about.)"
        )
    lines = [f"{len(findings)} machine(s) show a precondition likely to fail the next patch window:"]
    for f in findings[:10]:
        lines.append(f"- {f.machine.vm_name}: {f.result.title} ({f.result.cause_family.value})")
    if len(findings) > 10:
        lines.append(f"... and {len(findings) - 10} more.")
    return ChatAnswer(answer="\n".join(lines))


def _latest_report(session):
    from sqlalchemy import select

    from culprit.db import repository
    from culprit.db.models import RunRecord

    latest = session.execute(select(RunRecord).order_by(RunRecord.started_at.desc()).limit(1)).scalar_one_or_none()
    if latest is None:
        return None
    return repository.load_fleet_report(session, latest.run_id)
