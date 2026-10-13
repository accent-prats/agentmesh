"""End-to-end demo entry point - the script behind the event demo arc
(proposal Section 16).

    python -m culprit.demo.run_demo

Runs the full pipeline (cluster -> rules -> deep RCA -> advisor -> report)
against the synthetic 312/47/6-cluster scenario and writes the fleet
report as HTML next to this file. If ANTHROPIC_API_KEY (or another
credential `ant auth status` recognizes) is available, the two clusters
the rule engine can't settle go to the real claude-opus-5 agent; otherwise
it falls back to the scripted stand-in and says so loudly - never
silently pretends a scripted answer is a model's.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("culprit.demo")


def _make_rca_agent():
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        from culprit.pipeline.rca_agent import DeepRCAAgent

        log.info("ANTHROPIC credentials found - deep RCA will call claude-opus-5 for real.")
        return DeepRCAAgent()

    log.warning(
        "No ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN set - using the SCRIPTED demo RCA agent "
        "(culprit/demo/scripted_rca.py) instead of a real Claude call. This is fine for a "
        "rehearsal but is NOT a demonstration of the model's reasoning."
    )
    from culprit.demo.scripted_rca import ScriptedRCAAgent

    return ScriptedRCAAgent()


def main() -> int:
    from culprit.db.engine import make_session_factory
    from culprit.demo.generate_scenario import TOTAL_MACHINES, build_scenario
    from culprit.pipeline.orchestrator import Pipeline
    from culprit.reporting.fleet_report import build_fleet_report
    from culprit.reporting.render import render_fleet_report_html
    from culprit.retrieval.corpus import default_retrieval_store

    run, bundles = build_scenario()
    log.info("Scenario: %d total machines, %d failed", TOTAL_MACHINES, len(bundles))

    session_factory = make_session_factory()
    rca_agent = _make_rca_agent()
    retrieval_store = default_retrieval_store()

    pipeline = Pipeline(session_factory=session_factory, rca_agent=rca_agent, retrieval_store=retrieval_store)
    output = pipeline.run(run, bundles)

    report = build_fleet_report(output, total_machines=TOTAL_MACHINES, bundles=bundles)

    log.info("=" * 70)
    log.info("%d failed machines collapsed into %d clusters", report.total_failed, report.total_clusters)
    for entry in report.entries:
        badge = f" [{entry.recurrence_badge}]" if entry.recurrence_badge else ""
        log.info(
            "  %2d machines | conf %.0f%% | %-16s | %s%s",
            entry.cluster.size,
            entry.result.confidence * 100,
            entry.result.cause_family.value,
            entry.result.title,
            badge,
        )
    log.info("=" * 70)

    html = render_fleet_report_html(report)
    out_path = Path(__file__).parent / "fleet_report.html"
    out_path.write_text(html, encoding="utf-8")
    log.info("Fleet report written to %s", out_path)

    webhook = os.environ.get("CULPRIT_TEAMS_WEBHOOK_URL") or os.environ.get("CULPRIT_SLACK_WEBHOOK_URL")
    if webhook:
        from culprit.reporting.notify import post_to_slack, post_to_teams

        poster = post_to_teams if os.environ.get("CULPRIT_TEAMS_WEBHOOK_URL") else post_to_slack
        response = poster(webhook, report)
        log.info("Posted digest to webhook - status %s", response.status_code)

    return 0


if __name__ == "__main__":
    sys.exit(main())
