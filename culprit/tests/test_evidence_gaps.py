"""parse_evidence_gaps (culprit/reporting/evidence_gaps.py) - the display-
time transform that turns a cluster's/machine's raw collection_gaps /
missing_evidence strings ("{source}: {message}", per pipeline/normalize.py's
merge_bundle()) into structured cards for fleet_report.html.j2 and
machine.html.j2. Found live: the raw strings include full, often very long,
vendor API exception dumps - this is what makes the "Missing evidence"
section readable instead of a wall of text."""
from __future__ import annotations

from datetime import datetime, timezone

from culprit.models.rca import format_unverifiable_reason
from culprit.reporting.evidence_gaps import parse_evidence_gaps
from culprit.reporting.render import render_fleet_report_html

_LONG_AZURE_ERROR = (
    "Resource Graph query failed: (BadRequest) Please provide below info when asking for "
    "support: timestamp = 2026-10-10T18:06:38.0172192Z, correlationId = "
    "4705c7ea-a7f8-4fdc-ba42-4e28c494172d. Code: BadRequest Message: Please provide below "
    "info when asking for support: timestamp = 2026-10-10T18:06:38.0172192Z, correlationId = "
    "4705c7ea-a7f8-4fdc-ba42-4e28c494172d Exception Details: (InvalidQuery) Query is invalid. "
    "Please refer to the documentation for the Azure Resource Graph service."
)


def test_a_source_prefixed_short_message_gets_a_friendly_label_and_no_detail_toggle():
    gaps = parse_evidence_gaps(["azure_control_plane: no patch outcome available"])
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.label == "Azure Resource Graph"
    assert gap.icon == "cloud"
    assert gap.summary == "no patch outcome available"
    assert gap.detail is None  # short enough - nothing extra for a toggle to reveal
    assert gap.correlation_id is None


def test_every_known_source_prefix_maps_to_a_distinct_friendly_label():
    items = [
        "azure_control_plane: x", "azure_monitor: x", "guest_windows: x", "guest_linux: x",
        "datadog_metric: x", "datadog_monitor: x", "datadog_log: x", "datadog_event: x",
    ]
    gaps = parse_evidence_gaps(items)
    labels = [g.label for g in gaps]
    assert labels == [
        "Azure Resource Graph", "Azure Monitor", "Windows guest agent", "Linux guest agent",
        "Datadog metrics", "Datadog monitor", "Datadog logs", "Datadog events",
    ]
    assert len(set(labels)) == len(labels)  # every source reads as visibly distinct


def test_a_message_with_no_recognized_source_prefix_falls_back_to_a_generic_label():
    gaps = parse_evidence_gaps(["Deep RCA agent not configured for this pipeline run"])
    assert gaps[0].label == "Evidence gap"
    assert gaps[0].icon == "alert-triangle"
    assert gaps[0].summary == "Deep RCA agent not configured for this pipeline run"


def test_a_long_message_is_truncated_for_the_summary_with_the_full_text_kept_as_detail():
    gaps = parse_evidence_gaps([f"azure_control_plane: {_LONG_AZURE_ERROR}"])
    gap = gaps[0]
    assert len(gap.summary) <= 141  # _SUMMARY_MAX_CHARS + the ellipsis character
    assert gap.summary.endswith("…")
    assert gap.detail == _LONG_AZURE_ERROR
    assert gap.detail.startswith(gap.summary.rstrip("…"))


def test_a_correlation_id_is_extracted_and_trailing_punctuation_is_stripped():
    gaps = parse_evidence_gaps([f"azure_control_plane: {_LONG_AZURE_ERROR}"])
    assert gaps[0].correlation_id == "4705c7ea-a7f8-4fdc-ba42-4e28c494172d"


# ── A pipeline-rejected model output (found 2026-10-18 from a real user
# complaint: a hallucinated evidence_ref like "vendor_doc" was shown
# verbatim under a "what the RCA agent said it would need for more
# confidence" heading - both wrong, since nothing was missing, and
# meaningless to a non-technical reader) must render as something
# genuinely different from a real "we couldn't collect this source" gap ──

def test_an_unverifiable_reason_gets_its_own_label_and_keeps_the_summary_clean():
    reason = format_unverifiable_reason(
        "The analysis assistant proposed an explanation but cited evidence that doesn't exist.",
        "Fabricated evidence_refs: ['vendor_doc']",
    )
    gaps = parse_evidence_gaps([reason])
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.label == "Unverified analysis"
    assert gap.icon == "shield-alert"
    assert gap.summary == "The analysis assistant proposed an explanation but cited evidence that doesn't exist."
    assert "vendor_doc" not in gap.summary  # the confusing internal token never reaches the headline text


def test_an_unverifiable_reasons_raw_detail_is_kept_behind_the_toggle_even_when_short():
    """Unlike the generic _summarize() path (which only creates a `detail`
    once the message exceeds 140 chars), an unverifiable reason's raw
    technical detail is always tucked away, even when short - it's never
    meant to be read as the primary text."""
    reason = format_unverifiable_reason("Clean summary.", "short raw detail")
    gap = parse_evidence_gaps([reason])[0]
    assert gap.summary == "Clean summary."
    assert gap.detail == "short raw detail"


def test_an_unverifiable_reason_has_no_correlation_id():
    reason = format_unverifiable_reason("Clean summary.", "correlationId=abc-123")
    gap = parse_evidence_gaps([reason])[0]
    assert gap.correlation_id is None  # the raw detail isn't scanned - it's not meant to be a support-ticket id here


def test_a_message_with_no_correlation_id_leaves_it_none():
    gaps = parse_evidence_gaps(["datadog_metric: (401) Reason: Unauthorized"])
    assert gaps[0].correlation_id is None


def test_newlines_and_repeated_whitespace_in_the_message_are_flattened():
    gaps = parse_evidence_gaps(["guest_linux: line one\n   line two\t\tline three"])
    assert gaps[0].summary == "line one line two line three"


def test_a_short_lead_word_before_one_long_unbroken_token_falls_back_to_a_hard_cut():
    """Review caught this: a plain word-boundary cut on "a " + "b"*200 would
    rsplit back to just "a" (the only space is two characters in), showing a
    near-empty summary instead of using the available budget - realistic for
    a vendor error that's mostly a URL, hash, or base64 blob after a short
    lead word."""
    message = "error " + ("x" * 200)
    gaps = parse_evidence_gaps([f"datadog_log: {message}"])
    gap = gaps[0]
    assert len(gap.summary) > 100  # not the near-empty "error…" a bare word-boundary cut would give
    assert gap.detail == message


def test_a_correlation_id_eight_chars_or_shorter_gets_no_ellipsis_in_the_copy_chip():
    """The template only appends an ellipsis when something was actually
    truncated - a real Azure correlationId is a 36-char GUID so this is
    mostly theoretical, but an 8-char-or-shorter id showing "1234567…" would
    be a display lie (nothing after those 8 characters was cut)."""
    from culprit.models.evidence import PatchOutcome
    from culprit.reporting.render import render_machine_html

    class _FakeMember:
        vm_id, vm_name, deviation_notes = "vm-1-id", "vm-1", []

    class _FakeCluster:
        run_id, representative_vm_id = "run-1", "vm-1-id"

    # evidence_gaps/collection_gaps are only ever rendered alongside a real
    # outcome (db/repository.py::get_machine_detail reads collection_gaps
    # off the same MachineOutcomeRecord outcome itself comes from - an old
    # run with no outcome row has no collection_gaps either), so a
    # realistic fixture needs both, not collection_gaps alone.
    html = render_machine_html(
        cluster=_FakeCluster(), member=_FakeMember(), result=None,
        outcome=PatchOutcome(status="Failed"),
        collection_gaps=["azure_control_plane: query failed, correlationId = abc123."],
    )
    assert "abc123</span>" in html  # no "abc123…" - nothing was truncated
    assert "abc123…" not in html


def test_fleet_report_renders_structured_evidence_gap_cards_for_an_unresolved_cluster():
    """Full render path, not just the parser - a hand-built FleetReport
    with one unresolved cluster carrying a long, correlationId-bearing
    error (realistic shape of a live Resource Graph failure) and one
    short one. Asserts the raw "source: message" string never reaches the
    page, the friendly label/icon markup is present, the long message
    gets a "Show full error" toggle + the full text, the short one
    doesn't, and the correlation ID gets a copy affordance."""
    from culprit.models.cluster import Cluster, ClusterMember, Fingerprint
    from culprit.models.evidence import OSFamily
    from culprit.models.patch_run import PatchRun, TriggerMode
    from culprit.models.rca import RCAResult, ResultOrigin
    from culprit.models.report import ClusterReportEntry, FleetReport
    from culprit.models.taxonomy import CauseFamily

    member = ClusterMember(vm_id="vm-1-id", vm_name="vm-1")
    cluster = Cluster(
        cluster_id="cluster-1", run_id="run-1", cluster_key="key-1",
        fingerprint=Fingerprint(error_code_normalized="unknownerror", os_family=OSFamily.WINDOWS, failing_target=""),
        members=[member], representative_vm_id="vm-1-id",
    )
    result = RCAResult(
        cluster_id="cluster-1", origin=ResultOrigin.DEEP_RCA, cause_family=CauseFamily.UNRESOLVED,
        title="Insufficient evidence for a confident root cause", causal_chain=[], confidence=0.0,
        missing_evidence=[
            f"azure_control_plane: {_LONG_AZURE_ERROR}",
            "guest_linux: Run Command failed: (OperationNotAllowed) the VM needs to be running",
        ],
    )
    report = FleetReport(
        run=PatchRun(
            run_id="run-1", maintenance_configuration_id="cfg", subscription_id="sub-1",
            scope_name="Full fleet scan", started_at=datetime.now(timezone.utc), total_machines=1,
            trigger_mode=TriggerMode.AD_HOC,
        ),
        total_machines=1, total_failed=1, total_clusters=1,
        entries=[ClusterReportEntry(cluster=cluster, result=result)],
    )

    html = render_fleet_report_html(report)

    assert "azure_control_plane:" not in html  # the raw prefixed string never reaches the page
    assert "Azure Resource Graph" in html
    assert "Linux guest agent" in html
    assert "eg-detail-toggle" in html  # the long message gets an expand control
    assert _LONG_AZURE_ERROR in html  # ... and its full text is present (just collapsed)
    assert "the VM needs to be running" in html  # the short message's summary is shown directly
    assert "eg-copy-btn" in html
    assert "4705c7ea-a7f8-4fdc-ba42-4e28c494172d" in html
