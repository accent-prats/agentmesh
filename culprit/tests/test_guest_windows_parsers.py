from __future__ import annotations

from datetime import datetime, timezone

from culprit.collectors.guest_windows import (
    parse_cbs_log,
    parse_disk_usage,
    parse_extension_log,
    parse_pending_reboot,
    parse_windows_output,
    parse_wu_log,
    parse_wuauserv_state,
)

_WU_LOG = """\
2026-06-19 02:10:01:123  456  1a2b AU  ###########  AU: Uninstall/Install job status
2026-06-19 02:10:03:456  456  1a2b WU  WARNING: WU client failed Searching for updates with error 0x80244022
2026-06-19 02:10:04:001  456  1a2b AU  AU received policy manager notification
"""

_CBS_LOG = """\
2026-06-19 02:11:00, Info CBS Starting TrustedInstaller initialization.
2026-06-19 02:11:05, Error CBS Failed to CSI Transaction, disposition = 0, [HRESULT = 0x80070070 - ERROR_DISK_FULL]
"""


def test_parse_wu_log_extracts_error_code_and_flags_repo_unreachable():
    events = parse_wu_log(_WU_LOG, vm_id="vm-1")
    assert len(events) == 1
    assert events[0].detail["normalized_error"] == "0x80244022"
    assert events[0].detail["repo_unreachable"] is True


def test_parse_cbs_log_flags_failure_lines():
    events = parse_cbs_log(_CBS_LOG, vm_id="vm-1")
    assert len(events) == 1
    assert "Failed to CSI Transaction" in events[0].summary


def test_parse_pending_reboot_true():
    events = parse_pending_reboot("True\n", vm_id="vm-1")
    assert events[0].detail["pending_reboot"] is True


def test_parse_pending_reboot_false_is_silent():
    assert parse_pending_reboot("False\n", vm_id="vm-1") == []


def test_parse_wuauserv_state_flags_non_running():
    events = parse_wuauserv_state("Stopped\n", vm_id="vm-1")
    assert events[0].detail["agent_stale"] is True


def test_parse_wuauserv_state_running_is_silent():
    assert parse_wuauserv_state("Running\n", vm_id="vm-1") == []


def test_parse_disk_usage_flags_low_free_drive():
    text = "C 104857600 500000000000\nD 900000000000 100000000000\n"  # C: has 100MB free
    events = parse_disk_usage(text, vm_id="vm-1", min_free_bytes=250 * 1024 * 1024)
    flagged = {e.detail["mount"] for e in events}
    assert flagged == {"C:"}


# ── WindowsPatchExtension.log (found 2026-10-16: pipeline/installation_
# report.py::_guest_log_path already names this exact path as the
# human-facing "guest log (typical location)" hint, but no collector ever
# read it - only the terse .status summary) ─────────────────────────────────

def test_parse_extension_log_flags_an_anomaly_line():
    text = "2026-10-16 03:03:00 INFO Assessing patches\n2026-10-16 03:04:00 ERROR Failed to reach Windows Update endpoint: timed out\n"
    events = parse_extension_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "timed out" in events[0].summary
    assert events[0].kind == "extension_log"
    assert events[0].raw_ref == "guest:WindowsPatchExtension.log:vm-1:1"


def test_parse_extension_log_quiet_log_is_silent():
    text = "2026-10-16 03:03:00 INFO Assessing patches\n2026-10-16 03:03:30 INFO Installation complete\n"
    assert parse_extension_log(text, vm_id="vm-1") == []


def test_parse_extension_log_zero_count_is_not_a_false_positive():
    text = "2026-10-16 03:04:00 INFO Patch installation completed with 0 failed packages\n"
    assert parse_extension_log(text, vm_id="vm-1") == []


def test_parse_extension_log_uses_the_real_line_timestamp():
    text = "2026-10-16 03:04:00 ERROR Failed to reach Windows Update endpoint: timed out\n"
    events = parse_extension_log(text, vm_id="vm-1")
    assert events[0].ts == datetime(2026, 10, 16, 3, 4, 0, tzinfo=timezone.utc)


def test_full_windows_output_sectioning():
    stdout = (
        "---WU_LOG---\n" + _WU_LOG + "\n"
        "---CBS_LOG---\n" + _CBS_LOG + "\n"
        "---PENDING_REBOOT---\nTrue\n\n"
        "---WUAUSERV---\nRunning\n\n"
        "---DISK_USAGE---\nC 104857600 500000000000\n\n"
        "---WSUS_TARGET---\n\n"
        "---EXT_VERSION---\n\n"
        "---EXT_LOG---\n2026-10-16 03:04:00 ERROR Failed to reach Windows Update endpoint\n\n"
        "---EXT_STATUS---\nNo status file found\n"
    )
    events, findings = parse_windows_output(stdout, vm_id="vm-1")
    kinds = {e.kind for e in events}
    assert "wu_log" in kinds
    assert "cbs_log" in kinds
    assert "pending_reboot" in kinds
    assert "disk_usage" in kinds
    assert "extension_log" in kinds
    assert not any(e.kind == "agent_state" for e in events)  # Running is silent
    assert findings == []  # "No status file found" short-circuits, not a real finding


def test_ext_status_section_is_sliced_out_and_handed_to_the_shared_parser():
    """Same wiring proof as guest_linux.py's own version of this test -
    the JSON parsing itself is patch_extension_status.py's, already
    covered by tests/test_patch_extension_status.py."""
    import json

    status_json = json.dumps([{
        "version": "1.0",
        "status": {
            "name": "Microsoft.CPlat.Core.WindowsPatchExtension", "operation": "Installation",
            "status": "error", "code": 1,
            "formattedMessage": {"message": "Reboot required before patches could be installed"},
            "substatus": [],
        },
    }])
    stdout = (
        "---WU_LOG---\n\n"
        "---CBS_LOG---\n\n"
        "---PENDING_REBOOT---\n\n"
        "---WUAUSERV---\n\n"
        "---DISK_USAGE---\n\n"
        "---WSUS_TARGET---\n\n"
        "---EXT_VERSION---\n1.5.71\n\n"
        "---EXT_STATUS---\n" + status_json + "\n"
    )
    events, findings = parse_windows_output(stdout, vm_id="vm-1")
    assert any(e.kind == "patch_extension_status" for e in events)
    assert len(findings) == 1
    assert findings[0]["source"] == "guest_windows"
    assert findings[0]["extension_version"] == "1.5.71"  # from EXT_VERSION, not the status JSON's own "version": "1.0"
    assert "Reboot required" in findings[0]["message"]
