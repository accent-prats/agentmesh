"""parse_patch_extension_status (culprit/collectors/patch_extension_status.py)
- the Azure patch extension's own status file, parsed per the Azure VM
extension handler status schema (Azure/azure-linux-extensions repo's design
doc), shared by both guest_linux.py and guest_windows.py since the schema
is OS-agnostic."""
from __future__ import annotations

import json

from culprit.collectors.patch_extension_status import parse_patch_extension_status
from culprit.models.evidence import Source

_SUCCESS_STATUS = json.dumps([
    {
        "version": "1.0",
        "timestampUTC": "2026-10-10T18:00:00Z",
        "status": {
            "name": "Microsoft.CPlat.Core.LinuxPatchExtension",
            "operation": "Installation",
            "status": "success",
            "code": 0,
            "formattedMessage": {"lang": "en-US", "message": "Installed 12 of 12 patches successfully"},
            "substatus": [
                {"name": "PatchAssessmentSummary", "status": "success", "code": 0,
                 "formattedMessage": {"message": "Assessed 12 patches"}},
            ],
        },
    }
])

_ERROR_STATUS = json.dumps([
    {
        "version": "1.0",
        "timestampUTC": "2026-10-10T18:00:00Z",
        "status": {
            "name": "Microsoft.CPlat.Core.LinuxPatchExtension",
            "operation": "Installation",
            "status": "error",
            "code": 1,
            "formattedMessage": {"lang": "en-US", "message": "Installation failed - see substatus"},
            "substatus": [
                {"name": "PatchInstallationSummary", "status": "error", "code": 2,
                 "formattedMessage": {"message": "No space left on device while installing kernel package"}},
                {"name": "PatchAssessmentSummary", "status": "success", "code": 0,
                 "formattedMessage": {"message": "Assessed 12 patches"}},
            ],
        },
    }
])


def test_a_success_status_is_still_surfaced_as_a_finding():
    """A success from the extension while Azure's own control-plane record
    says Failed is itself diagnostic (a reporting gap, not a patch
    failure) - the top-level status is always surfaced, not just failures."""
    events, findings = parse_patch_extension_status(_SUCCESS_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert len(findings) == 1
    assert findings[0]["status"] == "success"
    assert findings[0]["extension_name"] == "Microsoft.CPlat.Core.LinuxPatchExtension"
    assert "Installed 12 of 12" in findings[0]["message"]
    assert len(events) == 1
    assert events[0].detail["anomaly"] is False


def test_successful_substatus_entries_are_not_surfaced_as_separate_findings():
    """Only anomalous (error/warning) substatus entries become their own
    finding - a fleet's worth of "success" substatus entries would be
    noise, not evidence (same convention every other guest parser follows:
    surface anomalies, not every success)."""
    events, findings = parse_patch_extension_status(_SUCCESS_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert len(findings) == 1  # only the top-level - the successful substatus is skipped


def test_an_error_substatus_becomes_its_own_finding_alongside_the_top_level_one():
    events, findings = parse_patch_extension_status(_ERROR_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert len(findings) == 2
    assert findings[0]["substatus_name"] is None
    assert findings[0]["status"] == "error"
    assert findings[1]["substatus_name"] == "PatchInstallationSummary"
    assert "No space left on device" in findings[1]["message"]
    assert len(events) == 2
    assert events[1].detail["anomaly"] is True


def test_raw_status_json_is_attached_only_to_the_first_finding():
    _, findings = parse_patch_extension_status(_ERROR_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert findings[0]["raw_status_json"] == _ERROR_STATUS
    assert findings[1]["raw_status_json"] is None


def test_no_status_file_found_produces_nothing():
    events, findings = parse_patch_extension_status("No status file found", vm_id="vm-1", source=Source.GUEST_LINUX)
    assert events == []
    assert findings == []


def test_empty_text_produces_nothing():
    events, findings = parse_patch_extension_status("", vm_id="vm-1", source=Source.GUEST_LINUX)
    assert events == []
    assert findings == []


def test_malformed_json_produces_one_informational_event_and_no_findings():
    events, findings = parse_patch_extension_status("{not valid json", vm_id="vm-1", source=Source.GUEST_WINDOWS)
    assert findings == []
    assert len(events) == 1
    assert events[0].detail["parse_error"] is True
    assert events[0].source == Source.GUEST_WINDOWS


def test_a_windows_source_is_tagged_correctly():
    events, findings = parse_patch_extension_status(_SUCCESS_STATUS, vm_id="vm-1", source=Source.GUEST_WINDOWS)
    assert findings[0]["source"] == "guest_windows"
    assert events[0].source == Source.GUEST_WINDOWS


def test_a_long_message_is_truncated_in_the_event_summary_but_not_in_the_finding():
    long_message = "x" * 500
    status = json.dumps([{
        "version": "1.0",
        "status": {
            "name": "Microsoft.CPlat.Core.LinuxPatchExtension", "operation": "Installation",
            "status": "error", "code": 1,
            "formattedMessage": {"message": long_message}, "substatus": [],
        },
    }])
    events, findings = parse_patch_extension_status(status, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert len(events[0].summary) <= 240
    assert findings[0]["message"] == long_message  # the finding keeps the full message for the UI


def test_extension_version_comes_from_the_caller_not_the_status_files_own_version_field():
    """Real bug caught in review: the status file's own top-level
    "version" field (here "1.0") is the status-reporting *protocol*
    version every extension always writes - not the installed extension's
    package version. The caller (guest_linux.py/guest_windows.py) must
    supply the real version, resolved from the extension directory's own
    name on disk, not this module reading the wrong field."""
    _, findings = parse_patch_extension_status(
        _SUCCESS_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX, extension_version="1.6.71",
    )
    assert findings[0]["extension_version"] == "1.6.71"
    assert findings[0]["extension_version"] != "1.0"  # the status-reporting protocol version in the fixture


def test_extension_version_is_none_when_the_caller_does_not_supply_one():
    """No silent fallback to the status file's own (wrong) "version"
    field - better to show nothing than something confidently wrong."""
    _, findings = parse_patch_extension_status(_SUCCESS_STATUS, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert findings[0]["extension_version"] is None


def test_an_unexpectedly_shaped_formattedMessage_does_not_raise():
    """Valid JSON, valid list/dict structure, but formattedMessage itself
    isn't a dict (e.g. a non-conforming guest agent write) - must degrade
    to a placeholder message, not raise, matching every other malformed-
    input case this parser already handles gracefully."""
    status = json.dumps([{
        "version": "1.0",
        "status": {
            "name": "Microsoft.CPlat.Core.LinuxPatchExtension", "operation": "Installation",
            "status": "error", "code": 1, "formattedMessage": "not a dict", "substatus": [],
        },
    }])
    events, findings = parse_patch_extension_status(status, vm_id="vm-1", source=Source.GUEST_LINUX)
    assert findings[0]["message"] == "(no message)"


def test_a_non_list_or_empty_json_payload_is_treated_as_no_findings():
    events, findings = parse_patch_extension_status("{}", vm_id="vm-1", source=Source.GUEST_LINUX)
    assert events == []
    assert findings == []
    events, findings = parse_patch_extension_status("[]", vm_id="vm-1", source=Source.GUEST_LINUX)
    assert events == []
    assert findings == []
