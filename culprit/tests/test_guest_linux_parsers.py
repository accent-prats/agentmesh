from __future__ import annotations

import shutil
import subprocess

import pytest

from culprit.collectors.guest_linux import (
    ALLOWED_LINUX_SCRIPT,
    parse_disk_usage,
    parse_dpkg_log,
    parse_linux_output,
    parse_lock_holder,
    parse_repo_check,
    parse_subscription_manager,
)

_DPKG_LOG = """\
2026-06-19 02:10:01 startup archives unpack
2026-06-19 02:14:05 upgrade linux-image-5.15.0-91-generic:amd64 5.15.0-90.100 5.15.0-91.101
2026-06-19 02:14:07 status half-installed linux-image-5.15.0-91-generic:amd64 5.15.0-91.101
gzip: stdout: No space left on device
2026-06-19 02:14:08 status unpacked linux-image-5.15.0-91-generic:amd64 5.15.0-91.101
"""


def test_parse_dpkg_log_finds_space_failure():
    events = parse_dpkg_log(_DPKG_LOG, vm_id="vm-1")
    assert any("No space left on device" in e.summary for e in events)
    assert any(e.detail.get("write_failure") for e in events)
    assert any(e.detail.get("disk_low") for e in events)


def test_parse_dpkg_log_flags_half_installed():
    events = parse_dpkg_log(_DPKG_LOG, vm_id="vm-1")
    assert any("half-installed" in e.summary for e in events)


_DF_OUTPUT = """\
/               34%    120G
/var            41%    30G
/boot           99%    3.2M
/home           12%    900G
"""


def test_parse_disk_usage_flags_only_high_utilization():
    events = parse_disk_usage(_DF_OUTPUT, vm_id="vm-1", threshold_pct=90)
    mounts_flagged = {e.detail["mount"] for e in events}
    assert mounts_flagged == {"/boot"}


def test_parse_lock_holder_extracts_pid():
    events = parse_lock_holder("4821\n", vm_id="vm-1")
    assert len(events) == 1
    assert events[0].detail["lock_holder_pid"] == "4821"
    assert events[0].detail["lock_held"] is True


def test_parse_lock_holder_empty_when_no_lock():
    assert parse_lock_holder("", vm_id="vm-1") == []
    assert parse_lock_holder("/var/lib/dpkg/lock-frontend: Permission denied", vm_id="vm-1") == []


def test_parse_repo_check_flags_non_200():
    events = parse_repo_check("000", vm_id="vm-1")
    assert events[0].detail["repo_unreachable"] is True


def test_parse_repo_check_ok_is_silent():
    assert parse_repo_check("200", vm_id="vm-1") == []


def test_parse_subscription_manager_flags_invalid():
    events = parse_subscription_manager("Overall Status: Invalid\n", vm_id="vm-1")
    assert events[0].detail["entitlement_expired"] is True


def test_parse_subscription_manager_current_is_silent():
    assert parse_subscription_manager("Overall Status: Current\n", vm_id="vm-1") == []


def test_full_output_sectioning_and_parsing():
    stdout = (
        "---DPKG_LOG---\n" + _DPKG_LOG + "\n"
        "---APT_HISTORY---\n\n"
        "---YUM_LOG---\n\n"
        "---DNF_LOG---\n\n"
        "---DISK_USAGE---\n" + _DF_OUTPUT + "\n"
        "---LOCK_HOLDER---\n4821\n\n"
        "---REPO_CHECK---\n200\n\n"
        "---KERNELS---\nii  linux-image-5.15.0-91-generic\n5.15.0-91-generic\n\n"
        "---SUBMAN---\nOverall Status: Current\n"
    )
    events, findings = parse_linux_output(stdout, vm_id="vm-1")
    kinds = {e.kind for e in events}
    assert "package_manager_log" in kinds
    assert "disk_usage" in kinds
    assert "lock_state" in kinds
    assert not any(e.kind == "repo_check" for e in events)  # 200 is silent
    assert findings == []  # no EXT_STATUS section in this fixture


def test_ext_status_section_is_sliced_out_and_handed_to_the_shared_parser():
    """parse_linux_output's job for EXT_STATUS is just section-slicing -
    the actual JSON parsing is patch_extension_status.py's own, already
    covered by tests/test_patch_extension_status.py. A real payload (not
    just the empty/"no file" case) proves the section genuinely reaches
    that parser and its findings/events come back out, not just that an
    empty-in/empty-out path happens to match."""
    import json

    status_json = json.dumps([{
        "version": "1.0",
        "status": {
            "name": "Microsoft.CPlat.Core.LinuxPatchExtension", "operation": "Installation",
            "status": "error", "code": 1,
            "formattedMessage": {"message": "No space left on device while installing kernel package"},
            "substatus": [],
        },
    }])
    stdout = (
        "---DPKG_LOG---\n\n"
        "---APT_HISTORY---\n\n"
        "---YUM_LOG---\n\n"
        "---DNF_LOG---\n\n"
        "---DISK_USAGE---\n\n"
        "---LOCK_HOLDER---\n\n"
        "---REPO_CHECK---\n200\n\n"
        "---KERNELS---\n\n"
        "---SUBMAN---\n\n"
        "---EXT_VERSION---\n1.6.71\n\n"
        "---EXT_STATUS---\n" + status_json + "\n"
    )
    events, findings = parse_linux_output(stdout, vm_id="vm-1")
    assert any(e.kind == "patch_extension_status" for e in events)
    assert len(findings) == 1
    assert findings[0]["source"] == "guest_linux"
    assert findings[0]["extension_version"] == "1.6.71"  # from EXT_VERSION, not the status JSON's own "version": "1.0"
    assert "No space left on device" in findings[0]["message"]
    assert not any(e.kind == "entitlement_state" for e in events)  # Current is silent


def test_repo_check_curl_format_ends_with_a_newline():
    """Review caught a real bug: curl's -w "%{http_code}" (no trailing
    newline - documented curl behavior, not an environment quirk) glued
    REPO_CHECK's "200" directly onto the very next line's "---KERNELS---"
    marker with no newline between them, so _split_sections's line-based
    "^---(\\w+)---$" regex never recognized KERNELS as a section header,
    and parse_repo_check's text != "200" check fired a spurious
    "repo_unreachable" finding on every healthy machine - fabricated
    evidence reaching the RCA prompt. The earlier hand-typed test fixture
    (test_full_output_sectioning_and_parsing, just above) didn't catch
    this precisely because it hand-typed the newline the real script
    never produced - this test guards the actual script text instead of
    a fixture that could silently drift from it again."""
    assert '-w "%{http_code}\\n"' in ALLOWED_LINUX_SCRIPT


@pytest.mark.skipif(shutil.which("bash") is None, reason="requires a real bash to execute the actual Run Command script")
def test_allowed_linux_script_runs_cleanly_through_a_real_shell(tmp_path):
    """The strongest possible regression guard for both bugs found in
    review (the swallowed ---DPKG_LOG--- marker from the old shlex.split
    + rejoin, and the REPO_CHECK/KERNELS merge from curl's missing
    newline): actually execute the script Azure's Run Command would run,
    not a hand-typed stand-in for its output. Every section marker must
    appear on its own line, and feeding the real captured stdout through
    parse_linux_output must not synthesize a spurious repo_check finding."""
    script_path = tmp_path / "script.sh"
    script_path.write_text(ALLOWED_LINUX_SCRIPT, encoding="utf-8")
    result = subprocess.run(["bash", str(script_path)], capture_output=True, text=True, timeout=30)
    stdout = result.stdout

    for marker in (
        "DPKG_LOG", "APT_HISTORY", "YUM_LOG", "DNF_LOG", "DISK_USAGE",
        "LOCK_HOLDER", "REPO_CHECK", "KERNELS", "SUBMAN", "EXT_VERSION", "EXT_STATUS",
    ):
        assert f"---{marker}---" in stdout.splitlines(), f"{marker} marker missing or merged onto another line"

    events, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert not any(e.kind == "repo_check" for e in events), "a healthy repo check must not synthesize a finding"
