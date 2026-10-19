from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from culprit.collectors.guest_linux import (
    ALLOWED_LINUX_SCRIPT,
    parse_disk_usage,
    parse_dnf_log,
    parse_dpkg_log,
    parse_extension_core_log,
    parse_extension_wrapper_log,
    parse_journal_reboot,
    parse_linux_output,
    parse_lock_holder,
    parse_repo_check,
    parse_repo_diagnostics,
    parse_subscription_manager,
    parse_waagent_log,
    parse_yum_log,
)
from culprit.collectors.patch_extension_status import MAX_ANOMALY_EVENTS_PER_SECTION

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


def test_parse_lock_holder_does_not_fabricate_a_pid_from_command_not_found_text():
    """Found by review 2026-10-19: dash/sh's own "not found" message embeds
    a line number (e.g. "sh: 1: fuser: not found") - without a guard, the
    bare PID regex below matched that "1" and fabricated a false "dpkg
    lock held by pid 1" anomaly on a VM where fuser (psmisc) was never
    even installed, let alone actually holding the lock."""
    assert parse_lock_holder("sh: 1: fuser: not found", vm_id="vm-1") == []
    assert parse_lock_holder("bash: fuser: command not found", vm_id="vm-1") == []


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
    events, findings, checks_performed, _, _ = parse_linux_output(stdout, vm_id="vm-1")
    kinds = {e.kind for e in events}
    assert "package_manager_log" in kinds
    assert "disk_usage" in kinds
    assert "lock_state" in kinds
    assert not any(e.kind == "repo_check" for e in events)  # 200 is silent
    assert findings == []  # no EXT_STATUS section in this fixture
    assert "subscription-manager (entitlement) status" in checks_performed


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
    events, findings, _, _, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert any(e.kind == "patch_extension_status" for e in events)
    assert len(findings) == 1
    assert findings[0]["source"] == "guest_linux"
    assert findings[0]["extension_version"] == "1.6.71"  # from EXT_VERSION, not the status JSON's own "version": "1.0"
    assert "No space left on device" in findings[0]["message"]
    assert not any(e.kind == "entitlement_state" for e in events)  # Current is silent


# ── waagent.log / core.log (found 2026-10-16: the extension's own detailed
# logs - what Microsoft's docs name as where "information about patches
# assessed/installed and problems encountered" actually lives - were never
# collected at all, only the terse .status summary) ─────────────────────────

def test_parse_waagent_log_flags_an_anomaly_line():
    text = "2026/10/16 03:03:00 INFO ExtHandler Command succeeded\n2026/10/16 03:04:00 ERROR ExtHandler Failed to download extension package: Connection refused\n"
    events = parse_waagent_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "Connection refused" in events[0].summary
    assert events[0].kind == "waagent_log"
    assert events[0].raw_ref == "guest:waagent.log:vm-1:1"


def test_parse_waagent_log_quiet_log_is_silent():
    text = "2026/10/16 03:03:00 INFO ExtHandler Command succeeded\n2026/10/16 03:04:00 INFO ExtHandler Heartbeat sent\n"
    assert parse_waagent_log(text, vm_id="vm-1") == []


def test_parse_waagent_log_empty_is_silent():
    assert parse_waagent_log("", vm_id="vm-1") == []


def test_parse_waagent_log_zero_count_is_not_a_false_positive():
    """Found in review: the keyword scan alone can't tell "0 packages
    failed" (healthy) from a real failure - has_extension_log_anomaly
    must suppress it."""
    text = "2026/10/16 03:04:00 INFO ExtHandler Assessment complete: 0 packages failed, 42 succeeded\n"
    assert parse_waagent_log(text, vm_id="vm-1") == []


def test_parse_waagent_log_zero_count_does_not_mask_a_real_co_occurring_failure():
    """Found in a second review: the first fix suppressed the *entire
    line* whenever a zero-count phrase appeared anywhere on it - which
    also silently dropped a real, separate failure sharing that line.
    has_extension_log_anomaly only strips the zero-count substring
    itself before re-checking, so a genuine anomaly elsewhere on the
    same line must still be caught."""
    text = "2026/10/16 03:04:00 ERROR ExtHandler Assessment: 0 packages failed to assess, but 2 packages failed to install: KB1, KB2\n"
    events = parse_waagent_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "failed to install" in events[0].summary


def test_parse_waagent_log_uses_the_real_line_timestamp():
    text = "2026/10/16 03:04:00 ERROR ExtHandler Failed to download extension package\n"
    events = parse_waagent_log(text, vm_id="vm-1")
    assert events[0].ts == datetime(2026, 10, 16, 3, 4, 0, tzinfo=timezone.utc)


def test_parse_extension_core_log_flags_an_anomaly_line():
    text = "2026-10-16 03:03:00,000 - root - INFO - Assessing patches\n2026-10-16 03:04:00,000 - root - ERROR - Repository unreachable: timed out after 30s\n"
    events = parse_extension_core_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "timed out" in events[0].summary
    assert events[0].kind == "extension_core_log"
    assert events[0].raw_ref == "guest:core.log:vm-1:1"


def test_parse_extension_core_log_quiet_log_is_silent():
    text = "2026-10-16 03:03:00,000 - root - INFO - Assessing patches\n2026-10-16 03:03:30,000 - root - INFO - Installation complete\n"
    assert parse_extension_core_log(text, vm_id="vm-1") == []


def test_parse_extension_core_log_zero_count_is_not_a_false_positive():
    text = "2026-10-16 03:04:00,000 - root - INFO - No errors encountered, 0 denied requests\n"
    assert parse_extension_core_log(text, vm_id="vm-1") == []


def test_parse_extension_core_log_zero_count_does_not_mask_a_real_co_occurring_failure():
    text = "2026-10-16 03:04:00,000 - root - ERROR - No errors encountered during download phase, however installation failed with exit code 1\n"
    events = parse_extension_core_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "installation failed" in events[0].summary


def test_parse_extension_core_log_uses_the_real_line_timestamp():
    text = "2026-10-16 03:04:00,500 - root - ERROR - Repository unreachable: timed out after 30s\n"
    events = parse_extension_core_log(text, vm_id="vm-1")
    assert events[0].ts == datetime(2026, 10, 16, 3, 4, 0, 500000, tzinfo=timezone.utc)


def test_parse_extension_wrapper_log_flags_an_anomaly_line():
    text = "2026/10/18 03:03:00 INFO Invoking patch operation\n2026/10/18 03:04:00 ERROR Could not invoke extension: timed out\n"
    events = parse_extension_wrapper_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "timed out" in events[0].summary
    assert events[0].kind == "extension_wrapper_log"
    assert events[0].raw_ref == "guest:ext_wrapper.log:vm-1:1"


def test_parse_extension_wrapper_log_quiet_log_is_silent():
    assert parse_extension_wrapper_log("2026/10/18 03:03:00 INFO Invoked successfully\n", vm_id="vm-1") == []


def test_parse_extension_wrapper_log_caps_at_the_shared_max():
    text = "\n".join(f"2026/10/18 03:0{i}:00 ERROR Failed attempt {i}" for i in range(MAX_ANOMALY_EVENTS_PER_SECTION + 5))
    events = parse_extension_wrapper_log(text, vm_id="vm-1")
    assert len(events) == MAX_ANOMALY_EVENTS_PER_SECTION


def test_parse_yum_log_flags_an_anomaly_line():
    """Found 2026-10-18: YUM_LOG was already fetched from the VM but
    parse_linux_output never read it - the data arrived and was silently
    dropped on every RHEL/CentOS/Fedora machine."""
    text = "Jun 19 02:10:01 Installed: bash-4.4.20-1.el8.x86_64\nJun 19 02:14:05 Error: Transaction check error: package conflict\n"
    events = parse_yum_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "Transaction check error" in events[0].summary
    assert events[0].kind == "package_manager_log"
    assert events[0].raw_ref == "guest:yum.log:vm-1:1"


def test_parse_yum_log_quiet_log_is_silent():
    assert parse_yum_log("Jun 19 02:10:01 Installed: bash-4.4.20-1.el8.x86_64\n", vm_id="vm-1") == []


def test_parse_dnf_log_flags_an_anomaly_line():
    """Same bug and same fix as parse_yum_log, for DNF_LOG."""
    text = "2026-06-19T02:10:01+0000 INFO Installed: bash-4.4.20-1.el8.x86_64\n2026-06-19T02:14:05+0000 ERROR Failed to synchronize cache: repo unreachable\n"
    events = parse_dnf_log(text, vm_id="vm-1")
    assert len(events) == 1
    assert "repo unreachable" in events[0].summary
    assert events[0].kind == "package_manager_log"
    assert events[0].raw_ref == "guest:dnf.log:vm-1:1"


def test_parse_dnf_log_quiet_log_is_silent():
    assert parse_dnf_log("2026-06-19T02:10:01+0000 INFO Installed: bash-4.4.20-1.el8.x86_64\n", vm_id="vm-1") == []


def test_parse_repo_diagnostics_is_silent_when_everything_resolves_and_responds():
    text = "configured_host=mirror.example.com\nhttp_proxy=\nhttps_proxy=\ndns_resolved=yes\nhttp_status=200\n"
    assert parse_repo_diagnostics(text, vm_id="vm-1") == []


def test_parse_repo_diagnostics_flags_a_dns_failure():
    text = "configured_host=mirror.example.com\nhttp_proxy=\nhttps_proxy=\ndns_resolved=no\nhttp_status=unreachable\n"
    events = parse_repo_diagnostics(text, vm_id="vm-1")
    assert len(events) == 1
    assert events[0].detail["dns_resolution_failed"] is True
    assert events[0].detail["repo_unreachable"] is True
    assert events[0].detail["configured_host"] == "mirror.example.com"


def test_parse_repo_diagnostics_flags_an_http_failure_even_with_dns_ok():
    text = "configured_host=mirror.example.com\nhttp_proxy=\nhttps_proxy=\ndns_resolved=yes\nhttp_status=503\n"
    events = parse_repo_diagnostics(text, vm_id="vm-1")
    assert len(events) == 1
    assert events[0].detail["dns_resolution_failed"] is False
    assert events[0].detail["repo_unreachable"] is True


def test_parse_journal_reboot_flags_a_kernel_error():
    text = "Boot 0: 2026-10-17 00:00:00 UTC\nkernel: [12345.678] ERROR: segfault in process\n"
    events = parse_journal_reboot(text, vm_id="vm-1")
    assert len(events) == 1
    assert "segfault" in events[0].summary
    assert events[0].kind == "journal_reboot"


def test_parse_journal_reboot_quiet_log_is_silent():
    assert parse_journal_reboot("Boot 0: 2026-10-17 00:00:00 UTC\nkernel: [12345.678] Linux version 5.15.0\n", vm_id="vm-1") == []


def test_full_output_sectioning_includes_the_new_log_sections():
    """parse_linux_output must actually slice WAAGENT_LOG/EXT_CORE_LOG out
    and hand them to their parsers - not just that the parsers work in
    isolation (the two tests above). Review 2026-10-18 found that an
    earlier version of this test used empty YUM_LOG/DNF_LOG content, so it
    passed even when that wiring was sabotaged out entirely (the exact
    "fetched but never parsed" bug class this round fixed for those two
    sections) - both now carry real anomaly content so the dispatcher
    wiring itself is actually exercised, not just the standalone parsers."""
    stdout = (
        "---DPKG_LOG---\n\n"
        "---APT_HISTORY---\n\n"
        "---YUM_LOG---\nJun 19 02:14:05 Error: Transaction check error: package conflict\n\n"
        "---DNF_LOG---\n2026-06-19T02:14:05+0000 ERROR Failed to synchronize cache: repo unreachable\n\n"
        "---DISK_USAGE---\n\n"
        "---LOCK_HOLDER---\n\n"
        "---REPO_CHECK---\n200\n\n"
        "---KERNELS---\n\n"
        "---SUBMAN---\n\n"
        "---WAAGENT_LOG---\n2026/10/16 03:04:00 ERROR ExtHandler Failed to download extension package\n\n"
        "---EXT_CORE_LOG---\n2026-10-16 03:04:00,000 - root - ERROR - Repository unreachable\n\n"
        "---EXT_WRAPPER_LOG---\n2026/10/18 03:04:00 ERROR Could not invoke extension: timed out\n\n"
        "---REPO_DIAGNOSTICS---\nconfigured_host=mirror.example.com\ndns_resolved=no\nhttp_status=unreachable\n\n"
        "---JOURNAL_REBOOT---\nkernel: [12345.678] ERROR: segfault in process\n\n"
        "---EXT_VERSION---\n\n"
        "---EXT_STATUS---\nNo status file found\n"
    )
    events, _, checks_performed, _, _ = parse_linux_output(stdout, vm_id="vm-1")
    kinds = {e.kind for e in events}
    raw_refs = {e.raw_ref for e in events}
    assert "waagent_log" in kinds
    assert "extension_core_log" in kinds
    assert "extension_wrapper_log" in kinds
    assert "repo_diagnostics" in kinds
    assert "journal_reboot" in kinds
    assert any(ref.startswith("guest:yum.log:") for ref in raw_refs)
    assert any(ref.startswith("guest:dnf.log:") for ref in raw_refs)
    assert "Azure Linux Agent log" in checks_performed
    assert "system journal / reboot and kernel error history" in checks_performed


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
        "LOCK_HOLDER", "REPO_CHECK", "KERNELS", "SUBMAN", "WAAGENT_LOG",
        "EXT_CORE_LOG", "EXT_WRAPPER_LOG", "REPO_DIAGNOSTICS", "JOURNAL_REBOOT",
        "EXT_VERSION", "EXT_STATUS",
    ):
        assert f"---{marker}---" in stdout.splitlines(), f"{marker} marker missing or merged onto another line"

    events, _, _, _, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert not any(e.kind == "repo_check" for e in events), "a healthy repo check must not synthesize a finding"


# ── Section order and per-section size (found 2026-10-19 from a real
# production incident: a VM's combined Run Command output exceeded Azure's
# documented ~4KB `instanceView` output cap - which silently keeps only
# the LAST bytes written - so 11 of 13 Linux sections read "not
# collected" despite a healthy, non-erroring Run Command completion).
# These two tests guard the mitigation itself, not just that it was
# applied once: a future edit that adds a new section at the front, or
# reintroduces a `-n 200`/`-c 8192`-sized tail, should fail one of these. ──

def test_the_most_diagnostically_valuable_sections_are_ordered_last():
    """Azure keeps the TAIL of a combined script's output when it's too
    large, not the head - so the sections most likely to carry genuine
    root-cause evidence must be the last ones written, not wherever they
    happened to land historically."""
    markers_in_order = re.findall(r"---(\w+)---", ALLOWED_LINUX_SCRIPT)
    position = {m: i for i, m in enumerate(markers_in_order)}

    # EXT_STATUS (the patch extension's own authoritative account) must be
    # the very last section in the script.
    assert markers_in_order[-1] == "EXT_STATUS"
    # SUBMAN and REPO_DIAGNOSTICS - both confirmed, in a real production
    # incident and the entitlement-expired demo cluster, to be genuine
    # root-cause evidence - must come after the OS-family-specific,
    # mutually-exclusive package-manager logs (only one pair of
    # DPKG_LOG/APT_HISTORY vs. YUM_LOG/DNF_LOG is ever non-empty on a
    # given distro, making them the least valuable per byte).
    for low_value in ("KERNELS", "DPKG_LOG", "APT_HISTORY", "YUM_LOG", "DNF_LOG"):
        assert position[low_value] < position["SUBMAN"]
        assert position[low_value] < position["REPO_DIAGNOSTICS"]


def test_every_tail_window_was_shrunk_from_the_original_200_lines():
    """The original `-n 200`/`-c 8192` sizes were themselves a real
    contributor to the production incident this guards against - a
    regression back to them would reopen it even with the reordering
    above intact."""
    assert "-n 200" not in ALLOWED_LINUX_SCRIPT
    assert "-c 8192" not in ALLOWED_LINUX_SCRIPT
    assert "-n 20 " in ALLOWED_LINUX_SCRIPT
    assert "-c 3072" in ALLOWED_LINUX_SCRIPT


# ── Window filtering (found 2026-10-18, same real-world gap as
# guest_windows.py's identical tests - see that file's own comment) ───────

_DPKG_LOG_TIMESTAMPED_ONLY = (
    "2026-06-19 02:14:07 status half-installed linux-image-5.15.0-91-generic:amd64 5.15.0-91.101\n"
)


def test_parse_dpkg_log_drops_an_anomaly_outside_the_given_window():
    old_window_start = datetime(2026, 6, 18, 0, 0, tzinfo=timezone.utc)
    old_window_end = datetime(2026, 6, 18, 6, 0, tzinfo=timezone.utc)
    events = parse_dpkg_log(_DPKG_LOG_TIMESTAMPED_ONLY, vm_id="vm-1", window_start=old_window_start, window_end=old_window_end)
    assert events == []


def test_parse_dpkg_log_keeps_an_anomaly_inside_the_given_window():
    window_start = datetime(2026, 6, 19, 2, 0, tzinfo=timezone.utc)
    window_end = datetime(2026, 6, 19, 2, 30, tzinfo=timezone.utc)
    events = parse_dpkg_log(_DPKG_LOG_TIMESTAMPED_ONLY, vm_id="vm-1", window_start=window_start, window_end=window_end)
    assert len(events) == 1


def test_parse_dpkg_log_without_window_args_is_unfiltered():
    """Backward compatibility - existing callers/tests that don't pass a
    window get the exact prior, unfiltered behavior."""
    events = parse_dpkg_log(_DPKG_LOG_TIMESTAMPED_ONLY, vm_id="vm-1")
    assert len(events) == 1


def test_parse_dpkg_log_keeps_a_line_it_cannot_timestamp_regardless_of_window():
    """The gzip "No space left on device" line has no leading timestamp
    _DPKG_LINE_RE can match - it must stay in-window (fail-open) even
    against a window nowhere near collection time, since excluding it
    would risk silently dropping a real anomaly over an unfamiliar format."""
    old_window_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    old_window_end = datetime(2020, 1, 1, 1, 0, tzinfo=timezone.utc)
    events = parse_dpkg_log("gzip: stdout: No space left on device\n", vm_id="vm-1", window_start=old_window_start, window_end=old_window_end)
    assert len(events) == 1


def test_parse_waagent_log_window_filtering_via_the_shared_anomaly_scan():
    """parse_waagent_log is one of the four parsers built on the shared
    _anomaly_scan helper - proving window filtering here is representative
    of parse_extension_core_log/parse_extension_wrapper_log/
    parse_journal_reboot too, since they all call the identical
    implementation."""
    text = "2026-10-16 03:04:00 ERROR Failed to reach Windows Update endpoint: timed out\n"
    in_window = parse_waagent_log(
        text, vm_id="vm-1",
        window_start=datetime(2026, 10, 16, 3, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 16, 3, 30, tzinfo=timezone.utc),
    )
    assert len(in_window) == 1

    out_of_window = parse_waagent_log(
        text, vm_id="vm-1",
        window_start=datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 18, 6, 0, tzinfo=timezone.utc),
    )
    assert out_of_window == []


def test_parse_linux_output_threads_the_window_into_its_parsers():
    """An integration-level check that parse_linux_output actually
    forwards window_start/window_end to the parsers that accept them."""
    stdout = "---DPKG_LOG---\n" + _DPKG_LOG_TIMESTAMPED_ONLY
    events, _, _, _, _ = parse_linux_output(
        stdout, vm_id="vm-1",
        window_start=datetime(2020, 1, 1, tzinfo=timezone.utc),
        window_end=datetime(2020, 1, 1, 1, 0, tzinfo=timezone.utc),
    )
    assert not any(e.kind == "package_manager_log" for e in events)


# ── checks_performed must not claim a check ran when its command simply
# isn't installed (found by review 2026-10-19: SUBMAN/LOCK_HOLDER both
# merge stderr into their own section content via `2>&1`, so a VM missing
# subscription-manager or fuser gets a literal "command not found" string
# in that section - neither parser recognizes that as anything but "no
# anomaly," so checks_performed was silently claiming "checked, healthy"
# for a tool that was never actually available). checks_unavailable (added
# the same day the "show all logs used/not used" UI feature was requested)
# is the honest home for those excluded labels instead of silently
# dropping them. ───────────────────────────────────────────────────────────

def test_checks_performed_excludes_subman_when_the_binary_is_missing():
    """The exact real-world shape on any non-RHEL box (this script already
    runs unconditionally against every Linux distro, Debian/Ubuntu
    included) - subscription-manager doesn't exist, so bash's own "command
    not found" text lands in the SUBMAN section via the script's `2>&1`."""
    stdout = (
        "---DPKG_LOG---\n\n"
        "---SUBMAN---\nbash: subscription-manager: command not found\n"
    )
    events, _, checks_performed, checks_unavailable, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert not any(e.kind == "entitlement_state" for e in events)
    assert "subscription-manager (entitlement) status" not in checks_performed
    assert "subscription-manager (entitlement) status" in checks_unavailable


def test_checks_performed_excludes_lock_holder_when_fuser_is_missing():
    """Same bug class as SUBMAN above - fuser (psmisc) isn't guaranteed
    installed on a minimal/container Linux image, and LOCK_HOLDER also
    merges stderr via `2>&1`."""
    stdout = "---LOCK_HOLDER---\nsh: 1: fuser: not found\n"
    events, _, checks_performed, checks_unavailable, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert not any(e.kind == "lock_state" for e in events)
    assert "dpkg lock holder" not in checks_performed
    assert "dpkg lock holder" in checks_unavailable


def test_checks_performed_still_includes_subman_when_it_genuinely_ran():
    """The positive case: a real, healthy subscription-manager response
    must still be reported as performed - the fix must only exclude actual
    command-not-found text, not legitimate output."""
    stdout = "---SUBMAN---\nOverall Status: Current\n"
    _, _, checks_performed, checks_unavailable, _ = parse_linux_output(stdout, vm_id="vm-1")
    assert "subscription-manager (entitlement) status" in checks_performed


# ── checks_finding_counts must reflect the TRUE, uncapped per-section
# count (found by review 2026-10-19: the reporting layer must never
# re-derive "used" from the persisted timeline, which is capped to the
# machine's most recent events overall and could silently evict a
# section's own finding) ───────────────────────────────────────────────

def test_checks_finding_counts_reflects_the_true_uncapped_count():
    stdout = (
        "---DPKG_LOG---\n" + _DPKG_LOG + "\n"
        "---SUBMAN---\nOverall Status: Invalid\n"
    )
    _, _, _, _, finding_counts = parse_linux_output(stdout, vm_id="vm-1")
    # _DPKG_LOG carries two distinct anomalies (the space failure and the
    # half-installed status line) - the count must be the real, uncapped
    # total, not just "at least one."
    assert finding_counts.get("dpkg package manager log") == 2
    assert finding_counts.get("subscription-manager (entitlement) status") == 1


def test_checks_finding_counts_omits_a_label_with_zero_events():
    stdout = "---SUBMAN---\nOverall Status: Current\n"
    _, _, _, _, finding_counts = parse_linux_output(stdout, vm_id="vm-1")
    assert "subscription-manager (entitlement) status" not in finding_counts
