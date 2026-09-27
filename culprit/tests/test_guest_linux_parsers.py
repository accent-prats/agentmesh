from __future__ import annotations

from culprit.collectors.guest_linux import (
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
    events = parse_linux_output(stdout, vm_id="vm-1")
    kinds = {e.kind for e in events}
    assert "package_manager_log" in kinds
    assert "disk_usage" in kinds
    assert "lock_state" in kinds
    assert not any(e.kind == "repo_check" for e in events)  # 200 is silent
    assert not any(e.kind == "entitlement_state" for e in events)  # Current is silent
