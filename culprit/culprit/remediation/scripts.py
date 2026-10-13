"""The allow-listed disk-cleanup scripts - the entire guest-side attack
surface for this one automated action. Extending or editing either script
requires an explicit code review, not a config change - the same rule
culprit/collectors/guest_linux.py and guest_windows.py already state for
their own (read-only) allow-lists.

Both scripts fulfill exactly what culprit/pipeline/rules.py::
rule_disk_exhaustion already promises a human: "prune old kernels, clear
temp/cache directories", target "at least 200MB free" on the affected
mount - never anything broader.

Design bar every command below is held to:
  - Conservative: only caches, temp files, rotated log archives, and
    superseded OS components - never user data, never an active/current
    file, never a currently-installed package needed to run or roll back.
  - Idempotent: safe to run twice in a row (an empty cache or an
    already-under-cap journal is just a no-op, not an error).
  - No interactive prompt: Run Command has no stdin, so every command
    that could normally ask for confirmation is forced non-interactive.
  - Fails loudly: a script that *ran* but didn't actually free enough
    space is a distinct, reported failure (a parsed status= line), not a
    silently-accepted "the agent ran something" success - Azure's own
    Run Command "succeeded" provisioning state only means the extension
    executed the script, never that the script's own goal was met.

The mount/drive to target is passed as a Run Command *parameter*
(RunCommandInputParameter), never string-interpolated into the script
text - see remediation/runner.py. That keeps the same guarantee the
existing read-only collectors already rely on: the script text itself is
fixed and reviewed, and nothing caller-supplied ever becomes code.
"""
from __future__ import annotations

import re

# Machine-parseable result block both scripts end with. Searched for by
# parse_remediation_result() below, not by exit code alone - Azure's own
# "succeeded" just means the script ran to completion, not that it
# achieved anything.
RESULT_MARKER = "---REMEDIATION_RESULT---"

ALLOWED_LINUX_CLEANUP_SCRIPT = r"""#!/bin/bash
# Idempotent, conservative disk cleanup for rule_disk_exhaustion's
# "prune old kernels, clear temp/cache directories" promise. $1 is the
# mount point (a Run Command parameter, never interpolated), default "/".
# Deliberately NOT `set -e` - one missing tool (e.g. no dnf on a Debian
# box) must not abort the other steps; the overall pass/fail verdict is
# decided once, at the end, from the actual free-space result.
set +e
MOUNT="${1:-/}"
TARGET_FREE_BYTES=209715200  # 200MB - matches the rule's own stated target

echo "---BEFORE---"
df -B1 --output=avail "$MOUNT" 2>/dev/null | tail -n1

echo "---ACTIONS---"
# 1. Package manager cache only - re-downloadable, never an installed or
#    manually-held package.
if command -v apt-get >/dev/null 2>&1; then
  echo "apt-get clean:"; apt-get clean 2>&1
elif command -v dnf >/dev/null 2>&1; then
  echo "dnf clean all:"; dnf clean all 2>&1
elif command -v yum >/dev/null 2>&1; then
  echo "yum clean all:"; yum clean all 2>&1
fi

# 2. Superseded kernel/package autoremove only - both apt and dnf/yum
#    autoremove refuse to remove the currently *running* kernel (uname -r)
#    by design; this never touches it.
echo "Currently running kernel (protected): $(uname -r)"
if command -v apt-get >/dev/null 2>&1; then
  echo "apt-get autoremove --purge:"; apt-get -y autoremove --purge 2>&1
elif command -v dnf >/dev/null 2>&1; then
  echo "dnf autoremove:"; dnf -y autoremove 2>&1
fi

# 3. Bounded systemd journal retention - drops the oldest entries down to
#    a fixed size cap only, never user data.
if command -v journalctl >/dev/null 2>&1; then
  echo "journalctl --vacuum-size=200M:"; journalctl --vacuum-size=200M 2>&1
fi

# 4. Already-rotated/compressed log archives only (*.gz, *.1, *.2, ...) -
#    never the active, currently-written log - and only ones older than 7
#    days, so a log rotated an hour ago during this very incident is left
#    alone.
echo "Rotated log archives older than 7 days:"
find /var/log -maxdepth 3 -regextype posix-extended -type f \
  \( -name '*.gz' -o -regex '.*\.[0-9]+$' \) -mtime +7 -print -delete 2>&1

# 5. Stale files under /tmp, /var/tmp only - world-writable scratch space
#    by POSIX convention, never a path a user/application is expected to
#    keep data in. Files only (never a directory, never a symlink
#    followed outside /tmp), older than 7 days.
echo "Stale /tmp, /var/tmp files older than 7 days:"
find /tmp /var/tmp -mindepth 1 -maxdepth 3 -type f -mtime +7 -print -delete 2>&1

echo "---AFTER---"
AFTER_BYTES=$(df -B1 --output=avail "$MOUNT" 2>/dev/null | tail -n1 | tr -d ' ')
echo "$AFTER_BYTES"

echo "---REMEDIATION_RESULT---"
if [ -z "$AFTER_BYTES" ]; then
  echo "status=failed reason=\"could not read free space on $MOUNT after cleanup\""
  exit 1
elif [ "$AFTER_BYTES" -ge "$TARGET_FREE_BYTES" ]; then
  echo "status=success mount=$MOUNT free_bytes_after=$AFTER_BYTES"
  exit 0
else
  echo "status=failed reason=\"only $AFTER_BYTES bytes free on $MOUNT, target is $TARGET_FREE_BYTES\" mount=$MOUNT free_bytes_after=$AFTER_BYTES"
  exit 1
fi
"""

ALLOWED_WINDOWS_CLEANUP_SCRIPT = r"""param(
    [string]$Mount = "C:\"
)
$ErrorActionPreference = "Continue"
$TargetFreeBytes = 200MB
$DriveLetter = $Mount.TrimEnd('\', ':').Substring(0,1)

Write-Output "---BEFORE---"
(Get-PSDrive -Name $DriveLetter -PSProvider FileSystem).Free

Write-Output "---ACTIONS---"

# 1. Windows Update's own download cache - re-populated on demand by
#    design, never an installed update or a user file. The service is
#    stopped only for the duration of this step and restarted
#    immediately after - the standard stop/clear/start sequence
#    Microsoft's own WU troubleshooting guidance uses.
Write-Output "Clearing SoftwareDistribution download cache:"
try {
    Stop-Service -Name wuauserv -Force -ErrorAction Stop
    Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Cleared."
} catch {
    Write-Output "Could not clear (service busy or access denied): $($_.Exception.Message)"
} finally {
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
}

# 2. System temp only - C:\Windows\Temp is machine-owned scratch space by
#    convention, never a user document. Files older than 7 days, files
#    only (never a directory), so anything this very maintenance run
#    just wrote is left alone.
Write-Output "Clearing stale C:\Windows\Temp files older than 7 days:"
Get-ChildItem -Path "$env:windir\Temp" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
Write-Output "Done."

# 3. Superseded Windows Update components only - Microsoft's own
#    documented command for reclaiming WinSxS space from updates already
#    superseded by a later one. Deliberately WITHOUT /ResetBase, which
#    would additionally forfeit the ability to uninstall any
#    currently-installed update - too aggressive for an unattended,
#    automated action.
Write-Output "DISM StartComponentCleanup:"
& dism.exe /Online /Cleanup-Image /StartComponentCleanup 2>&1 | Out-String | Write-Output

Write-Output "---AFTER---"
$freeAfter = (Get-PSDrive -Name $DriveLetter -PSProvider FileSystem).Free
Write-Output $freeAfter

Write-Output "---REMEDIATION_RESULT---"
if ($null -eq $freeAfter) {
    Write-Output "status=failed reason=`"could not read free space on $Mount after cleanup`""
    exit 1
} elseif ($freeAfter -ge $TargetFreeBytes) {
    Write-Output "status=success mount=$Mount free_bytes_after=$freeAfter"
    exit 0
} else {
    Write-Output "status=failed reason=`"only $freeAfter bytes free on $Mount, target is $TargetFreeBytes`" mount=$Mount free_bytes_after=$freeAfter"
    exit 1
}
"""

_RESULT_LINE_RE = re.compile(
    r"status=(?P<status>success|failed)"
    r"(?:\s+reason=\"(?P<reason>[^\"]*)\")?"
    r"(?:\s+mount=(?P<mount>\S+))?"
    r"(?:\s+free_bytes_after=(?P<free_bytes>\d+))?"
)


def parse_remediation_result(stdout: str) -> dict:
    """Pulls the structured status= line out of either script's
    ---REMEDIATION_RESULT--- block. Returns {"status": "failed", "reason":
    "no result block found"} if the marker is missing entirely (e.g. the
    script crashed before reaching it) - a missing result is a failure,
    never silently treated as success."""
    if RESULT_MARKER not in stdout:
        return {"status": "failed", "reason": "no result block found in Run Command output"}

    after_marker = stdout.split(RESULT_MARKER, 1)[1]
    for line in after_marker.splitlines():
        m = _RESULT_LINE_RE.search(line)
        if m:
            result = {"status": m.group("status")}
            if m.group("reason"):
                result["reason"] = m.group("reason")
            if m.group("mount"):
                result["mount"] = m.group("mount")
            if m.group("free_bytes"):
                result["free_bytes_after"] = int(m.group("free_bytes"))
            return result
    return {"status": "failed", "reason": "result block present but no status= line found"}
