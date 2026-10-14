"""Finds which machines actually need diagnosing in a live run.

Two Resource Graph queries: one for the distinct VM ids with a non-
succeeded patch result in the window, one to fetch those VMs' identity
details (name, resource group, OS family). The parsing of each query's
rows into `MachineIdentity` objects is split into pure functions
(`_extract_vm_ids`, `_machines_from_rows`) so they're unit-tested against
fixture rows without needing a live Resource Graph call - the same split
used for the guest log parsers in collectors/guest_linux.py and
guest_windows.py.

A live run approximates "one maintenance run" as "everything that failed
in this subscription within the given window" rather than resolving one
specific `maintenanceresources` run id - simpler, and correct for the
common case of one scheduled window per subscription; a deployment with
multiple concurrent maintenance configurations per subscription would
want to scope this further (e.g. by resource group or tag), which is a
straightforward extension of `_FAILED_MACHINES_QUERY` below, not a
different architecture.
"""
from __future__ import annotations

import re
from datetime import datetime

from culprit.models.evidence import MachineIdentity, OSFamily

_MAX_MACHINES_PER_RUN = 200  # sane cap so a live run can't accidentally fan out across an entire estate

_FAILED_MACHINES_QUERY = """
patchinstallationresources
| where type =~ 'microsoft.compute/virtualmachines/patchinstallationresults'
| where properties.status !in ('Succeeded')
| where properties.startDateTime >= datetime('{window_start}')
| where properties.startDateTime <= datetime('{window_end}')
| extend vmId = tostring(split(id, '/patchInstallationResults/')[0])
| distinct vmId
| limit {limit}
"""

_VM_DETAILS_QUERY = """
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| where id in ({vm_ids})
| project id, name, resourceGroup, subscriptionId, osType = tostring(properties.storageProfile.osDisk.osType), tags
"""


def _extract_vm_ids(rows: list[dict]) -> list[str]:
    return [r["vmId"] for r in rows if r.get("vmId")]


def _os_family_from_type(os_type: str | None) -> OSFamily:
    if not os_type:
        return OSFamily.UNKNOWN
    lowered = os_type.lower()
    if lowered == "windows":
        return OSFamily.WINDOWS
    if lowered == "linux":
        return OSFamily.LINUX
    return OSFamily.UNKNOWN


def _machines_from_rows(rows: list[dict]) -> list[MachineIdentity]:
    machines = []
    for r in rows:
        machines.append(
            MachineIdentity(
                vm_id=r["id"],
                vm_name=r["name"],
                resource_group=r["resourceGroup"],
                subscription_id=r["subscriptionId"],
                os_family=_os_family_from_type(r.get("osType")),
                tags=r.get("tags") or {},
            )
        )
    return machines


def _quote_ids(vm_ids: list[str]) -> str:
    from culprit.security.kql import escape_kql_string

    return ", ".join(f"'{escape_kql_string(vid)}'" for vid in vm_ids)


def discover_failed_machines(
    credential,
    subscription_ids: list[str],
    window_start: datetime,
    window_end: datetime,
) -> list[MachineIdentity]:
    """Live Resource Graph lookup - the two queries above, run for real.
    Returns [] (rather than raising) if nothing failed in the window, so
    callers can report a clean "nothing to diagnose" instead of an error."""
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    client = ResourceGraphClient(credential)

    failed_query = _FAILED_MACHINES_QUERY.format(
        window_start=window_start.isoformat(), window_end=window_end.isoformat(), limit=_MAX_MACHINES_PER_RUN
    )
    failed_result = client.resources(QueryRequest(subscriptions=subscription_ids, query=failed_query))
    vm_ids = _extract_vm_ids(failed_result.data or [])
    if not vm_ids:
        return []

    details_query = _VM_DETAILS_QUERY.format(vm_ids=_quote_ids(vm_ids))
    details_result = client.resources(QueryRequest(subscriptions=subscription_ids, query=details_query))
    return _machines_from_rows(details_result.data or [])


_COUNT_QUERY = "Resources | where type =~ 'microsoft.compute/virtualmachines' | count"


def count_total_machines(credential, subscription_ids: list[str]) -> int:
    """Fleet size for the report's `total_machines` denominator - a
    separate query from `discover_failed_machines` since it needs every
    VM, not just the failed ones."""
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest

    client = ResourceGraphClient(credential)
    result = client.resources(QueryRequest(subscriptions=subscription_ids, query=_COUNT_QUERY))
    rows = result.data or []
    return int(rows[0]["Count"]) if rows else 0


_ALL_MACHINES_QUERY = """
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id, name, resourceGroup, subscriptionId, osType = tostring(properties.storageProfile.osDisk.osType), tags
"""

# Resource Graph's own hard cap on rows returned by a single *page* (not a
# judgment call like _MAX_MACHINES_PER_RUN above) - paged over below via
# QueryRequestOptions.skip_token, not a KQL `limit` (that would cap the
# query's total result set, not just one page of it).
_RESOURCE_GRAPH_MAX_PAGE_SIZE = 1000

# A hard ceiling on how many pages discover_all_machines will follow a
# skip_token for, purely as a runaway-loop guard against a misbehaving or
# mocked client that never stops returning one - 500 pages is 500,000
# machines at the page size above, far past any real fleet this estate-wide
# scan is meant to cover.
_MAX_PREFLIGHT_PAGES = 500


# Every patch result in the window, not just non-succeeded ones (unlike
# _FAILED_MACHINES_QUERY above) - the Patch Installation Report's own
# full-fleet view (models/installation_report.py). Field names
# (status/startDateTime/lastModifiedDateTime) match the real
# patchinstallationresources shape already proven out in
# collectors/azure_control_plane.py::_outcome_from_install_result - that
# function's own `status=props.get("status", "Unknown")` default is what
# "Unresponsive or Shutdown" (this report's label for a VM that never
# posted a result) maps from.
#
# `summarize arg_max(startDateTime, *) by vmId` collapses a VM touched
# more than once in the same window (a retried install, overlapping
# maintenance configs) down to its single latest result - found in
# review: without this, _rows_to_outcomes/build_installation_report
# would see two rows for one vmId and double-count that machine in the
# report's totals. startDateTime stays a plain ISO-8601 *string* (not
# todatetime()) deliberately - ISO-8601's own lexical order already
# matches chronological order, so arg_max's string comparison picks the
# right row without a type conversion.
_ALL_PATCH_RESULTS_QUERY = """
patchinstallationresources
| where type =~ 'microsoft.compute/virtualmachines/patchinstallationresults'
| where properties.startDateTime >= datetime('{window_start}')
| where properties.startDateTime <= datetime('{window_end}')
| extend vmId = tostring(split(id, '/patchInstallationResults/')[0])
| project vmId, status = tostring(properties.status),
    startDateTime = tostring(properties.startDateTime), lastModifiedDateTime = tostring(properties.lastModifiedDateTime)
| summarize arg_max(startDateTime, *) by vmId
"""


def _rows_to_outcomes(rows: list[dict]) -> list[tuple[str, str, str | None, str | None]]:
    """Pure parser (vm_id, status, started_at_iso, ended_at_iso) - fixture-
    testable without a live Resource Graph call, same split as
    `_extract_vm_ids`/`_machines_from_rows` above. Also de-dupes by
    vm_id client-side (keeping the row with the latest startDateTime) -
    defense in depth under the query's own `arg_max ... by vmId`
    (found in review: a second caller, or a KQL change that loses that
    summarize, must not silently reintroduce a double-counted machine)."""
    seen: dict[str, tuple[str, str, str | None, str | None]] = {}
    for r in rows:
        vm_id = r.get("vmId")
        if not vm_id:
            continue
        outcome = (vm_id, r.get("status") or "Unknown", r.get("startDateTime"), r.get("lastModifiedDateTime"))
        existing = seen.get(vm_id)
        if existing is None or (outcome[2] or "") > (existing[2] or ""):
            seen[vm_id] = outcome
    return list(seen.values())


def discover_all_patch_outcomes(
    credential,
    subscription_ids: list[str],
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[str, str, str | None, str | None]]:
    """Live Resource Graph lookup for the Patch Installation Report's
    full-fleet view - every machine that posted *any* patch result in the
    window (Succeeded/Failed/Unknown alike), not just the non-succeeded
    ones `discover_failed_machines` returns. Returns raw
    (vm_id, status, started_at_iso, ended_at_iso) tuples - identity
    details (name/resource group/subscription) are joined separately via
    `_VM_DETAILS_QUERY`/`_machines_from_rows`, same two-step shape as
    `discover_failed_machines`, by whichever caller needs them.

    Paginates via `skip_token`, same as `discover_all_machines` - found in
    review: this used to cap at one page (1000 rows) with no skip_token
    follow-up, unlike `discover_all_machines`'s own explicit "instead of
    silently truncating" docstring promise. Any subscription with more
    than 1000 machines posting a result in the window would have had
    everything past the first page vanish from `all_outcomes` entirely,
    and the Excluded-count formula (`total_machines - len(all_outcomes)`)
    then silently folded every one of those real, reported machines into
    "Excluded" - exactly the large-fleet case this report exists for."""
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = ResourceGraphClient(credential)
    query = _ALL_PATCH_RESULTS_QUERY.format(window_start=window_start.isoformat(), window_end=window_end.isoformat())

    rows: list[dict] = []
    skip_token: str | None = None
    for _ in range(_MAX_PREFLIGHT_PAGES):
        options = QueryRequestOptions(top=_RESOURCE_GRAPH_MAX_PAGE_SIZE, skip_token=skip_token)
        result = client.resources(QueryRequest(subscriptions=subscription_ids, query=query, options=options))
        rows.extend(result.data or [])
        skip_token = getattr(result, "skip_token", None)
        if not skip_token:
            break
    return _rows_to_outcomes(rows)


_VM_ID_RE = re.compile(
    r"^/subscriptions/(?P<subscription_id>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)"
    r"/providers/Microsoft\.Compute/virtualMachines/(?P<vm_name>[^/]+)$",
    re.IGNORECASE,
)


def _identity_from_vm_id(vm_id: str) -> dict | None:
    """Parses subscription_id/resource_group/vm_name straight out of the
    VM's own ARM resource id - the standard, fixed
    .../subscriptions/{s}/resourceGroups/{g}/.../virtualMachines/{n}
    shape every Azure VM resource id has. `None` for a vm_id that doesn't
    match it (never seen in practice for a real `patchinstallationresults`
    row, but never crash on one rather than assume)."""
    m = _VM_ID_RE.match(vm_id)
    if not m:
        return None
    return m.groupdict()


def discover_all_patch_outcomes_with_identity(
    credential,
    subscription_ids: list[str],
    window_start: datetime,
    window_end: datetime,
) -> list[dict]:
    """`discover_all_patch_outcomes` plus identity (name/resource_group/
    subscription_id), parsed directly from each outcome's own vm_id via
    `_identity_from_vm_id` - what the Patch Installation Report actually
    needs to build a row. Deliberately NOT a second Resource Graph query
    (a `_VM_DETAILS_QUERY` join, the way `discover_failed_machines` joins
    for osType/tags) - found in review: that join could silently drop a
    machine that posted a real status but whose VM resource no longer
    exists/moved, which the Excluded-count formula
    (`total_machines - len(all_outcomes)`) would then misattribute to
    "Excluded" even though it definitely reported. Parsing the id string
    Culprit already has can't fail that way - a VM patch result's own id
    always carries this shape, no second network round-trip, no lookup
    to miss. Returns one dict per machine: vm_id, vm_name, resource_group,
    subscription_id, status, started_at, ended_at (the latter two parsed
    into datetimes, `None` if missing/unparseable - a status like
    "Unresponsive or Shutdown" legitimately has neither)."""
    outcomes = discover_all_patch_outcomes(credential, subscription_ids, window_start, window_end)

    rows = []
    for vm_id, status, started_at_iso, ended_at_iso in outcomes:
        identity = _identity_from_vm_id(vm_id)
        if identity is None:
            continue  # not a standard VM resource id - shouldn't happen, never crash on it
        rows.append({
            "vm_id": vm_id,
            "vm_name": identity["vm_name"],
            "resource_group": identity["resource_group"],
            "subscription_id": identity["subscription_id"],
            "status": status,
            "started_at": _parse_iso(started_at_iso),
            "ended_at": _parse_iso(ended_at_iso),
        })
    return rows


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def discover_all_machines(credential, subscription_ids: list[str]) -> list[MachineIdentity]:
    """Every in-scope machine, regardless of patch outcome - what the
    pre-flight prediction mode (proposal Section 10) scans, since it's
    checking *current* state ahead of the next window opening rather than
    a completed run's failures. Reuses the same row-parsing helpers as
    `discover_failed_machines`.

    Deliberately does NOT reuse `_MAX_MACHINES_PER_RUN` - that cap exists
    to bound how many *failed* machines one run fans out across (a small
    fraction of a fleet, by design), whereas this is meant to cover the
    *entire* fleet; capping it the same way would silently scan only a
    fraction of the estate for anything bigger than 200 VMs. Follows
    Resource Graph's own skip_token to cover a fleet larger than one page
    (1000 rows) instead of silently truncating it."""
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = ResourceGraphClient(credential)

    rows: list[dict] = []
    skip_token: str | None = None
    for _ in range(_MAX_PREFLIGHT_PAGES):
        options = QueryRequestOptions(top=_RESOURCE_GRAPH_MAX_PAGE_SIZE, skip_token=skip_token)
        result = client.resources(
            QueryRequest(subscriptions=subscription_ids, query=_ALL_MACHINES_QUERY, options=options)
        )
        rows.extend(result.data or [])
        skip_token = getattr(result, "skip_token", None)
        if not skip_token:
            break
    return _machines_from_rows(rows)
