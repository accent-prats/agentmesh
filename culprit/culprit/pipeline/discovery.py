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
