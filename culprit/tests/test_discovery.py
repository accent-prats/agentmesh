from __future__ import annotations

from types import SimpleNamespace

import pytest

from culprit.models.evidence import OSFamily
from culprit.pipeline.discovery import (
    _MAX_PREFLIGHT_PAGES,
    _extract_vm_ids,
    _fallback_identity,
    _machines_from_rows,
    _os_family_from_type,
    _quote_ids,
    discover_all_machines,
    discover_all_patch_outcomes,
    discover_failed_machines,
)


def test_extract_vm_ids_pulls_the_field_and_drops_blanks():
    rows = [{"vmId": "/subscriptions/s/.../vm-1"}, {"vmId": ""}, {"vmId": "/subscriptions/s/.../vm-2"}]
    assert _extract_vm_ids(rows) == ["/subscriptions/s/.../vm-1", "/subscriptions/s/.../vm-2"]


def test_os_family_from_type():
    assert _os_family_from_type("Windows") == OSFamily.WINDOWS
    assert _os_family_from_type("Linux") == OSFamily.LINUX
    assert _os_family_from_type("linux") == OSFamily.LINUX  # case-insensitive
    assert _os_family_from_type(None) == OSFamily.UNKNOWN
    assert _os_family_from_type("BSD") == OSFamily.UNKNOWN


def test_machines_from_rows_builds_machine_identity():
    rows = [
        {
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
            "name": "vm-1",
            "resourceGroup": "rg",
            "subscriptionId": "s",
            "osType": "Linux",
            "tags": {"env": "prod"},
        }
    ]
    machines = _machines_from_rows(rows)
    assert len(machines) == 1
    m = machines[0]
    assert m.vm_name == "vm-1"
    assert m.resource_group == "rg"
    assert m.subscription_id == "s"
    assert m.os_family == OSFamily.LINUX
    assert m.tags == {"env": "prod"}


def test_machines_from_rows_handles_missing_tags():
    rows = [{"id": "id", "name": "n", "resourceGroup": "rg", "subscriptionId": "s", "osType": None}]
    machines = _machines_from_rows(rows)
    assert machines[0].tags == {}
    assert machines[0].os_family == OSFamily.UNKNOWN


def test_quote_ids_for_kql_in_clause():
    assert _quote_ids(["a", "b"]) == "'a', 'b'"
    assert _quote_ids([]) == ""


# ── discover_all_machines pagination ───────────────────────────────────────
# Resource Graph's real skip_token contract, faked at the ResourceGraphClient
# boundary (same fakes-not-real-SDK-calls rule the rest of this suite
# follows for Azure/Datadog) - discover_all_machines used to silently
# truncate at one page (1000 rows); these pin the fix.

def _row(name: str) -> dict:
    return {
        "id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}",
        "name": name, "resourceGroup": "rg", "subscriptionId": "s", "osType": "Linux", "tags": {},
    }


def _fake_resource_graph_client(pages: list[dict]):
    """`pages[i]` is served on the i-th call to `.resources()`; any call
    past the end of `pages` gets an empty, skip_token-less page (a safety
    net so a test's fake never has to enumerate every call the loop
    guard - `_MAX_PREFLIGHT_PAGES` - could theoretically make)."""

    class FakeResourceGraphClient:
        instances: list["FakeResourceGraphClient"] = []

        def __init__(self, credential):
            self.credential = credential
            self.calls: list = []
            FakeResourceGraphClient.instances.append(self)

        def resources(self, request):
            idx = len(self.calls)
            self.calls.append(request)
            page = pages[idx] if idx < len(pages) else {"data": [], "skip_token": None}
            return SimpleNamespace(data=page["data"], skip_token=page.get("skip_token"))

    return FakeResourceGraphClient


def test_discover_all_machines_returns_everything_on_a_single_page(monkeypatch):
    pytest.importorskip("azure.mgmt.resourcegraph")  # optional `culprit[azure]` extra - see pyproject.toml
    fake_cls = _fake_resource_graph_client([{"data": [_row("vm-1"), _row("vm-2")], "skip_token": None}])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    machines = discover_all_machines(credential=object(), subscription_ids=["sub-1"])

    assert [m.vm_name for m in machines] == ["vm-1", "vm-2"]
    assert len(fake_cls.instances[0].calls) == 1


def test_discover_all_machines_follows_skip_token_across_pages(monkeypatch):
    pytest.importorskip("azure.mgmt.resourcegraph")
    fake_cls = _fake_resource_graph_client([
        {"data": [_row("vm-1"), _row("vm-2")], "skip_token": "page-2-token"},
        {"data": [_row("vm-3")], "skip_token": None},
    ])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    machines = discover_all_machines(credential=object(), subscription_ids=["sub-1"])

    assert [m.vm_name for m in machines] == ["vm-1", "vm-2", "vm-3"]
    calls = fake_cls.instances[0].calls
    assert len(calls) == 2
    # The second request must actually carry the first page's skip_token
    # forward - the whole point of the fix.
    assert calls[0].options.skip_token is None
    assert calls[1].options.skip_token == "page-2-token"


def test_discover_all_machines_stops_at_the_page_guard_rather_than_looping_forever(monkeypatch):
    """A client that (erroneously, or under test) always hands back a
    skip_token must not turn this into an infinite loop."""
    pytest.importorskip("azure.mgmt.resourcegraph")

    class AlwaysMoreClient:
        instances: list["AlwaysMoreClient"] = []

        def __init__(self, credential):
            self.calls: list = []
            AlwaysMoreClient.instances.append(self)

        def resources(self, request):
            self.calls.append(request)
            return SimpleNamespace(data=[], skip_token="always-another-page")

    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", AlwaysMoreClient)

    discover_all_machines(credential=object(), subscription_ids=["sub-1"])

    assert len(AlwaysMoreClient.instances[0].calls) == _MAX_PREFLIGHT_PAGES


# ── discover_all_patch_outcomes pagination ─────────────────────────────────
# Found in review (the Patch Installation Report feature): this query used
# to cap at one page (1000 rows) with no skip_token follow-up, unlike
# discover_all_machines above - any subscription with more than 1000
# machines posting a result in the window had the overflow silently
# vanish, then get misattributed to "Excluded" by the report's own count
# formula. Same fakes-not-real-SDK-calls rule, same pagination test shape.

def _outcome_row(vm_id: str, status: str = "Succeeded") -> dict:
    return {"vmId": vm_id, "status": status, "startDateTime": "2026-09-26T04:00:00Z", "lastModifiedDateTime": "2026-09-26T04:10:00Z"}


def test_discover_all_patch_outcomes_follows_skip_token_across_pages(monkeypatch):
    pytest.importorskip("azure.mgmt.resourcegraph")
    fake_cls = _fake_resource_graph_client([
        {"data": [_outcome_row("vm-1"), _outcome_row("vm-2")], "skip_token": "page-2-token"},
        {"data": [_outcome_row("vm-3")], "skip_token": None},
    ])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    outcomes = discover_all_patch_outcomes(
        credential=object(), subscription_ids=["sub-1"],
        window_start=datetime(2026, 9, 26, tzinfo=timezone.utc), window_end=datetime(2026, 9, 27, tzinfo=timezone.utc),
    )

    assert {o[0] for o in outcomes} == {"vm-1", "vm-2", "vm-3"}
    calls = fake_cls.instances[0].calls
    assert len(calls) == 2
    assert calls[0].options.skip_token is None
    assert calls[1].options.skip_token == "page-2-token"


# ── discover_failed_machines resilience ────────────────────────────────────
# Found 2026-10-16: a vmId _FAILED_MACHINES_QUERY found but the
# _VM_DETAILS_QUERY join didn't return a row for (a casing mismatch between
# the two Resource Graph tables' own `id` columns, or the VM having been
# deleted/renamed/moved since it posted its patch result) used to be
# silently dropped, taking a genuinely-failed machine out of the deep-RCA
# pipeline with no error at all. These pin the fix: discover_failed_machines
# must resolve every vmId _FAILED_MACHINES_QUERY returns, one way or another.

def _two_call_fake_client(failed_rows: list[dict], details_rows: list[dict]):
    """A fixed two-page fake: call 1 (the _FAILED_MACHINES_QUERY) gets
    `failed_rows`, call 2 (the _VM_DETAILS_QUERY join) gets `details_rows`
    - simpler than the generic `_fake_resource_graph_client` above since
    discover_failed_machines always issues exactly two calls, never pages."""
    return _fake_resource_graph_client([
        {"data": failed_rows, "skip_token": None},
        {"data": details_rows, "skip_token": None},
    ])


def test_discover_failed_machines_issues_a_case_insensitive_resource_graph_join(monkeypatch):
    """Found in review (2026-10-16): the other new tests here prove the
    Python-level `.lower()` lookup and the vmId-parsing fallback are both
    load-bearing, but none of them inspect the actual KQL text sent to
    Resource Graph - the fake client returns its canned `details_rows`
    regardless of the query string, so reverting `in~` back to `in` in
    _VM_DETAILS_QUERY left every other test here green. This asserts on
    the literal query text itself, so that specific regression - the
    literal root-cause fix named in this change - has real coverage."""
    pytest.importorskip("azure.mgmt.resourcegraph")
    fake_cls = _two_call_fake_client(failed_rows=[{"vmId": "/subscriptions/s/.../vm-1"}], details_rows=[])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    discover_failed_machines(
        credential=object(), subscription_ids=["sub-1"],
        window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
    )

    details_query = fake_cls.instances[0].calls[1].query
    assert "where id in~ (" in details_query
    assert "where id in (" not in details_query  # would also match "in~ (" via substring - checked separately above


def test_discover_failed_machines_resolves_a_casing_mismatch_between_the_two_tables(monkeypatch):
    """Two vmIds from step 1: `vm-a` (resolved, but the Resources row's own
    `id` comes back in *different* casing than the vmId extracted from
    patchinstallationresources - realistic for `in~`, which matches
    case-insensitively but is free to return its own stored casing) and
    `vm-b` (genuinely unresolved - no row at all). This is the test that
    actually exercises the `.lower()`-keyed lookup, not just the fallback
    path: vm-a must be recognized as resolved and get its *real* identity
    (Windows, real tags) despite the casing difference - a case-sensitive
    lookup would wrongly treat it as unresolved too and hand it the
    impoverished OSFamily.UNKNOWN fallback identity instead, exactly like
    vm-b's genuinely-missing case. Asserting vm-a's OS/tags are the real
    ones (not the fallback's empty/UNKNOWN ones) is what pins this."""
    pytest.importorskip("azure.mgmt.resourcegraph")
    vm_id_a = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM-A"
    row_id_a = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
    vm_id_b = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b"
    fake_cls = _two_call_fake_client(
        failed_rows=[{"vmId": vm_id_a}, {"vmId": vm_id_b}],
        # Only vm-a comes back, and in different casing than vm_id_a - vm-b
        # has no row at all (genuinely gone).
        details_rows=[{
            "id": row_id_a, "name": "vm-a", "resourceGroup": "rg", "subscriptionId": "s",
            "osType": "Windows", "tags": {"env": "prod"},
        }],
    )
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    machines = discover_failed_machines(
        credential=object(), subscription_ids=["sub-1"],
        window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
    )

    assert len(machines) == 2
    by_name = {m.vm_name: m for m in machines}
    # vm-a was actually resolved (despite the casing difference) - it must
    # carry its *real* identity, not the fallback's impoverished one.
    assert by_name["vm-a"].os_family == OSFamily.WINDOWS
    assert by_name["vm-a"].tags == {"env": "prod"}
    # vm-b was genuinely never resolved - the fallback identity.
    assert by_name["vm-b"].os_family == OSFamily.UNKNOWN
    assert by_name["vm-b"].tags == {}


def test_discover_failed_machines_falls_back_when_the_vm_resource_is_gone(monkeypatch):
    pytest.importorskip("azure.mgmt.resourcegraph")
    resolved_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-resolved"
    gone_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-gone"
    fake_cls = _two_call_fake_client(
        failed_rows=[{"vmId": resolved_id}, {"vmId": gone_id}],
        # Only the resolved VM comes back from the Resources join - vm-gone
        # has no row, simulating a deleted/renamed/moved resource.
        details_rows=[{
            "id": resolved_id, "name": "vm-resolved", "resourceGroup": "rg", "subscriptionId": "s",
            "osType": "Windows", "tags": {},
        }],
    )
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    machines = discover_failed_machines(
        credential=object(), subscription_ids=["sub-1"],
        window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
    )

    assert len(machines) == 2
    by_name = {m.vm_name: m for m in machines}
    assert by_name["vm-resolved"].os_family == OSFamily.WINDOWS
    gone = by_name["vm-gone"]
    assert gone.vm_id == gone_id
    assert gone.resource_group == "rg"
    assert gone.subscription_id == "s"
    assert gone.os_family == OSFamily.UNKNOWN
    assert gone.tags == {}


def test_discover_failed_machines_drops_a_non_standard_vm_id_with_a_warning(monkeypatch, caplog):
    pytest.importorskip("azure.mgmt.resourcegraph")
    weird_id = "/subscriptions/s/providers/Microsoft.HybridCompute/machines/arc-box"  # not the VM-ARM-id shape
    fake_cls = _two_call_fake_client(failed_rows=[{"vmId": weird_id}], details_rows=[])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    with caplog.at_level("WARNING"):
        machines = discover_failed_machines(
            credential=object(), subscription_ids=["sub-1"],
            window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
        )

    assert machines == []
    assert any(weird_id in record.message for record in caplog.records)


def test_fallback_identity_parses_the_vm_id_with_unknown_os():
    vm_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"
    machine = _fallback_identity(vm_id)
    assert machine is not None
    assert machine.vm_name == "vm-1"
    assert machine.resource_group == "rg"
    assert machine.subscription_id == "s"
    assert machine.os_family == OSFamily.UNKNOWN
    assert machine.tags == {}


def test_fallback_identity_returns_none_for_a_non_standard_id():
    assert _fallback_identity("/subscriptions/s/providers/Microsoft.HybridCompute/machines/arc-box") is None


# ── Tracing (2026-10-17: extended the same discipline added to the RCA
# provider path to every real Resource Graph call here too) ─────────────────

def test_discover_failed_machines_logs_progress_at_each_step(monkeypatch, caplog):
    fake_cls = _two_call_fake_client(
        failed_rows=[{"vmId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"}],
        details_rows=[{
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
            "name": "vm-1", "resourceGroup": "rg", "subscriptionId": "s", "osType": "Linux", "tags": {},
        }],
    )
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    from datetime import datetime, timezone

    with caplog.at_level("INFO"):
        discover_failed_machines(
            credential=object(), subscription_ids=["sub-1"],
            window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
        )

    messages = [r.message for r in caplog.records]
    assert any("querying failed machines" in m for m in messages)
    assert any("1 candidate vmId" in m for m in messages)
    assert any("1 of 1 vmId" in m and "resolved" in m for m in messages)


def test_discover_failed_machines_logs_a_warning_and_still_raises_on_a_real_query_failure(monkeypatch, caplog):
    """The most important property of this tracing: it must be purely
    observational. A try/except that logs and re-raises can accidentally
    swallow or replace the original exception - this pins that the exact
    same exception keeps propagating, same discipline already proven for
    the RCA-provider call sites."""
    class ExplodingClient:
        def __init__(self, credential):
            pass

        def resources(self, request):
            raise RuntimeError("Resource Graph is unavailable")

    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", ExplodingClient)

    from datetime import datetime, timezone

    with caplog.at_level("WARNING"):
        try:
            discover_failed_machines(
                credential=object(), subscription_ids=["sub-1"],
                window_start=datetime(2026, 10, 16, tzinfo=timezone.utc), window_end=datetime(2026, 10, 17, tzinfo=timezone.utc),
            )
            raised = None
        except RuntimeError as exc:
            raised = exc

    assert raised is not None and str(raised) == "Resource Graph is unavailable"
    assert any(
        r.levelname == "WARNING" and "failed-machines query failed" in r.message and "RuntimeError" in r.message
        for r in caplog.records
    )


def test_discover_all_machines_logs_total_rows_and_pages(monkeypatch, caplog):
    pytest.importorskip("azure.mgmt.resourcegraph")
    fake_cls = _fake_resource_graph_client([
        {"data": [_row("vm-1"), _row("vm-2")], "skip_token": "page-2"},
        {"data": [_row("vm-3")], "skip_token": None},
    ])
    monkeypatch.setattr("azure.mgmt.resourcegraph.ResourceGraphClient", fake_cls)

    with caplog.at_level("INFO"):
        discover_all_machines(credential=object(), subscription_ids=["sub-1"])

    messages = [r.message for r in caplog.records]
    assert any("3 row(s) across 2 page(s)" in m for m in messages)
