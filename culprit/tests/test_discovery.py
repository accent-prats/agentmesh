from __future__ import annotations

from types import SimpleNamespace

import pytest

from culprit.models.evidence import OSFamily
from culprit.pipeline.discovery import (
    _MAX_PREFLIGHT_PAGES,
    _extract_vm_ids,
    _machines_from_rows,
    _os_family_from_type,
    _quote_ids,
    discover_all_machines,
    discover_all_patch_outcomes,
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
