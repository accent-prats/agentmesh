"""culprit/serverless/function_app.py::get_azure_settings_http /
put_azure_settings_http - a stand-in for the Settings screen's own Azure
tab, added because this deployment has no reachable Settings UI at all
(the Console/Settings web UI was explicitly scoped out of the serverless
migration - see function_app.py's own module docstring).

Found live 2026-11-23: configuring the Azure subscription IDs on the
EXISTING Docker Compose deployment's Settings page had zero effect on the
serverless Function App - they're two completely separate databases
(the Docker Compose deployment defaults to a local sqlite file; the
Function App uses its own Postgres instance). These two HTTP routes are
the only way to get real settings into that second database at all right
now, so they're tested directly against the real repository functions
they wrap, not mocked away.

Routed at `settings/azure`, NOT `admin/settings/azure` - a first deploy
under the `admin/` prefix loaded both functions "in error: The specified
route conflicts with one or more built in routes" (confirmed live via
Application Insights the same day) because the Azure Functions host
reserves the whole `admin/*` route prefix for its own built-in management
API, host-wide, regardless of `routePrefix` config. There's no local
Functions host in this test environment to re-trigger that exact
failure, so `test_route_is_not_under_the_reserved_admin_prefix` guards it
statically instead, directly against the source these decorators are
written in.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import azure.functions as func
import pytest

from culprit.db.engine import make_engine, make_session_factory


def _make_request(method: str, body: dict | None) -> func.HttpRequest:
    body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
    return func.HttpRequest(
        method=method,
        url="https://patchrca-fa.azurewebsites.net/api/settings/azure",
        headers={},
        params={},
        route_params={},
        body=body_bytes,
    )


def test_route_is_not_under_the_reserved_admin_prefix():
    from culprit.serverless import function_app

    source = Path(function_app.__file__).read_text()
    routes = re.findall(r'@app\.route\(route="([^"]+)"', source)
    assert routes, "expected at least one @app.route(route=...) in function_app.py"
    for route in routes:
        assert not route.startswith("admin/"), (
            f"route {route!r} is under the reserved admin/* prefix - the "
            "Functions host owns that prefix for its own management API "
            "and will refuse to load a user function routed there"
        )


@pytest.fixture
def session_factory(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    return factory


def test_get_azure_settings_http_returns_the_empty_default_view_when_nothing_is_saved(session_factory):
    from culprit.serverless import function_app

    resp = function_app.get_azure_settings_http(_make_request("GET", None))
    assert resp.status_code == 200
    body = json.loads(resp.get_body())
    assert body["subscription_ids"] == []
    assert body["configured"] is False


def test_put_azure_settings_http_saves_subscription_ids_and_they_are_readable_back(session_factory):
    from culprit.serverless import function_app

    real_subscription_ids = [
        "6304c200-55d2-4081-87f7-7eb92f506ddb",
        "3a081834-818a-4822-8143-f72bd38092d4",
        "8e2583e0-857f-4ae8-84b7-15f570ca0f75",
        "f8138736-0d05-474f-951e-2f3b180c7d50",
    ]
    put_resp = function_app.put_azure_settings_http(
        _make_request("PUT", {"subscription_ids": real_subscription_ids})
    )
    assert put_resp.status_code == 200
    put_body = json.loads(put_resp.get_body())
    assert put_body["subscription_ids"] == real_subscription_ids

    # A completely separate GET call (the next real caller, or a sanity
    # re-check) must see the same thing - proves this actually persisted
    # to the database rather than just echoing the input back.
    get_resp = function_app.get_azure_settings_http(_make_request("GET", None))
    get_body = json.loads(get_resp.get_body())
    assert get_body["subscription_ids"] == real_subscription_ids


def test_put_azure_settings_http_with_malformed_json_returns_400_not_a_crash(session_factory):
    from culprit.serverless import function_app

    req = func.HttpRequest(
        method="PUT",
        url="https://patchrca-fa.azurewebsites.net/api/settings/azure",
        headers={},
        params={},
        route_params={},
        body=b"not valid json",
    )
    resp = function_app.put_azure_settings_http(req)
    assert resp.status_code == 400
