"""api/deps.py::build_live_collectors - the one place every live/scheduled
run's real collector set gets assembled from whatever's saved on
/culprit/settings. Had zero real test coverage before this (every existing
reference, e.g. test_live_run.py, mocks the whole function out rather than
exercising its real dict-composition logic) - found 2026-10-15 while
fixing the exact bug this file's own tests now guard: Datadog used to be
registered unconditionally, so a deployment that never configured it still
got a Datadog-shaped collection_gaps entry on every machine, every run,
indistinguishable from an intermittent real failure."""
from __future__ import annotations

import pytest

pytest.importorskip("datadog_api_client")  # optional `culprit[datadog]` extra, same as test_datadog_auth.py
pytest.importorskip("azure.identity")  # optional `culprit[azure]` extra, same as test_azure_auth.py

from culprit.api.deps import build_live_collectors
from culprit.db import repository
from culprit.db.engine import make_engine, make_session_factory
from culprit.models.evidence import Source
from culprit.models.settings import AzureSettingsInput, DatadogSettingsInput


@pytest.fixture
def session_factory():
    engine = make_engine("sqlite:///:memory:")
    return make_session_factory(engine)


def _save_azure(session_factory, **kwargs):
    with session_factory() as session:
        repository.save_azure_settings(session, AzureSettingsInput(subscription_ids=["sub-1"], **kwargs))


def test_datadog_is_absent_when_nothing_is_configured(session_factory, monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    _save_azure(session_factory)
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.DATADOG_METRIC not in collectors


def test_datadog_is_present_when_an_api_key_is_saved(session_factory, monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    _save_azure(session_factory)
    with session_factory() as session:
        repository.save_datadog_settings(session, DatadogSettingsInput(api_key="an-api-key"))
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.DATADOG_METRIC in collectors


def test_datadog_is_present_via_the_env_var_fallback_alone(session_factory, monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "env-key")
    _save_azure(session_factory)
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.DATADOG_METRIC in collectors


def test_azure_monitor_is_absent_without_a_workspace_id(session_factory):
    """Already-correct, already-untested behavior - covered here too since
    this is the first real test of build_live_collectors' composition at
    all."""
    _save_azure(session_factory)
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.AZURE_MONITOR not in collectors


def test_azure_monitor_is_present_with_a_workspace_id(session_factory):
    _save_azure(session_factory, log_analytics_workspace_id="workspace-1")
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.AZURE_MONITOR in collectors


def test_guest_and_control_plane_collectors_are_always_present(session_factory, monkeypatch):
    monkeypatch.delenv("DD_API_KEY", raising=False)
    _save_azure(session_factory)
    with session_factory() as session:
        collectors, _, _ = build_live_collectors(session)
    assert Source.AZURE_CONTROL_PLANE in collectors
    assert Source.GUEST_LINUX in collectors
    assert Source.GUEST_WINDOWS in collectors
