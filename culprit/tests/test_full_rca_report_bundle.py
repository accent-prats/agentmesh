"""Coverage for the "Download full RCA report (zip)" link on the Fleet
Report page - user-requested 2026-11-19, a SEPARATE capability from the
auto-send/manual-send email attachment (see notifications/
auto_report_email.py and api/routes_notifications.py), which stays a
single flat HTML file for email-scanner reasons that don't apply here.
This resurrects the ORIGINAL (pre-2026-11-03) email bundle's exact
multi-page, cross-linked zip design for this new route - see
reporting/report_bundle.py::build_full_rca_report_bundle's own docstring.
"""
from __future__ import annotations

import io
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

from culprit.db.engine import make_engine, make_session_factory


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    from culprit.demo.scripted_rca import ScriptedRCAAgent

    monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())

    from culprit.api.main import app

    return TestClient(app)


@pytest.fixture
def seeded_run_id(client) -> str:
    resp = client.post("/runs/demo")
    assert resp.status_code == 200
    return resp.json()["run"]["run_id"]


def test_full_rca_report_zip_contains_every_page_and_static_asset(client, seeded_run_id):
    report = client.get(f"/runs/{seeded_run_id}/report").json()
    vm_names = {row["vm_name"] for row in report["machine_rows"]}
    assert vm_names, "the demo run's own report has no machine rows to assert against"

    resp = client.get(f"/runs/{seeded_run_id}/full-report.zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = set(zf.namelist())
        assert f"runs/{seeded_run_id}/report.html" in names
        for vm_name in vm_names:
            assert f"runs/{seeded_run_id}/machines/{vm_name}.html" in names
        # Found by review 2026-11-02 against the original version of this
        # same design: a missing lucide.min.js silently breaks every "Show
        # full error/status/timeline" disclosure across every bundled
        # page - both static assets must travel with the bundle, not just
        # the HTML.
        assert "static/tailwind.js" in names
        assert "static/lucide.min.js" in names

        # The bundled Fleet Report page's own relative link to its
        # installation report must resolve to a file this same zip
        # actually contains, the whole point of reproducing the live
        # app's nested folder structure rather than flattening it.
        install_resp = client.get(f"/runs/{seeded_run_id}/installation-report")
        if install_resp.status_code == 200:
            assert f"runs/{seeded_run_id}/installation-report.html" in names
            fleet_html = zf.read(f"runs/{seeded_run_id}/report.html").decode("utf-8")
            assert 'href="installation-report.html"' in fleet_html


def test_full_rca_report_zip_filename_uses_the_run_id_and_a_clean_timestamp(client, seeded_run_id):
    resp = client.get(f"/runs/{seeded_run_id}/full-report.zip")
    assert resp.status_code == 200

    disposition = resp.headers["content-disposition"]
    match = re.search(r'filename="([^"]+)"', disposition)
    assert match, f"no filename in Content-Disposition header: {disposition!r}"
    filename = match.group(1)

    assert filename.startswith(f"{seeded_run_id}_")
    assert filename.endswith(".zip")
    # dd-mm-yy-hh-mm-ss, the same clean, non-raw-repr timestamp convention
    # offline_report_attachment_filename already uses for the email path -
    # not a bare str(datetime) with microseconds.
    assert re.search(r"_\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.zip$", filename)


def test_full_rca_report_zip_404s_for_an_unknown_run(client):
    resp = client.get("/runs/does-not-exist/full-report.zip")
    assert resp.status_code == 404


def test_fleet_report_page_links_to_the_full_rca_report_zip(client, seeded_run_id):
    resp = client.get(f"/runs/{seeded_run_id}/report.html")
    assert resp.status_code == 200
    assert 'href="full-report.zip"' in resp.text
