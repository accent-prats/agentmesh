"""Fixes /docs (Swagger UI) rendering "Unable to render this definition"
when reverse-proxied under /culprit/ - found 2026-09-27. FastAPI's built-in
docs route embeds an *absolute* openapi_url computed from
`request.scope["root_path"]`; without a root_path, it points at the site
root, which nginx routes to Portal's SPA instead of Culprit."""
from __future__ import annotations

from fastapi.testclient import TestClient

from culprit.api.main import app


def test_docs_openapi_url_is_unprefixed_without_the_header():
    client = TestClient(app)
    resp = client.get("/docs")
    assert resp.status_code == 200
    assert "url: '/openapi.json'" in resp.text


def test_docs_openapi_url_is_prefixed_when_forwarded_prefix_header_present():
    client = TestClient(app)
    resp = client.get("/docs", headers={"X-Forwarded-Prefix": "/culprit"})
    assert resp.status_code == 200
    assert "url: '/culprit/openapi.json'" in resp.text


def test_openapi_json_itself_is_still_served_and_valid_at_the_unprefixed_path():
    client = TestClient(app)
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "openapi" in body  # the exact field Swagger UI complained was missing
