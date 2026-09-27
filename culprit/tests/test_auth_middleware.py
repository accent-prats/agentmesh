"""RequireApiTokenMiddleware - the fix for "zero authentication anywhere"
found in review. Every existing test in this suite runs with
CULPRIT_API_TOKEN unset (fail-open, by design - see the module docstring
in culprit/api/auth_middleware.py); these tests are the ones that actually
configure a token and verify enforcement."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from culprit import config
from culprit.db.engine import make_engine, make_session_factory

TOKEN = "test-shared-token-abc123"


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

    # Replace the whole frozen Settings instance - config.settings.api_token
    # can't be mutated in place (frozen dataclass), and every consumer reads
    # it via `config.settings.X` at call time (not a bound name import), so
    # swapping the module attribute here is what every route/middleware
    # check actually sees.
    monkeypatch.setattr(config, "settings", config.Settings(api_token=TOKEN))

    from culprit.api.main import app

    return TestClient(app, follow_redirects=False)


@pytest.fixture
def open_client(monkeypatch):
    """Same app, but with no token configured - confirms auth stays fully
    disabled (today's default) rather than accidentally becoming stricter."""
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(config, "settings", config.Settings(api_token=""))

    from culprit.api.main import app

    return TestClient(app, follow_redirects=False)


def test_no_token_configured_leaves_everything_open(open_client):
    assert open_client.get("/").status_code == 200
    assert open_client.get("/settings").status_code == 200
    assert open_client.post("/runs/demo").status_code == 200


def test_unauthenticated_json_request_gets_401(client):
    resp = client.post("/runs/demo")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Unauthorized"}


def test_unauthenticated_html_request_redirects_to_login(client):
    resp = client.get("/settings", headers={"accept": "text/html"})
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?next=")


def test_health_and_login_and_webhook_stay_public(client):
    assert client.get("/health").status_code == 200
    assert client.get("/login").status_code == 200
    resp = client.post(
        "/webhooks/event-grid",
        json=[{"id": "1", "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent", "data": {"validationCode": "abc"}}],
    )
    assert resp.status_code == 200


def test_correct_bearer_token_is_accepted(client):
    resp = client.post("/runs/demo", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


def test_wrong_bearer_token_is_rejected(client):
    resp = client.post("/runs/demo", headers={"Authorization": "Bearer wrong-token"})
    assert resp.status_code == 401


def test_login_flow_sets_a_cookie_that_then_authenticates(client):
    login_resp = client.post("/login", data={"token": TOKEN, "next": "/"})
    assert login_resp.status_code == 303
    assert "culprit_session" in login_resp.cookies

    # The cookie the login response set is what a real browser would carry
    # on the next request - simulate that explicitly rather than relying on
    # TestClient's cookie jar, to prove it's the auth path that matters.
    resp = client.post("/runs/demo", cookies={"culprit_session": login_resp.cookies["culprit_session"]})
    assert resp.status_code == 200


def test_login_with_wrong_token_shows_error_and_sets_no_cookie(client):
    resp = client.post("/login", data={"token": "nope", "next": "/"})
    assert resp.status_code == 401
    assert "culprit_session" not in resp.cookies
    assert "Incorrect token" in resp.text


def test_logout_redirects_to_login_and_clears_the_cookie(client):
    resp = client.get("/logout", cookies={"culprit_session": TOKEN})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    set_cookie = resp.headers.get("set-cookie", "")
    assert "culprit_session=" in set_cookie
    assert ("Max-Age=0" in set_cookie) or ("expires=" in set_cookie.lower())


# ── Reported 2026-09-27: "clicking Culprit takes me to the same screen" ──────
# Every redirect above was correct unprefixed, but hardcoded an *absolute*
# path ("/login", "/") - under nginx's /culprit/ mount, the browser resolves
# that against the site root, landing back on Portal's catch-all instead of
# Culprit. These simulate nginx's X-Forwarded-Prefix header (see
# infrastructure/nginx/conf.d/portal.conf and root_path_middleware.py) to
# prove the whole chain stays under /culprit/ end to end.

_PREFIX_HEADERS = {"X-Forwarded-Prefix": "/culprit"}


def test_unauthenticated_html_request_redirects_under_the_prefix(client):
    resp = client.get("/settings", headers={"accept": "text/html", **_PREFIX_HEADERS})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/culprit/login?next=/settings"


def test_login_page_when_already_authenticated_redirects_under_the_prefix(client):
    resp = client.get("/login?next=/settings", headers={**_PREFIX_HEADERS}, cookies={"culprit_session": TOKEN})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/culprit/settings"


def test_login_submit_redirects_under_the_prefix(client):
    resp = client.post("/login", data={"token": TOKEN, "next": "/settings"}, headers=_PREFIX_HEADERS)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/culprit/settings"
    assert "culprit_session" in resp.cookies


def test_logout_redirects_under_the_prefix(client):
    resp = client.get("/logout", headers=_PREFIX_HEADERS, cookies={"culprit_session": TOKEN})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/culprit/login"


def test_full_redirect_chain_under_the_prefix_never_leaves_culprit(client):
    """The exact scenario reported: click the Culprit card (unauthenticated),
    land on Culprit's own login page (not bounced back to Portal), sign in,
    and land back inside /culprit/ - never once redirected to a bare,
    unprefixed path."""
    step1 = client.get("/", headers={"accept": "text/html", **_PREFIX_HEADERS})
    assert step1.status_code == 303
    assert step1.headers["location"] == "/culprit/login?next=/"

    step2 = client.post("/login", data={"token": TOKEN, "next": "/"}, headers=_PREFIX_HEADERS)
    assert step2.status_code == 303
    assert step2.headers["location"] == "/culprit/"
