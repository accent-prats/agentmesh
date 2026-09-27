"""Portal SSO - fixes "if I'm an authentic user of this platform it
should not ask for any other access key" (reported 2026-09-27, right
after the shared-token auth gate shipped). An already-authenticated
Portal user launching Culprit from the AgentMesh launcher carries
`?auth_token=<portal JWT>` on the first navigation; this should be
accepted and converted into a session, never bounced to the unrelated
shared-token login form."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from culprit import config
from culprit.db.engine import make_engine, make_session_factory
from culprit.security.portal_jwt import validate_portal_token

PORTAL_SECRET = "shared-platform-secret"
CULPRIT_TOKEN = "the-culprit-only-shared-token"


def _portal_token(
    app_access: list[str], *, expired: bool = False, token_type: str = "access", role: str = "user"
) -> str:
    exp = datetime.now(timezone.utc) + (timedelta(minutes=-5) if expired else timedelta(minutes=60))
    return jwt.encode(
        {
            "sub": "user-1", "email": "alice@example.com", "role": role,
            "full_name": "Alice", "app_access": app_access, "type": token_type, "exp": exp,
        },
        PORTAL_SECRET, algorithm="HS256",
    )


def test_validate_portal_token_accepts_a_well_formed_grant():
    token = _portal_token(["culprit", "some-other-app"])
    claims = validate_portal_token(token, PORTAL_SECRET)
    assert claims is not None
    assert claims["email"] == "alice@example.com"


def test_validate_portal_token_rejects_wrong_secret():
    token = _portal_token(["culprit"])
    assert validate_portal_token(token, "wrong-secret") is None


def test_validate_portal_token_rejects_expired():
    token = _portal_token(["culprit"], expired=True)
    assert validate_portal_token(token, PORTAL_SECRET) is None


def test_validate_portal_token_rejects_without_culprit_in_app_access():
    """A real, validly-signed Portal token for a user who was never
    granted Culprit access (no "culprit" checkbox in Admin) must not work
    just because they're logged into the platform generally."""
    token = _portal_token(["some-other-app"])
    assert validate_portal_token(token, PORTAL_SECRET) is None


def test_validate_portal_token_accepts_admin_role_even_with_no_culprit_grant():
    """Found 2026-09-27, immediately after the first SSO fix shipped: an
    admin clicking the Culprit card still hit the login wall.
    create_access_token() embeds the user's *raw* app_access DB column
    with no admin bypass - that bypass only exists in apps.py's launcher-
    visibility query - so an admin's own token often has no "culprit"
    entry even though their role lets them see and click the card
    everywhere else in the platform. Mirrors apps.py's exact rule:
    role in ("admin", "ci_service") sees/uses everything."""
    token = _portal_token([], role="admin")  # empty app_access, deliberately
    claims = validate_portal_token(token, PORTAL_SECRET)
    assert claims is not None


def test_validate_portal_token_accepts_ci_service_role_too():
    token = _portal_token(["something-unrelated"], role="ci_service")
    assert validate_portal_token(token, PORTAL_SECRET) is not None


def test_validate_portal_token_still_rejects_expired_admin_tokens():
    """The admin bypass is an authorization shortcut, not a way around
    the token's own expiry/signature checks."""
    token = _portal_token([], role="admin", expired=True)
    assert validate_portal_token(token, PORTAL_SECRET) is None


def test_validate_portal_token_rejects_refresh_tokens():
    token = _portal_token(["culprit"], token_type="refresh")
    assert validate_portal_token(token, PORTAL_SECRET) is None


def test_validate_portal_token_with_no_secret_configured_rejects_everything():
    token = _portal_token(["culprit"])
    assert validate_portal_token(token, "") is None


@pytest.fixture
def client(monkeypatch):
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(
        config, "settings", config.Settings(api_token=CULPRIT_TOKEN, portal_jwt_secret=PORTAL_SECRET)
    )

    from culprit.api.main import app

    return TestClient(app, follow_redirects=False)


def test_valid_portal_launch_link_is_let_straight_through_no_login_wall(client):
    token = _portal_token(["culprit"])
    resp = client.get(f"/?auth_token={token}", headers={"accept": "text/html"})
    assert resp.status_code == 200
    assert "culprit_session" in resp.cookies


def test_the_cookie_it_sets_then_authenticates_subsequent_requests(client):
    token = _portal_token(["culprit"])
    launch = client.get(f"/settings?auth_token={token}", headers={"accept": "text/html"})
    session_cookie = launch.cookies["culprit_session"]

    # A later request (e.g. the settings page's own fetch() call) carries
    # only the cookie, no query string - this is the part that would
    # break without persisting it.
    resp = client.get("/settings/azure", cookies={"culprit_session": session_cookie})
    assert resp.status_code == 200


def test_portal_user_without_culprit_access_still_hits_the_login_wall(client):
    token = _portal_token(["some-other-app"])  # never granted Culprit
    resp = client.get(f"/?auth_token={token}", headers={"accept": "text/html"})
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


def test_expired_portal_token_still_hits_the_login_wall(client):
    token = _portal_token(["culprit"], expired=True)
    resp = client.get(f"/?auth_token={token}", headers={"accept": "text/html"})
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


def test_login_page_get_redirects_away_when_already_portal_authenticated(client):
    token = _portal_token(["culprit"])
    resp = client.get("/login?next=/settings", cookies={"culprit_session": token})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings"


def test_shared_token_login_still_works_alongside_portal_sso(client):
    """Both mechanisms coexist - configuring Portal SSO must not break the
    existing shared-token path for scripts/curl."""
    resp = client.post("/runs/demo", headers={"Authorization": f"Bearer {CULPRIT_TOKEN}"})
    assert resp.status_code == 200


@pytest.fixture
def portal_only_client(monkeypatch):
    """CULPRIT_API_TOKEN unset, only Portal SSO configured - a legitimate
    deployment shape (platform users only, no separate script credential)."""
    import culprit.api.deps as deps_module

    engine = make_engine("sqlite:///:memory:")
    factory = make_session_factory(engine)
    deps_module.get_session_factory.cache_clear()
    monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)
    monkeypatch.setattr(config, "settings", config.Settings(api_token="", portal_jwt_secret=PORTAL_SECRET))

    from culprit.api.main import app

    return TestClient(app, follow_redirects=False)


def test_portal_only_mode_still_gates_unauthenticated_requests(portal_only_client):
    resp = portal_only_client.get("/settings", headers={"accept": "text/html"})
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


def test_portal_only_mode_lets_a_valid_portal_user_through(portal_only_client):
    token = _portal_token(["culprit"])
    resp = portal_only_client.get(f"/?auth_token={token}", headers={"accept": "text/html"})
    assert resp.status_code == 200


# ── sliding-session renewal ─────────────────────────────────────────────────
# Real bug found in review 2026-09-27: the cookie's Max-Age and the JWT
# inside it both hard-expired 60 minutes after the *original* Portal login,
# with nothing renewing either one on activity - an actively-browsing user
# got bounced to the shared-token login screen mid-session, a screen with no
# working recovery path for them (that token is an operator secret).

def test_the_session_cookie_is_renewed_on_every_authenticated_request(client):
    # A deliberately short-lived original token - renewal always grants a
    # fresh full _PORTAL_COOKIE_MAX_AGE_SECONDS window, so starting the
    # original well below that makes the "later" assertion robust even if
    # both requests land within the same wall-clock second (exp is
    # second-precision, so two *full-window* renewals back to back could
    # otherwise tie).
    original_cookie = _portal_token(["culprit"])
    original_cookie = jwt.encode(
        {**jwt.decode(original_cookie, PORTAL_SECRET, algorithms=["HS256"]),
         "exp": datetime.now(timezone.utc) + timedelta(seconds=30)},
        PORTAL_SECRET, algorithm="HS256",
    )

    resp = client.get("/settings/azure", cookies={"culprit_session": original_cookie})
    assert resp.status_code == 200
    renewed_cookie = resp.cookies["culprit_session"]

    original_exp = jwt.decode(original_cookie, PORTAL_SECRET, algorithms=["HS256"])["exp"]
    renewed_exp = jwt.decode(renewed_cookie, PORTAL_SECRET, algorithms=["HS256"])["exp"]
    assert renewed_exp > original_exp


def test_a_renewed_cookie_keeps_authenticating_past_the_original_tokens_lifetime(client):
    """The actual point of renewal, proven end to end: a token that would
    have expired by now still works, because each request along the way
    re-signed a fresh one - not just that *a* Set-Cookie header appears."""
    token = _portal_token(["culprit"], expired=False)
    # A token that's already outside its original window - simulates a
    # long browsing session that kept renewing before this point.
    almost_gone = jwt.encode(
        {**jwt.decode(token, PORTAL_SECRET, algorithms=["HS256"]),
         "exp": datetime.now(timezone.utc) + timedelta(seconds=5)},
        PORTAL_SECRET, algorithm="HS256",
    )
    resp = client.get("/settings/azure", cookies={"culprit_session": almost_gone})
    assert resp.status_code == 200
    renewed_cookie = resp.cookies["culprit_session"]

    renewed_exp = jwt.decode(renewed_cookie, PORTAL_SECRET, algorithms=["HS256"])["exp"]
    assert renewed_exp > (datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()


def test_a_shared_token_cookie_is_never_renewed_with_a_portal_shaped_token(client):
    """The renewal path must only ever fire for a Portal-JWT cookie - the
    shared CULPRIT_API_TOKEN cookie authenticates the same way every
    time it's presented and has no expiry to renew."""
    resp = client.get("/settings/azure", cookies={"culprit_session": CULPRIT_TOKEN})
    assert resp.status_code == 200
    assert "culprit_session" not in resp.cookies


def test_a_bearer_header_request_gets_no_cookie_set_at_all(client):
    """A script authenticating via Authorization: Bearer has no cookie
    jar to benefit from a renewed session cookie - it re-sends its own
    credential every call, so nothing should be set for it."""
    token = _portal_token(["culprit"])
    resp = client.get("/settings/azure", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "culprit_session" not in resp.cookies
