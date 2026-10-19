"""Coverage for observability.py::safe_exc_summary - the shared helper
every new 2026-10-17 tracing call site (discovery.py, azure_control_plane.py,
azure_monitor.py, guest_windows.py, guest_linux.py) uses to log *what* an
exception was without risking a secret leak through it."""
from __future__ import annotations

import logging

import httpx

from culprit.observability import RedactSensitiveQueryParamsFilter, safe_exc_summary


def test_plain_exception_is_just_its_class_name():
    assert safe_exc_summary(TimeoutError("gateway never responded")) == "TimeoutError"


def test_http_status_error_includes_the_status_code():
    request = httpx.Request("GET", "https://example.invalid")
    response = httpx.Response(503, request=request)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        assert safe_exc_summary(exc) == "HTTPStatusError(status=503)"
    else:
        raise AssertionError("expected raise_for_status to raise")


def test_never_returns_str_exc_even_when_the_exception_embeds_a_secret():
    """The whole reason this helper exists: httpx.HTTPStatusError's own
    __str__ embeds the full request URL, which can carry a real secret in
    its query string for some providers (shared/src/llm/gemini.py). Proves
    the real secret is nowhere in the returned summary, no matter what
    str(exc) itself would have contained."""
    secret_url = "https://api.example.com/v1/chat?key=AIzaSecretDontLogMe"
    request = httpx.Request("POST", secret_url)
    response = httpx.Response(401, request=request)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        assert "AIzaSecretDontLogMe" in str(exc)  # sanity check: confirms the exception really does embed it
        summary = safe_exc_summary(exc)
        assert "AIzaSecretDontLogMe" not in summary
        assert summary == "HTTPStatusError(status=401)"
    else:
        raise AssertionError("expected raise_for_status to raise")


class TestRedactSensitiveQueryParamsFilter:
    """Found 2026-10-19 from a real deployment's own logs: uvicorn's access
    logger printed a real Portal SSO JWT in plaintext, in full, via the
    one-time `?auth_token=<jwt>` handoff (api/auth_middleware.py). Shapes
    these tests directly around uvicorn's own real access-log call (one
    positional %s per field, the raw path+query string as one of them) -
    not an invented log shape - so this is proven against what the access
    logger actually does, not just against the filter's own API."""

    def _logger_with_filter(self, caplog):
        logger = logging.getLogger("test_uvicorn_access_filter")
        logger.addFilter(RedactSensitiveQueryParamsFilter())
        caplog.set_level(logging.INFO, logger="test_uvicorn_access_filter")
        return logger

    def test_the_real_jwt_never_reaches_the_log_record(self, caplog):
        logger = self._logger_with_filter(caplog)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.secretSig"
        # Exact shape of uvicorn's own access-log call: one positional %s per
        # field, the raw request path (query string included) as one arg.
        logger.info('%s - "%s %s HTTP/%s" %d', "172.18.0.2:37542", "GET", f"/?auth_token={jwt}", "1.1", 200)

        assert len(caplog.records) == 1
        rendered = caplog.records[0].getMessage()
        assert jwt not in rendered
        assert "auth_token=[REDACTED]" in rendered

    def test_other_query_params_on_the_same_request_survive(self, caplog):
        """The redaction must be surgical - a deep-link's own query params
        (e.g. ?run_id=... alongside the one-time ?auth_token=...) are not
        secrets and are useful for debugging; only the sensitive one goes."""
        logger = self._logger_with_filter(caplog)
        logger.info('%s - "%s %s HTTP/%s" %d', "172.18.0.2:1", "GET", "/?run_id=live-123&auth_token=abc.def.ghi", "1.1", 200)

        rendered = caplog.records[0].getMessage()
        assert "run_id=live-123" in rendered
        assert "auth_token=[REDACTED]" in rendered
        assert "abc.def.ghi" not in rendered

    def test_a_request_with_no_sensitive_param_is_unchanged(self, caplog):
        logger = self._logger_with_filter(caplog)
        logger.info('%s - "%s %s HTTP/%s" %d', "172.18.0.2:1", "GET", "/runs/live-20261019/report.html", "1.1", 200)

        assert caplog.records[0].getMessage() == '172.18.0.2:1 - "GET /runs/live-20261019/report.html HTTP/1.1" 200'
