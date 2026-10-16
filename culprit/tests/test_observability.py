"""Coverage for observability.py::safe_exc_summary - the shared helper
every new 2026-10-17 tracing call site (discovery.py, azure_control_plane.py,
azure_monitor.py, guest_windows.py, guest_linux.py) uses to log *what* an
exception was without risking a secret leak through it."""
from __future__ import annotations

import httpx

from culprit.observability import safe_exc_summary


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
