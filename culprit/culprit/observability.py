"""A small, shared logging utility for any module that talks to an
external system (Azure Resource Graph, Azure Monitor, Azure Run Command,
and so on) and wants to log *what* a failure was without risking leaking
a secret through it.

Mirrors the same helper already duplicated independently in
pipeline/rca_agent.py and shared/src/llm/{openai_compatible,gemini}.py -
those three predate this module and stay as they are (no functional
reason to touch already-reviewed, already-deployed code just to
de-duplicate it, and shared/src/llm/ can't import from this package
anyway). This is the one shared home for every *new* caller added after
them, now that there are enough to justify it instead of a fourth, fifth,
sixth independent copy.
"""
from __future__ import annotations

import logging
import re

# The one confirmed real leak (found 2026-10-19 from a real deployment's own
# logs, tcx-tenant): api/auth_middleware.py's one-time Portal SSO handoff
# necessarily carries a real JWT in `?auth_token=<jwt>` on its first
# request, and uvicorn's own access logger (distinct from anything this app
# logs itself - confirmed by grepping the whole app for any other place the
# full request URL/query string is logged, and finding none) prints that
# full URL, token included, in plaintext. Keyed by name rather than a single
# constant so a future sensitive query param can be added here without a new
# regex, but only `auth_token` is a confirmed leak today - nothing else is
# added speculatively.
_SENSITIVE_QUERY_PARAMS = ("auth_token",)
_SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"(" + "|".join(re.escape(p) for p in _SENSITIVE_QUERY_PARAMS) + r")=[^&\s\"']+"
)


class RedactSensitiveQueryParamsFilter(logging.Filter):
    """Install on `uvicorn.access` (see api/main.py) to stop a sensitive
    query-string value from ever reaching that logger's output, in
    plaintext, in every real deployment.

    Rewrites `record.args` rather than `record.msg`: uvicorn's access
    logger formats its line via positional %-style args (client_addr,
    method, full_path, http_version, status_code) - the request's raw
    path, query string included, lives in one of those args, not in the
    literal format string, so redacting `record.msg` alone would do
    nothing. A dict-style `record.args` (not used by uvicorn's access
    logger today, but not guaranteed to stay that way) is left untouched
    rather than guessed at."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                _SENSITIVE_QUERY_PARAM_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", arg)
                if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


def safe_exc_summary(exc: BaseException) -> str:
    """A short, provably-secret-free description of an exception for a log
    line - just the exception class, plus an HTTP status code when one is
    actually available (`httpx.HTTPStatusError.response.status_code`, or
    anything else exposing the same shape). Deliberately never `str(exc)`:
    confirmed empirically (see shared/src/llm/gemini.py's own test suite)
    that `httpx.HTTPStatusError`'s own string representation embeds the
    full request URL, which can carry a real secret in its query string
    for some providers - `str(exc)` on an exception from *any* external
    call is not safe to assume is secret-free, so this stays conservative
    for all of them rather than re-deriving that risk per caller."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status is not None:
        return f"{type(exc).__name__}(status={status})"
    return type(exc).__name__
