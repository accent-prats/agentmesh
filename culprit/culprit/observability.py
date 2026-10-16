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
