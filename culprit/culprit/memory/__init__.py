"""Agent memory for Culprit, on mem0 - with the write path kept in Culprit's
own hands.

    store     the one place mem0 is called: remember / recall / forget /
              explain, self-hosted only (store.py)
    episodic  Culprit's one kind of memory: a confirmed-correct RCA verdict
              becomes an exemplar for the next similar cluster; a later
              "wrong" verdict forgets it (episodic.py)

Ported from the platform's `test` branch (`shared/src/memory/`,
`docs/proposals/CATALYST_agent_memory.md`, QAI-92..101) and cut down to the
one kind of memory that matches Culprit's own core loop: "every RCA an
engineer confirms becomes a retrieval target for the next cycle" (Culprit's
own proposal, Section 7). Deliberately NOT ported: the generic outcome
ledger (Culprit already has one - the Verdict/VerdictRecord table verdicts
are submitted to, see db/repository.py), facts and lessons (Culprit's rule
engine and recurrence tracking already cover the same ground in code, not
in a prompt file there's no equivalent of here), preferences (no per-user
tone customization surface in Culprit's RCA output), and graph memory / the
MCP server (both optional stretch stories even in the original design).

Off by default (`CULPRIT_MEMORY_ENABLED`) and a graceful no-op even when on
if the optional `culprit[memory]` extra (mem0ai + sentence-transformers)
isn't installed - see `culprit/api/deps.py::get_retrieval_store`. Importing
this package imports nothing heavy; `store` pulls in mem0 only on first use.
"""
from __future__ import annotations

from importlib import import_module

__all__ = ["store", "episodic"]


def __getattr__(name: str):
    if name in __all__:
        return import_module(f"{__name__}.{name}")
    raise AttributeError(name)
