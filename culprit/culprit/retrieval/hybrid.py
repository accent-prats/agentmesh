"""Combines the always-available vendor-doc store with mem0-backed
episodic memory (culprit/memory/) - only built by api/deps.py::get_retrieval_store
when `CULPRIT_MEMORY_ENABLED=true` and the optional `culprit[memory]` extra
is installed; every other deployment gets the plain `RetrievalStore` and
never imports this module at all.

Vendor documentation stays in the lightweight TF-IDF store deliberately -
it's a small, fixed seed set (culprit/retrieval/corpus.py) that doesn't
grow or need real embeddings to search well. Confirmed RCAs are the part
that grows over months and benefits from mem0's actual similarity search as
the corpus grows - see culprit/memory/episodic.py and the module docstring
there for why only that one kind of memory was ported.
"""
from __future__ import annotations

from culprit.memory import episodic
from culprit.memory.store import MemoryStore
from culprit.models.rca import RCAResult
from culprit.models.verdict import Verdict
from culprit.retrieval.store import RetrievalStore


class HybridRetrievalStore:
    """Same public interface as `RetrievalStore` (`render_context`,
    `add_resolved_incident`, `forget_resolved_incident`), plus
    `remember_verdict` - which `api/routes_verdicts.py` calls only when
    `hasattr(store, "remember_verdict")`, so the plain TF-IDF-only
    deployment path never needs to know this method exists."""

    def __init__(self, vendor_store: RetrievalStore, memory_store: MemoryStore):
        self._vendor = vendor_store
        self._memory = memory_store

    def add(self, doc) -> None:
        self._vendor.add(doc)

    def add_resolved_incident(self, cluster_key: str, title: str, summary: str, tags: list[str]) -> None:
        """Kept for interface parity with `RetrievalStore`, but
        `api/routes_verdicts.py` calls `remember_verdict` instead whenever
        this store is active - writing the same confirmed RCA here too
        would make `render_context()` return it twice (once via this
        store's term overlap, once via mem0's semantic similarity) for any
        query that matches it. Call this directly only if you want the
        vendor-side copy specifically and have already decided that
        duplication is fine for your use case."""
        self._vendor.add_resolved_incident(cluster_key, title, summary, tags)

    def forget_resolved_incident(self, cluster_key: str) -> int:
        removed = self._vendor.forget_resolved_incident(cluster_key)
        episodic.forget(self._memory, cluster_key)
        return removed

    def remember_verdict(self, verdict: Verdict, cluster_key: str, result: RCAResult) -> str | None:
        """The mem0 write - takes the full Verdict/RCAResult objects
        directly (unlike `add_resolved_incident`'s plain-string signature,
        which is fixed by `RetrievalStore`'s existing interface and only
        carries what the TF-IDF side needs)."""
        return episodic.remember(self._memory, verdict, cluster_key, result)

    def search(self, query: str, top_k: int = 5):
        return self._vendor.search(query, top_k=top_k)

    def render_context(self, query: str, top_k: int = 5) -> str:
        vendor_context = self._vendor.render_context(query, top_k=top_k)
        memory_hits = episodic.recall(self._memory, query, k=top_k)
        memory_context = episodic.as_evidence(memory_hits)
        return "\n\n".join(part for part in (vendor_context, memory_context) if part)
