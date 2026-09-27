"""A minimal retrieval store over vendor documentation and this
organization's own resolved-incident history (proposal Section 7: "the
organization's own resolved history" is what makes the system compound -
every confirmed RCA becomes a retrieval target for the next cycle).

This implementation is deliberately dependency-light: pure-Python TF-IDF-
style term overlap, no vector database required to run the demo or the
tests. It is a real, working retrieval mechanism, not a stub - swap in
pgvector/Chroma + real embeddings for production scale by replacing
`RetrievalStore.search` and leaving its interface (`Document`, `search`,
`add_resolved_incident`) unchanged; nothing above this module needs to
change when you do.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


_TOKEN_RE = re.compile(r"[a-z0-9_./]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass
class Document:
    doc_id: str
    title: str
    body: str
    kind: str = "vendor_doc"  # "vendor_doc" | "resolved_incident"
    tags: list[str] = field(default_factory=list)


class RetrievalStore:
    def __init__(self, documents: list[Document] | None = None):
        self._documents: list[Document] = []
        self._doc_freq: Counter[str] = Counter()
        for doc in documents or []:
            self.add(doc)

    def add(self, doc: Document) -> None:
        self._documents.append(doc)
        for term in set(_tokenize(doc.title + " " + doc.body + " " + " ".join(doc.tags))):
            self._doc_freq[term] += 1

    def add_resolved_incident(self, cluster_key: str, title: str, summary: str, tags: list[str]) -> None:
        """Called after an engineer confirms an RCA verdict - this is the
        compounding mechanism the proposal describes: the system gets
        sharper on *this* estate's quirks specifically, cycle over cycle."""
        self.add(
            Document(
                doc_id=f"resolved:{cluster_key}",
                title=title,
                body=summary,
                kind="resolved_incident",
                tags=tags,
            )
        )

    def forget_resolved_incident(self, cluster_key: str) -> int:
        """The inverse: a later verdict on the same recurring cause (the
        same `cluster_key`) says the earlier one was wrong - remove it
        rather than let a confirmed-wrong finding keep being retrieved as
        if it were institutional knowledge. Returns how many documents were
        removed (0 or 1 in practice - see `add`'s docstring on why more
        than one is possible)."""
        doc_id = f"resolved:{cluster_key}"
        keep, removed = [], []
        for doc in self._documents:
            (removed if doc.doc_id == doc_id else keep).append(doc)
        if not removed:
            return 0
        self._documents = keep
        self._doc_freq = Counter()
        for doc in keep:
            for term in set(_tokenize(doc.title + " " + doc.body + " " + " ".join(doc.tags))):
                self._doc_freq[term] += 1
        return len(removed)

    def search(self, query: str, top_k: int = 5) -> list[tuple[Document, float]]:
        query_terms = _tokenize(query)
        if not query_terms or not self._documents:
            return []

        n_docs = len(self._documents)
        scored: list[tuple[Document, float]] = []
        for doc in self._documents:
            doc_terms = _tokenize(doc.title + " " + doc.body + " " + " ".join(doc.tags))
            doc_tf = Counter(doc_terms)
            doc_len = max(len(doc_terms), 1)
            score = 0.0
            for term in query_terms:
                tf = doc_tf.get(term, 0)
                if tf == 0:
                    continue
                df = self._doc_freq.get(term, 1)
                idf = math.log((n_docs + 1) / df) + 1.0
                score += (tf / doc_len) * idf
            # Resolved incidents from this estate outrank generic vendor
            # docs at equal term-overlap score - institutional memory should
            # win a tie over a generic KB article.
            if doc.kind == "resolved_incident":
                score *= 1.15
            if score > 0:
                scored.append((doc, score))

        scored.sort(key=lambda pair: -pair[1])
        return scored[:top_k]

    def render_context(self, query: str, top_k: int = 5) -> str:
        hits = self.search(query, top_k=top_k)
        if not hits:
            return ""
        lines = []
        for doc, score in hits:
            lines.append(f"[{doc.kind}] {doc.title} (relevance {score:.2f})\n{doc.body}")
        return "\n\n".join(lines)
