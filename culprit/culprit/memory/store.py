"""The one place mem0 is called (ported from the platform's `test` branch,
`shared/src/memory/store.py`, MEMORY-1/QAI-92 - see this package's
`__init__.py` for what was cut and why).

mem0 stores, retrieves, updates and explains; Culprit decides what is
allowed in - enforced the same way the original design enforces it:

  * `remember()` accepts only a confirmed verdict - a `culprit.models.verdict.Verdict`
    whose value is `CORRECT`, tied to the RCAResult it verdicts. A cluster
    with no verdict yet is not memory; a "wrong" verdict is never written,
    it FORGETS a previous memory instead (episodic.py).
  * `remember()` writes with `infer=False`: the text stored is exactly the
    text given (composed by episodic.py from validated Pydantic fields -
    `RCAResult.title`, `causal_chain`, `remediation` - never from a raw
    external string), with provenance in metadata. Culprit never calls
    mem0 with `infer=True` at all - there is no per-user preference surface
    here to justify a model in the write path, so that whole attack
    surface (the original design's entire section on prompt-injection
    defence for `infer=True`) doesn't exist in this port.
  * The image has no path to mem0's hosted platform: `config_from_env()`
    never sets an API key or a platform URL for mem0/Chroma, and
    `assert_self_hosted()` is what the tests and `status()` call. The
    vector store is on-disk Chroma (no server) and the embedder is a local
    sentence-transformers model - memory never leaves the host, same
    principle as the original design, adapted to Culprit not having its
    own Chroma/Ollama services running (see docs/proposals in the original
    for why those were the platform's choice; Culprit is a single
    standalone app and picked the equivalent that needs no extra service).

Nothing here is async: mem0's client is synchronous and Culprit's calls
happen from the verdict route and the deep-RCA prompt-building step, both
already synchronous call sites.
"""
from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("culprit.memory.store")

DEFAULT_COLLECTION = "culprit_memory"
DEFAULT_EMBED_MODEL = "multi-qa-MiniLM-L6-cos-v1"
# The only config keys a self-hosted deployment may carry. Anything that
# would route a memory off the host is refused before mem0 sees it - same
# list and same reasoning as the original design's store.py.
FORBIDDEN_CONFIG_KEYS = ("api_key", "org_id", "project_id", "host_url", "platform")


class MemoryRefused(ValueError):
    """The wrapper refused a write or a config. Message says why; nothing
    was stored."""


class NotAConfirmedVerdict(MemoryRefused):
    pass


@dataclass(frozen=True)
class Scope:
    """Culprit has exactly one memory-writing agent, so this is narrower
    than the original design's three-dimensional (app/agent, user, run)
    scope - kept as its own type anyway so `store.py`'s calls read the same
    way and a future per-subscription scope (see this module's own
    docstring discussion) is a one-line change, not a rewrite."""

    agent_id: str = "culprit/rca_agent"

    def ids(self) -> dict:
        return {"agent_id": self.agent_id}


@dataclass
class Recalled:
    id: str
    text: str
    score: float | None
    metadata: dict = field(default_factory=dict)

    @property
    def provenance(self) -> dict:
        m = self.metadata
        return {k: m.get(k) for k in ("cluster_id", "cluster_key", "cause_family", "reviewer", "reviewed_at")}

    def as_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "score": self.score, "metadata": self.metadata,
                "provenance": self.provenance}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


# ── configuration ─────────────────────────────────────────────────────────

def config_from_env(**overrides: Any) -> dict:
    """mem0's config for Culprit: on-disk Chroma (no server - see
    culprit.config.settings.memory_chroma_path), a local sentence-
    transformers embedder (no API call), and Anthropic as the LLM provider
    - reusing the same ANTHROPIC_API_KEY the deep RCA agent already
    requires, since mem0 wants an LLM configured even though Culprit never
    exercises it (infer=False everywhere here). No API key, no platform
    URL for mem0/Chroma themselves: those are refused by
    `assert_self_hosted`, not merely omitted."""
    from culprit.config import settings

    collection = overrides.pop("collection", None) or DEFAULT_COLLECTION
    chroma_path = overrides.pop("chroma_path", None) or settings.memory_chroma_path
    embed_model = overrides.pop("embed_model", None) or settings.memory_embed_model

    config = {
        "vector_store": {
            "provider": "chroma",
            "config": {"collection_name": collection, "path": chroma_path},
        },
        "embedder": {
            "provider": "huggingface",
            "config": {"model": embed_model},
        },
        "llm": {
            "provider": "anthropic",
            "config": {"model": settings.rca_model, "temperature": 0.0, "max_tokens": 10},
        },
    }
    config.update(overrides)
    assert_self_hosted(config)
    return config


def assert_self_hosted(config: dict) -> None:
    """Refuse any config that could reach mem0's hosted platform or
    Chroma's hosted platform. Walks the whole dict: a key under
    `llm.config` counts as much as a top-level one - ported unchanged from
    the original design's store.py, since the reasoning doesn't depend on
    which apps are calling it."""
    found: list = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in FORBIDDEN_CONFIG_KEYS and v not in (None, "", {}):
                    found.append(".".join(path + [k]))
                walk(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, path + [str(i)])

    walk(config, [])
    if found:
        raise MemoryRefused("memory config would leave the host: " + ", ".join(found))
    for section in ("embedder", "llm", "vector_store"):
        if (config.get(section) or {}).get("provider") == "mem0":
            raise MemoryRefused(f"{section} provider 'mem0' is the hosted platform")


# ── the store ─────────────────────────────────────────────────────────────

class MemoryStore:
    """remember / recall / forget over one mem0 client."""

    def __init__(self, config: dict | None = None, *, client=None):
        self._config = config
        self._client = client
        self._lock = threading.Lock()
        # Nothing leaves the host: mem0's own telemetry and Chroma's
        # anonymized telemetry are off unless an operator has said
        # otherwise - same as the original design.
        os.environ.setdefault("MEM0_TELEMETRY", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

    @property
    def client(self):
        if self._client is None:
            with self._lock:
                if self._client is None:
                    config = self._config or config_from_env()
                    assert_self_hosted(config)
                    chroma_path = (config.get("vector_store") or {}).get("config", {}).get("path")
                    if chroma_path:
                        os.makedirs(chroma_path, exist_ok=True)
                    from mem0 import Memory  # the only import of mem0 in this package

                    self._client = Memory.from_config(config)
        return self._client

    def remember(self, text: str, *, metadata: dict, scope: Scope | None = None) -> str | None:
        """Store `text` exactly as given (infer=False), with provenance in
        `metadata`. Callers are `episodic.py` only - see that module for
        the confirmed-verdict gate this method itself does not re-check."""
        if not isinstance(text, str) or not text.strip():
            raise MemoryRefused("nothing to remember")
        scope = scope or Scope()
        meta = {k: v for k, v in metadata.items() if v is not None}
        result = self.client.add([{"role": "user", "content": text}], infer=False, metadata=meta, **scope.ids())
        ids = [r.get("id") for r in (result or {}).get("results", []) if r.get("id")]
        if not ids:
            raise MemoryRefused("mem0 stored nothing for a valid write")
        return ids[0]

    def recall(self, query: str, *, k: int = 3, where: dict | None = None,
               scope: Scope | None = None) -> list[Recalled]:
        """The k most similar memories, filtered by metadata equality
        (`where`) before similarity - overfetches and filters in Python
        since `where` here is Culprit's own filter (cause_family), not
        necessarily one Chroma indexes."""
        if not query or not query.strip():
            return []
        scope = scope or Scope()
        filters = dict(scope.ids())
        result = self.client.search(query, top_k=max(1, k) * 4, filters=filters)
        hits = [self._recalled(r) for r in (result or {}).get("results", [])]
        for key, value in (where or {}).items():
            if value is not None:
                hits = [h for h in hits if str(h.metadata.get(key)) == str(value)]
        hits.sort(key=lambda h: -(h.score or 0.0))
        return hits[:max(1, k)]

    def list(self, *, where: dict | None = None, scope: Scope | None = None, limit: int = 200) -> list[Recalled]:
        scope = scope or Scope()
        result = self.client.get_all(filters=dict(scope.ids()), top_k=max(1, min(limit, 1000)))
        hits = [self._recalled(r) for r in (result or {}).get("results", [])]
        for key, value in (where or {}).items():
            if value is not None:
                hits = [h for h in hits if str(h.metadata.get(key)) == str(value)]
        return hits

    def get(self, memory_id: str) -> Recalled | None:
        raw = self.client.get(memory_id)
        return self._recalled(raw) if raw else None

    def forget(self, memory_id: str) -> bool:
        self.client.delete(memory_id)
        return True

    def forget_where(self, *, where: dict, scope: Scope | None = None) -> list[str]:
        """Delete every memory matching `where` exactly - the "a later
        verdict says this was wrong" path (episodic.py::forget), matched by
        cluster_key so a recurring cause's memory can be corrected without
        needing its mem0 memory id."""
        gone = []
        for memory in self.list(where=where, scope=scope, limit=1000):
            self.forget(memory.id)
            gone.append(memory.id)
        return gone

    def counts(self, *, scope: Scope | None = None) -> dict:
        """How many memories, and the oldest - what a health/status view
        shows without needing the full list."""
        memories = self.list(scope=scope, limit=1000)
        if not memories:
            return {"count": 0, "oldest": None}
        observed = sorted(m.metadata.get("reviewed_at") for m in memories if m.metadata.get("reviewed_at"))
        return {"count": len(memories), "oldest": observed[0] if observed else None}

    @staticmethod
    def _recalled(raw: dict) -> Recalled:
        meta = dict(raw.get("metadata") or {})
        for key in ("agent_id", "user_id", "run_id"):
            if raw.get(key) and key not in meta:
                meta[key] = raw[key]
        return Recalled(id=str(raw.get("id")), text=str(raw.get("memory") or raw.get("data") or ""),
                        score=raw.get("score"), metadata=meta)


# ── the process-wide store ────────────────────────────────────────────────

_STORE: MemoryStore | None = None
_STORE_LOCK = threading.Lock()


def get_store() -> MemoryStore:
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = MemoryStore()
    return _STORE


def set_store(store: MemoryStore | None) -> None:
    """For tests, and for a caller that builds its own config."""
    global _STORE
    _STORE = store


def status() -> dict:
    """For a health/inspection endpoint: where memory lives, without
    touching mem0 itself."""
    try:
        cfg = config_from_env()
        vs = cfg["vector_store"]["config"]
        return {
            "vector_store": "chroma",
            "collection": vs.get("collection_name"),
            "location": vs.get("path"),
            "embedder": f"huggingface/{cfg['embedder']['config']['model']}",
            "llm": f"anthropic/{cfg['llm']['config']['model']}",
            "self_hosted": True,
        }
    except Exception as exc:  # noqa: BLE001 - a status view must not itself crash the page
        return {"error": str(exc)[:200], "self_hosted": False}
