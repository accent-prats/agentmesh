"""Coverage for culprit/memory/ (mem0-backed episodic memory) and its
wiring into the retrieval store and the verdict route.

Uses a fake mem0 client (matching the exact surface `MemoryStore.client`
calls - `add`/`search`/`get_all`/`get`/`delete`/`update`) so this suite runs
with zero heavy dependencies, the same way the rest of Culprit's test suite
runs Azure/Datadog collector tests against fakes rather than the real SDKs.
The real mem0/Chroma/sentence-transformers stack was verified separately,
end to end through the actual API routes, before this suite was written -
see the module docstrings in culprit/memory/store.py and episodic.py for
what that verified.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from culprit.memory import episodic
from culprit.memory.store import (
    MemoryRefused,
    MemoryStore,
    NotAConfirmedVerdict,
    Scope,
    assert_self_hosted,
    config_from_env,
)
from culprit.models.rca import CausalStep, RCAResult, RemediationPlaybook, RemediationStep, ResultOrigin
from culprit.models.taxonomy import CauseFamily
from culprit.models.verdict import Verdict, VerdictValue


_WORD_RE = re.compile(r"[a-z0-9]+")


def _words(text: str) -> set[str]:
    """Word-boundary tokenizer for FakeMem0Client's overlap score - plain
    `.split()` would leave punctuation glued to a word (`/boot`, `kernels,`),
    so a query term like "boot" would never match text containing "/boot"
    even though any real embedding model (or mem0 itself) would treat them
    as the same word. Regex-based splitting keeps the fake honest about
    what a real semantic match would actually find."""
    return set(_WORD_RE.findall(text.lower()))


class FakeMem0Client:
    """An in-memory stand-in for mem0's `Memory` - real enough to exercise
    every method `MemoryStore` calls, with a trivial "similarity" score
    (shared-token overlap) instead of real embeddings, so recall ordering
    is deterministic without a model."""

    def __init__(self):
        self._rows: dict[str, dict] = {}

    def add(self, messages, *, infer, metadata, **scope_ids):
        assert infer is False, "Culprit's memory wrapper must never call mem0 with infer=True"
        text = messages[0]["content"]
        memory_id = str(uuid.uuid4())
        self._rows[memory_id] = {"id": memory_id, "memory": text, **scope_ids, "metadata": dict(metadata)}
        return {"results": [{"id": memory_id}]}

    def search(self, query, *, top_k, filters):
        query_terms = _words(query)
        hits = []
        for row in self._rows.values():
            if not self._matches(row, filters):
                continue
            text_terms = _words(row["memory"])
            overlap = len(query_terms & text_terms)
            if overlap:
                hits.append({**row, "score": overlap / max(len(query_terms), 1)})
        hits.sort(key=lambda r: -r["score"])
        return {"results": hits[:top_k]}

    def get_all(self, *, filters, top_k):
        hits = [row for row in self._rows.values() if self._matches(row, filters)]
        return {"results": hits[:top_k]}

    def get(self, memory_id):
        return self._rows.get(memory_id)

    def delete(self, memory_id):
        self._rows.pop(memory_id, None)

    def update(self, memory_id, text, *, metadata):
        row = self._rows.get(memory_id)
        if row is None:
            return
        row["memory"] = text
        row["metadata"] = dict(metadata)

    @staticmethod
    def _matches(row: dict, filters: dict) -> bool:
        for key, value in filters.items():
            if key in ("agent_id", "user_id", "run_id"):
                if str(row.get(key)) != str(value):
                    return False
            elif str(row.get("metadata", {}).get(key)) != str(value):
                return False
        return True


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore(client=FakeMem0Client())


def _result(cause_family=CauseFamily.CAPACITY, confidence=0.9) -> RCAResult:
    return RCAResult(
        cluster_id="cluster-1",
        origin=ResultOrigin.RULE_ENGINE,
        cause_family=cause_family,
        title="Disk exhaustion on /boot blocked the package/update transaction",
        causal_chain=[CausalStep(order=1, statement="Free space on /boot was below threshold", evidence_refs=["e1"])],
        confidence=confidence,
        remediation=RemediationPlaybook(immediate_fix=[RemediationStep(order=1, instruction="Purge old kernels")]),
    )


def _verdict(value: VerdictValue, cluster_id="cluster-1", reviewer="alice@example.com") -> Verdict:
    return Verdict(
        cluster_id=cluster_id, cause_family=CauseFamily.CAPACITY, verdict=value,
        reviewer=reviewer, reviewed_at=datetime.now(timezone.utc),
    )


# ── store.py ────────────────────────────────────────────────────────────────

class TestConfigSafety:
    def test_assert_self_hosted_refuses_an_api_key_anywhere_in_the_tree(self):
        with pytest.raises(MemoryRefused, match="leave the host"):
            assert_self_hosted({"vector_store": {"config": {"api_key": "sk-something"}}})

    def test_assert_self_hosted_refuses_a_nested_forbidden_key(self):
        with pytest.raises(MemoryRefused, match="leave the host"):
            assert_self_hosted({"llm": {"config": {"nested": {"org_id": "org-1"}}}})

    def test_assert_self_hosted_refuses_the_mem0_hosted_provider(self):
        with pytest.raises(MemoryRefused, match="hosted platform"):
            assert_self_hosted({"vector_store": {"provider": "mem0"}})

    def test_assert_self_hosted_accepts_a_clean_config(self):
        assert_self_hosted({"vector_store": {"provider": "chroma", "config": {"path": "x"}},
                            "embedder": {"provider": "huggingface", "config": {"model": "y"}},
                            "llm": {"provider": "anthropic", "config": {"model": "z"}}})

    def test_config_from_env_never_puts_an_api_key_in_the_dict(self, monkeypatch, tmp_path):
        """The Anthropic LLM provider is satisfied by the ANTHROPIC_API_KEY
        environment variable at call time (same as Culprit's own RCA
        client) - never by a literal key in the config dict, which
        assert_self_hosted would (correctly) refuse."""
        import dataclasses

        import culprit.config as config_module

        monkeypatch.setattr(
            config_module, "settings",
            dataclasses.replace(config_module.settings, memory_chroma_path=str(tmp_path)),
        )
        cfg = config_from_env()
        assert "api_key" not in cfg["llm"]["config"]
        assert cfg["vector_store"]["provider"] == "chroma"
        assert cfg["embedder"]["provider"] == "huggingface"
        assert cfg["llm"]["provider"] == "anthropic"


class TestMemoryStore:
    def test_remember_then_recall(self, store):
        mid = store.remember("free space on /boot was below threshold", metadata={"cause_family": "capacity"})
        assert mid
        hits = store.recall("boot threshold free space", k=3)
        assert [h.id for h in hits] == [mid]

    def test_recall_filters_by_where_before_similarity(self, store):
        store.remember("boot partition exhausted", metadata={"cause_family": "capacity"})
        store.remember("boot partition exhausted", metadata={"cause_family": "configuration"})
        hits = store.recall("boot partition exhausted", k=5, where={"cause_family": "capacity"})
        assert len(hits) == 1
        assert hits[0].metadata["cause_family"] == "capacity"

    def test_forget_where_removes_every_match(self, store):
        store.remember("a", metadata={"cluster_key": "k1"})
        store.remember("b", metadata={"cluster_key": "k1"})
        store.remember("c", metadata={"cluster_key": "k2"})
        removed = store.forget_where(where={"cluster_key": "k1"})
        assert len(removed) == 2
        assert len(store.list(where={"cluster_key": "k2"})) == 1

    def test_remember_refuses_blank_text(self, store):
        with pytest.raises(MemoryRefused):
            store.remember("   ", metadata={})

    def test_scope_defaults_to_the_single_rca_agent(self):
        assert Scope().agent_id == "culprit/rca_agent"


# ── episodic.py ───────────────────────────────────────────────────────────

class TestEpisodic:
    def test_compose_summary_includes_causal_chain_and_confirmed_fix(self):
        text = episodic.compose_summary(_result())
        assert "Free space on /boot was below threshold" in text
        assert "Confirmed fix: Purge old kernels" in text

    def test_remember_writes_a_recallable_memory(self, store):
        mid = episodic.remember(store, _verdict(VerdictValue.CORRECT), "cluster-key-1", _result())
        assert mid
        hits = episodic.recall(store, "boot disk exhaustion threshold", cause_family="capacity")
        assert len(hits) == 1
        assert hits[0].metadata["cluster_key"] == "cluster-key-1"
        assert hits[0].metadata["reviewer"] == "alice@example.com"

    def test_remember_refuses_anything_but_correct(self, store):
        for value in (VerdictValue.PARTIALLY_CORRECT, VerdictValue.WRONG):
            with pytest.raises(NotAConfirmedVerdict):
                episodic.remember(store, _verdict(value), "cluster-key-1", _result())

    def test_forget_removes_a_previously_remembered_finding(self, store):
        episodic.remember(store, _verdict(VerdictValue.CORRECT), "cluster-key-1", _result())
        gone = episodic.forget(store, "cluster-key-1")
        assert len(gone) == 1
        assert episodic.recall(store, "boot disk exhaustion threshold", cause_family="capacity") == []

    def test_forget_on_a_never_remembered_cluster_key_is_a_quiet_noop(self, store):
        assert episodic.forget(store, "never-remembered") == []

    def test_recall_never_returns_a_different_cause_family(self, store):
        episodic.remember(store, _verdict(VerdictValue.CORRECT), "k1", _result(CauseFamily.CAPACITY))
        hits = episodic.recall(store, "boot disk exhaustion threshold", cause_family="configuration")
        assert hits == []

    def test_as_evidence_is_labelled_and_empty_for_no_hits(self, store):
        assert episodic.as_evidence([]) == ""
        episodic.remember(store, _verdict(VerdictValue.CORRECT), "k1", _result())
        hits = episodic.recall(store, "boot disk exhaustion threshold")
        text = episodic.as_evidence(hits)
        assert "confirmed prior finding" in text
        assert "not instructions" in text

    def test_a_finding_citing_the_2026_10_18_evidence_sources_is_remembered_and_recalled(self, store):
        """Proves the Phase 3 architectural finding from the 2026-10-18
        evidence-collection round (patch_assessment, repo_diagnostics,
        wsus_connectivity, vmagent_status, the yum/dnf parser fixes): no
        new memory-module code was needed for these new sources to
        benefit from recall on a future similar cluster, because
        _build_user_prompt renders the whole timeline generically (no
        hardcoded event-kind list) and episodic.remember() captures
        whatever the RCA agent actually wrote in its causal_chain
        statement, verbatim, regardless of which evidence source that
        statement cites. This is that round-trip proven for a statement
        that specifically cites two of the new sources."""
        result = RCAResult(
            cluster_id="cluster-2", origin=ResultOrigin.RULE_ENGINE, cause_family=CauseFamily.CONFIGURATION,
            title="Repo unreachable due to DNS failure blocked the patch install",
            causal_chain=[CausalStep(
                order=1,
                statement="Repo diagnostics showed DNS resolution failed for the configured mirror, and "
                "the patch assessment recorded 4 security patches still pending",
                evidence_refs=["guest:repo_diagnostics:vm-1", "resourcegraph:patchassessmentresources/x"],
            )],
            confidence=0.9,
            remediation=RemediationPlaybook(immediate_fix=[RemediationStep(order=1, instruction="Fix DNS resolver config and retry")]),
        )
        verdict = Verdict(
            cluster_id="cluster-2", cause_family=CauseFamily.CONFIGURATION, verdict=VerdictValue.CORRECT,
            reviewer="bob@example.com", reviewed_at=datetime.now(timezone.utc),
        )

        episodic.remember(store, verdict, "cluster-key-2", result)
        hits = episodic.recall(
            store, "repo diagnostics DNS resolution failed mirror patch assessment security patches pending",
            cause_family="configuration",
        )

        assert len(hits) == 1
        assert "Repo diagnostics" in hits[0].text
        assert "patch assessment" in hits[0].text
        assert hits[0].metadata["cluster_key"] == "cluster-key-2"


# ── hybrid.py + deps.py wiring ────────────────────────────────────────────

class TestHybridRetrievalStore:
    @pytest.fixture
    def hybrid(self, store):
        from culprit.retrieval.corpus import default_retrieval_store
        from culprit.retrieval.hybrid import HybridRetrievalStore

        return HybridRetrievalStore(vendor_store=default_retrieval_store(), memory_store=store)

    def test_remember_verdict_writes_to_mem0_not_the_vendor_store(self, hybrid):
        v = _verdict(VerdictValue.CORRECT)
        mid = hybrid.remember_verdict(v, "cluster-key-1", _result())
        assert mid
        # The vendor TF-IDF store's own document count is unaffected -
        # api/routes_verdicts.py deliberately calls remember_verdict
        # *instead of* add_resolved_incident whenever this store is active,
        # precisely so a confirmed RCA isn't retrievable from both backends
        # at once (see TestNoDuplicateEvidence below for the route-level
        # regression test).
        assert not any(d.doc_id == "resolved:cluster-key-1" for d in hybrid._vendor._documents)

    def test_render_context_combines_vendor_docs_and_episodic_memory(self, hybrid):
        hybrid.remember_verdict(_verdict(VerdictValue.CORRECT), "cluster-key-1", _result())
        context = hybrid.render_context("boot partition disk full kernels retained")
        assert "confirmed prior finding" in context  # from mem0
        assert "vendor_doc" in context  # the seeded Ubuntu /boot doc still matches too

    def test_forget_resolved_incident_forgets_both_backends(self, hybrid):
        hybrid.add_resolved_incident("cluster-key-1", "title", "summary", ["capacity"])
        hybrid.remember_verdict(_verdict(VerdictValue.CORRECT), "cluster-key-1", _result())
        removed = hybrid.forget_resolved_incident("cluster-key-1")
        assert removed == 1  # the vendor side had exactly one matching doc
        assert episodic.recall(hybrid._memory, "boot disk exhaustion threshold") == []


class TestRetrievalStoreForget:
    """The plain TF-IDF store's own forget support - added alongside the
    memory port, and exercised by default (CULPRIT_MEMORY_ENABLED=false)
    without needing mem0 at all."""

    def test_forget_resolved_incident_removes_it_from_search(self):
        from culprit.retrieval.corpus import default_retrieval_store

        rs = default_retrieval_store()
        rs.add_resolved_incident("k1", "Kernel retention issue", "boot partition filled by retained kernels", ["capacity"])
        assert rs.search("retained kernels boot partition")
        removed = rs.forget_resolved_incident("k1")
        assert removed == 1
        hits = rs.search("retained kernels boot partition")
        assert not any(doc.doc_id == "resolved:k1" for doc, _score in hits)

    def test_forget_resolved_incident_on_an_unknown_key_is_a_quiet_noop(self):
        from culprit.retrieval.corpus import default_retrieval_store

        assert default_retrieval_store().forget_resolved_incident("never-added") == 0


class TestNoDuplicateEvidence:
    """POST /verdicts, with the memory backend active, must write a
    confirmed RCA to exactly one place - a real regression this suite
    didn't catch the first time (both add_resolved_incident and
    remember_verdict were being called unconditionally), found only by
    checking render_context()'s output shape, not just that it contains
    the expected evidence at all."""

    @pytest.fixture
    def client_with_memory(self, monkeypatch):
        import culprit.api.deps as deps_module
        import culprit.memory.store as memstore_module
        from culprit.db.engine import make_engine, make_session_factory
        from culprit.demo.scripted_rca import ScriptedRCAAgent

        engine = make_engine("sqlite:///:memory:")
        factory = make_session_factory(engine)
        deps_module.get_session_factory.cache_clear()
        monkeypatch.setattr(deps_module, "get_session_factory", lambda: factory)

        monkeypatch.setattr(deps_module, "get_rca_agent", lambda: ScriptedRCAAgent())

        fake_memory_store = MemoryStore(client=FakeMem0Client())
        monkeypatch.setattr(memstore_module, "get_store", lambda: fake_memory_store)
        monkeypatch.setattr(deps_module, "settings", _with_memory_enabled(deps_module.settings))
        deps_module.get_retrieval_store.cache_clear()

        from culprit.api.main import app

        yield TestClient(app)
        deps_module.get_retrieval_store.cache_clear()

    def test_a_confirmed_verdict_is_retrievable_exactly_once(self, client_with_memory):
        resp = client_with_memory.post("/runs/demo")
        body = resp.json()
        entry = next(e for e in body["entries"] if len(e["cluster"]["members"]) == 19)  # the capacity cluster
        cluster_id = entry["cluster"]["cluster_id"]

        v = client_with_memory.post(
            "/verdicts",
            json={"cluster_id": cluster_id, "cause_family": "capacity", "verdict": "correct",
                  "reviewer": "alice@example.com"},
        )
        assert v.status_code == 200

        import culprit.api.deps as deps_module

        store = deps_module.get_retrieval_store()
        context = store.render_context("boot partition disk full kernels retained")
        assert context.count("confirmed prior finding") == 1, (
            "the same confirmed RCA appeared more than once in the evidence block - "
            "it was written to both the vendor store and mem0"
        )


def _with_memory_enabled(settings):
    import dataclasses

    return dataclasses.replace(settings, memory_enabled=True)


class TestDepsWiring:
    def test_memory_disabled_returns_the_plain_store(self, monkeypatch):
        import dataclasses

        import culprit.api.deps as deps_module
        from culprit.retrieval.store import RetrievalStore

        # deps.py does `from culprit.config import settings` at module
        # level, so the name to patch is deps_module.settings, not
        # culprit.config.settings (a separate binding by then).
        monkeypatch.setattr(deps_module, "settings", dataclasses.replace(deps_module.settings, memory_enabled=False))
        deps_module.get_retrieval_store.cache_clear()
        result = deps_module.get_retrieval_store()
        assert isinstance(result, RetrievalStore)
        assert not hasattr(result, "remember_verdict")
        deps_module.get_retrieval_store.cache_clear()

    def test_memory_enabled_but_mem0_not_installed_falls_back_gracefully(self, monkeypatch):
        """Mirrors get_rca_agent()'s own graceful-degradation shape: a
        missing optional extra must not take the app down."""
        import builtins
        import dataclasses

        import culprit.api.deps as deps_module
        from culprit.retrieval.store import RetrievalStore

        monkeypatch.setattr(deps_module, "settings", dataclasses.replace(deps_module.settings, memory_enabled=True))
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "culprit.memory.store" or name.startswith("mem0"):
                raise ImportError("mem0ai not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        deps_module.get_retrieval_store.cache_clear()
        result = deps_module.get_retrieval_store()
        assert isinstance(result, RetrievalStore)
        deps_module.get_retrieval_store.cache_clear()
