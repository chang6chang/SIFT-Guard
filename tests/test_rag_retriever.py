"""Unit tests for `rag.retriever.Retriever`.

Builds a fixture index in `tmp_path` once per class and exercises the
search interface against it. No network, no on-disk artifacts left
behind.

Two semantic claims this test enforces (both came directly from the
prompt for this PR):

  1. an exact-ID query (``"T1055"``) must return T1055 as the top hit
  2. a semantic query (``"hidden process"``) must surface the
     "evade-by-running-elsewhere" cluster of techniques (process
     injection, masquerading, rootkit) ahead of unrelated ones — the
     whole point of vector search

If either claim breaks because the embedding model changed, the
retriever broke, or the fixture lost a relevant technique, the
failure should be unambiguous from the message.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rag.ingest_attack import build_index_files, build_records
from rag.retriever import Retriever, search
from rag.schemas import RagRecord


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "rag_attack_sample.json"


@pytest.fixture(scope="module")
def index_dir(tmp_path_factory) -> Path:
    """Build the fixture index once per test module. Embedding the
    5-record fixture takes ~1 s on CPU; doing it per test would be
    wasteful. tmp_path_factory cleans up at the end of the session."""
    records = build_records(json.loads(FIXTURE_PATH.read_text()))
    out = tmp_path_factory.mktemp("rag_retriever")
    build_index_files(records, out)
    return out


@pytest.fixture(scope="module")
def retriever(index_dir) -> Retriever:
    return Retriever(index_dir=index_dir)


# ---------------------------------------------------------------------------
# Semantic claims — the contract the validator will rely on
# ---------------------------------------------------------------------------


class TestRetrievalSemantics:
    def test_exact_technique_id_query_returns_t1055_first(self, retriever):
        results = retriever.search("T1055", k=5)
        assert results, "expected at least one result"
        assert results[0].technique_id == "T1055", (
            f"top result for 'T1055' must be T1055; got {[r.technique_id for r in results]}"
        )
        # Exact-ID short-circuit assigns score 1.0 — see retriever
        # module-level comment on _TECHNIQUE_ID_RE for why pure vector
        # retrieval can't anchor on a 4-digit ID.
        assert results[0].score == 1.0, (
            f"exact technique-ID match must score 1.0 (the short-circuit "
            f"value); got {results[0].score}. If this drifted, the "
            "_EXACT_ID_SCORE constant moved or the short-circuit didn't fire."
        )
        # The remaining slots come from vector search — no duplicates.
        ids = [r.technique_id for r in results]
        assert len(set(ids)) == len(ids), f"vector backfill leaked the exact-ID hit back in: {ids}"

    def test_id_shaped_query_for_missing_id_falls_through_to_vector(self, retriever):
        # T9000 isn't in the fixture. The retriever must not raise; it
        # must fall through to vector search and return semantically
        # similar techniques. This is the real-world failure mode —
        # an LLM types a plausible-looking ID we don't have.
        results = retriever.search("T9000", k=3)
        assert len(results) == 3
        # All scores in vector-cosine range, none are the 1.0
        # short-circuit value (because the short-circuit didn't match).
        assert all(r.score is not None and r.score < 1.0 for r in results)

    def test_semantic_query_finds_hiding_techniques(self, retriever):
        # "hidden process" should surface the cluster: process
        # injection (T1055), rootkit (T1014), masquerading (T1036).
        # These share the "evade by running elsewhere / under a
        # different name" semantic, even though only T1014's
        # description has the literal word "hide".
        results = retriever.search("hidden process", k=5)
        top_ids = [r.technique_id for r in results[:3]]
        # At least 2 of the 3 expected techniques must appear in the
        # top-3 — leaves a sliver of room for embedding-model drift
        # without making the test useless.
        relevant = {"T1055", "T1014", "T1036"}
        hits = relevant.intersection(top_ids)
        assert len(hits) >= 2, (
            f"semantic search for 'hidden process' should surface "
            f"≥2 of {sorted(relevant)} in top-3; got top-3 = {top_ids} "
            f"(intersection: {sorted(hits)})"
        )

    def test_credential_dumping_query_finds_t1003(self, retriever):
        # Distinct semantic neighborhood from the "hiding" cluster —
        # confirms the embedding isn't just collapsing every query
        # onto the same techniques.
        results = retriever.search("dump password hashes from LSASS", k=3)
        assert results[0].technique_id == "T1003", (
            f"expected T1003 (OS Credential Dumping) at rank 1; got "
            f"{[r.technique_id for r in results]}"
        )


# ---------------------------------------------------------------------------
# Retriever interface contract
# ---------------------------------------------------------------------------


class TestRetrieverContract:
    def test_search_returns_RagRecord_instances_with_score_filled(self, retriever):
        results = retriever.search("masquerading", k=2)
        assert all(isinstance(r, RagRecord) for r in results)
        for r in results:
            assert r.score is not None, "score must be filled by the retriever"
            assert r.citation_url.startswith("https://attack.mitre.org/techniques/")
            assert r.license == "CC-BY 4.0"

    def test_k_capped_to_index_size(self, retriever):
        # Asking for more than the corpus has should not raise; FAISS
        # would silently return fewer, and the retriever should match.
        results = retriever.search("anything", k=100)
        assert len(results) == 5  # fixture has 5 records

    def test_empty_query_rejected(self, retriever):
        with pytest.raises(ValueError, match="non-empty"):
            retriever.search("   ")

    def test_zero_k_rejected(self, retriever):
        with pytest.raises(ValueError, match="k must be"):
            retriever.search("anything", k=0)


# ---------------------------------------------------------------------------
# Index-version mismatch guardrail
# ---------------------------------------------------------------------------


class TestIndexVersionGuard:
    def test_constructing_with_mismatched_model_refuses_loudly(self, index_dir):
        # Index was built with all-MiniLM-L6-v2; passing a different
        # model name must refuse rather than silently produce
        # meaningless cosine scores against a different embedding
        # space.
        with pytest.raises(RuntimeError, match="embedding_model_version"):
            Retriever(
                index_dir=index_dir,
                model_name="sentence-transformers/all-mpnet-base-v2",
            )

    def test_missing_index_dir_explains_how_to_fix(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="rag.ingest_attack"):
            Retriever(index_dir=tmp_path / "does-not-exist")


# ---------------------------------------------------------------------------
# Convenience `search()` covers the one-off CLI path. We don't repeat
# the full semantic suite — the class is the canonical entry point —
# but smoke-testing the wrapper at least once catches signature drift.
# ---------------------------------------------------------------------------


class TestModuleLevelSearch:
    def test_search_helper_returns_same_top_id(self, index_dir):
        results = search("T1055", k=1, index_dir=index_dir)
        assert len(results) == 1
        assert results[0].technique_id == "T1055"
