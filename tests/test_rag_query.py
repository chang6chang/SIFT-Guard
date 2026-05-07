"""Unit tests for `server.tools.rag.rag_query` (week 7 G-2).

The MCP tool is a thin envelope around the week-3 retriever:
input-shape validation, audit-on-rejection for typed failure
modes, and projection of `RagRecord` onto the agent-facing
`RagHit` shape. The retriever's behavior (exact-ID short-circuit,
vector search, score semantics) is exercised end-to-end against
the live FAISS index — same surface area
`tests/test_rag_retriever.py` covers, but with the tool-layer
audit chain present.

Tests deliberately exercise the live index (rag/data/) rather
than mocking it. The merged corpus (697 ATT&CK + ~2147 Sigma =
~2844 records) is small enough to load fast, the retriever's
lazy model load amortizes across this file's queries, and the
load-bearing property — that a validator's rag_query call lands
real grounding content in correlation hypotheses — is what we
want to pin against drift.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from server.schemas import RagQueryResult
from server.tools.rag import rag_query


def _seed_case_dir(tmp_path: Path) -> Path:
    """rag_query writes audit lines to <case_dir>/audit/sift-guard-mcp.jsonl
    but never reads CASE.yaml, registers evidence, or touches
    extractions/findings/correlations. The minimal case dir is just
    the directory itself — `append_audit_entry` creates the audit
    subdir on first write.
    """
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    return case_dir


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestRagQueryHappyPaths:
    def test_exact_technique_id_returns_t1055_at_rank1_score_one(
        self, tmp_path: Path
    ):
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(
            technique_id="T1055", case_dir=str(case_dir), top_k=5
        )
        assert isinstance(result, RagQueryResult)
        assert result.query_kind == "technique_id"
        assert result.query_value == "T1055"
        assert len(result.hits) >= 1
        assert result.hits[0].technique_id == "T1055"
        # Exact-ID short-circuit pins similarity_score to 1.0
        assert result.hits[0].similarity_score == 1.0
        assert result.hits[0].name  # non-empty
        assert result.hits[0].citation_url.startswith("https://attack.mitre.org/")

    def test_exact_subtechnique_id_returns_t1055_001(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(
            technique_id="T1055.001", case_dir=str(case_dir), top_k=3
        )
        assert result.hits[0].technique_id == "T1055.001"
        assert result.hits[0].similarity_score == 1.0

    def test_semantic_query_finds_relevant_techniques(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(
            semantic_query="hidden process injection",
            case_dir=str(case_dir),
            top_k=5,
        )
        assert result.query_kind == "semantic"
        assert result.query_value == "hidden process injection"
        # Top-5 cohort should contain at least one process-anomaly
        # technique. The exact ranks drift between sentence-transformers
        # patch versions; the cohort membership is the load-bearing
        # signal.
        ids = {h.technique_id for h in result.hits}
        process_techniques = {"T1055", "T1014", "T1036"}  # injection, rootkit, masquerading
        assert ids & process_techniques, (
            f"semantic search for 'hidden process injection' should "
            f"surface at least one of {process_techniques}; got {ids}"
        )
        # Vector-search scores live in roughly [0.3, 0.8] for normalized
        # embeddings on a typical sentence corpus; 1.0 is the
        # exact-ID-only marker.
        for h in result.hits:
            assert 0.0 <= h.similarity_score <= 1.0


# ---------------------------------------------------------------------------
# "Technique not found" — regex matches, ID absent → empty hits
# ---------------------------------------------------------------------------


class TestTechniqueIdNotInCorpus:
    def test_regex_matching_id_not_in_corpus_returns_empty_hits(
        self, tmp_path: Path
    ):
        # T9999 matches the regex but is not in the ATT&CK enterprise
        # corpus. The retriever's default behavior would fall through
        # to vector search; the tool's contract returns empty hits
        # instead so the agent's `technique_id` semantic isn't silently
        # swapped for `semantic_query` semantics.
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(technique_id="T9999", case_dir=str(case_dir))
        assert result.hits == []
        assert result.query_kind == "technique_id"
        assert result.query_value == "T9999"
        # Audit chain still records this as a SUCCESS (not a rejection)
        # — "technique not found" is a valid outcome, not a refusal.
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "rag_query"


# ---------------------------------------------------------------------------
# Rejections (audited as rag_query:rejected_*)
# ---------------------------------------------------------------------------


class TestRagQueryRejections:
    def test_both_inputs_supplied_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            rag_query(
                technique_id="T1055",
                semantic_query="something",
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "rag_query:rejected_both_inputs"

    def test_no_input_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            rag_query(case_dir=str(case_dir))
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "rag_query:rejected_no_input"

    def test_top_k_above_cap_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            rag_query(
                technique_id="T1055", top_k=21, case_dir=str(case_dir)
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "rag_query:rejected_top_k_too_large"

    def test_query_too_long_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            rag_query(
                semantic_query="x" * 501, case_dir=str(case_dir)
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "rag_query:rejected_query_too_long"

    def test_technique_id_bad_shape_rejected(self, tmp_path: Path):
        # "BAD-ID" doesn't match T<4 digits>[.<3 digits>] — not a
        # canonical ATT&CK form. The agent passed a value under
        # technique_id and meant the exact-ID semantic; we refuse
        # rather than silently route to vector search.
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            rag_query(technique_id="BAD-ID", case_dir=str(case_dir))
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "rag_query:rejected_technique_id_bad_shape"
        )


# ---------------------------------------------------------------------------
# Result-envelope properties
# ---------------------------------------------------------------------------


class TestRagQueryResultEnvelope:
    def test_audit_line_matches_chain_position_after_call(
        self, tmp_path: Path
    ):
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(
            technique_id="T1055", case_dir=str(case_dir)
        )
        # The result's audit_line is the line number where THIS
        # call's success entry was written.
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert result.audit_line == audit[-1]["line_number"]
        assert audit[-1]["tool_name"] == "rag_query"

    def test_embedding_model_version_matches_meta_sidecar(
        self, tmp_path: Path
    ):
        # The version on the result must match the meta.json sidecar
        # that the retriever loads at construction (`Retriever.__init__`
        # already enforces meta.embedding_model_version against the
        # constructed model_name; we re-surface the value on the
        # result so a future audit-replay can verify scores were
        # computed against the expected model without re-loading).
        case_dir = _seed_case_dir(tmp_path)
        result = rag_query(
            technique_id="T1055", case_dir=str(case_dir)
        )
        meta = json.loads(
            (Path("rag/data/attack-enterprise.meta.json")).read_text()
        )
        assert (
            result.embedding_model_version
            == meta["embedding_model_version"]
        )

    def test_untrusted_fields_is_always_empty(self, tmp_path: Path):
        # MITRE ATT&CK content is vendor-curated, not evidence-derived.
        # The schema-level model_validator pins this; the tool layer
        # should never produce a non-empty list. Property tested for
        # both query shapes.
        case_dir = _seed_case_dir(tmp_path)
        r1 = rag_query(technique_id="T1055", case_dir=str(case_dir))
        r2 = rag_query(
            semantic_query="masquerading", case_dir=str(case_dir)
        )
        r3 = rag_query(technique_id="T9999", case_dir=str(case_dir))
        assert r1.untrusted_fields == []
        assert r2.untrusted_fields == []
        assert r3.untrusted_fields == []


# ---------------------------------------------------------------------------
# Cross-tool: schema-introspection guard does NOT regress with
# RagQueryResult added.
# ---------------------------------------------------------------------------


class TestSchemaIntrospectionGuardStillHolds:
    def test_rag_query_result_does_not_introduce_path_field(self):
        """Architectural lock parallel: `tests/test_no_path_fields.py`
        runs over MCP tool surfaces. Sanity-check the new
        `RagQueryResult` doesn't carry a path-shaped field name that
        would trigger a false positive on a future iteration of that
        introspection.
        """
        from server.schemas import RagQueryResult

        path_tokens = {"path", "file", "filename", "filepath", "dir", "directory"}
        for field_name in RagQueryResult.model_fields:
            tokens = field_name.lower().split("_")
            assert not (set(tokens) & path_tokens), (
                f"RagQueryResult.{field_name} shares a token with the "
                "path-field-rejection set; rename or update the test."
            )
