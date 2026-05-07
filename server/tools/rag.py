"""Tier-2-shaped RAG-query MCP tool (week 7 G-2).

Exposes the week-3 ATT&CK enterprise corpus to the validator subagent
for grounding correlation hypotheses in named techniques. The
orchestrator's R1-R6 promotion rules continue to ignore RAG content;
mechanical RAG-grounded promotion (R7+) is deferred. See
`docs/decisions-log.md` 2026-05-?? "RAG queryable but not mechanically
promoting" entry.

Architectural rules:
  - Tool surface accepts ONE of `technique_id` or `semantic_query`,
    not both. Both / neither each fire a typed audit-on-rejection.
  - Tool does NOT reimplement retrieval. It routes to
    `rag.retriever.Retriever` / `rag.retriever.search` and surfaces
    the result through the typed `RagQueryResult` envelope.
  - `untrusted_fields` is empty by schema construction (see
    `server.schemas.RagQueryResult._untrusted_fields_must_be_empty`).
    The corpus is vendor-curated MITRE ATT&CK material, not
    evidence-derived strings. If a future RAG source emits
    user-controllable content, that source needs its own schema.
  - `audit_line` is the audit-chain line where THIS rag_query
    invocation's success entry is logged — same provenance pattern
    as tier-2 results, so the validator can cite the line directly
    in a correlation `EvidenceRef` without probing.

The retriever's existing exact-ID short-circuit (see
`rag/retriever.py` `_TECHNIQUE_ID_RE`) handles ``technique_id`` input
when the ID exists in the corpus. When the ID matches the regex but
is NOT in the corpus, the retriever's default behavior is to fall
through to vector search; this tool intentionally diverges and
returns ``hits=[]`` (a typed "technique not found" outcome) rather
than surfacing semantically-similar but unrequested techniques. The
divergence keeps the tool's contract clean: technique_id input
returns a hit for that specific ID or nothing.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from server.audit import append_audit_entry, peek_next_line_number
from server.schemas import RagHit, RagQueryResult
from rag.retriever import Retriever


_RAG_QUERY_TOOL = "rag_query"

# Hard caps. ``top_k > 20`` is rejected — the validator's prompt
# instructs it to keep top_k ≤ 20, but the runtime gate is the
# architectural enforcement. ``query > 500 chars`` is rejected
# because the retriever's encoder truncates long queries silently
# (sentence-transformers default max_seq_length = 256 tokens) and
# we want the failure to be a typed audit-on-rejection rather than
# a quiet semantic degradation.
_TOP_K_CAP = 20
_QUERY_LENGTH_CAP = 500

# Mirrors ``rag.retriever._TECHNIQUE_ID_RE`` for input-shape
# validation. Defined locally rather than imported from the private
# attribute so the tool's contract is explicit at the boundary; the
# two regexes describe the same shape (``T<4 digits>`` plus optional
# ``.<3 digits>`` sub-technique).
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class _RejectionReason(StrEnum):
    """Why a rag_query call was refused.

    `BOTH_INPUTS` and `NO_INPUT` are mutually exclusive cases of
    "exactly one of technique_id and semantic_query must be set".
    `TOP_K_TOO_LARGE` and `QUERY_TOO_LONG` are the bound checks.
    `TECHNIQUE_ID_BAD_SHAPE` catches a `technique_id` that's not the
    canonical ATT&CK form (``T1055`` / ``T1055.001``); the tool
    refuses rather than silently routing to vector search, because
    the agent passed the value as an exact ID and meant it.
    """

    BOTH_INPUTS = "both_inputs"
    NO_INPUT = "no_input"
    TOP_K_TOO_LARGE = "top_k_too_large"
    QUERY_TOO_LONG = "query_too_long"
    TECHNIQUE_ID_BAD_SHAPE = "technique_id_bad_shape"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected rag_query call. Same two-field
    shape as the analytical-tools rejection record so an operator
    paging through the audit chain sees a consistent structure
    across tool families."""

    reason: _RejectionReason
    detail: str | None = None


def _log_rejection(
    case_dir: Path,
    reason: _RejectionReason,
    input_args: dict,
    detail: str | None = None,
) -> None:
    rejection = _RejectionRecord(reason=reason, detail=detail)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_RAG_QUERY_TOOL}:rejected_{reason.value}",
        evidence_id=None,
        input_args=input_args,
        output=rejection,
    )


def _technique_id_in_corpus(retriever: Retriever, technique_id: str) -> bool:
    """Direct lookup against the records list. The retriever stores
    every record's ``technique_id`` as a top-level key; an O(N) scan
    over 697 records is well under a millisecond and avoids
    constructing a side index that would drift from the canonical
    records.json on a re-ingest."""
    return any(
        r.get("technique_id") == technique_id for r in retriever.records
    )


def rag_query(
    *,
    technique_id: str | None = None,
    semantic_query: str | None = None,
    top_k: int = 5,
    case_dir: str = "case-data",
) -> RagQueryResult:
    """Query the ATT&CK corpus by exact technique-ID or by
    semantic-similarity vector search.

    Exactly one of ``technique_id`` and ``semantic_query`` MUST be
    provided.

    For ``technique_id``: if the ID is in the corpus, the retriever's
    short-circuit returns it at rank 1 with ``similarity_score=1.0``
    and fills the remaining slots with the closest semantic
    neighbors (mirrors the week-3 `Retriever.search` behavior). If
    the ID matches the regex but is NOT in the corpus, the tool
    returns ``hits=[]`` — the agent asked for a specific technique;
    we don't surface unrelated semantic neighbors.

    For ``semantic_query``: passes through to ``Retriever.search``
    after length-bounding the input.

    `top_k` is capped at 20 (the schema-level cap, mirrored as a
    typed audit-on-rejection). `semantic_query` is capped at 500
    characters; longer queries are rejected (the encoder silently
    truncates beyond its max-seq length, which would land as
    semantic degradation rather than as a typed error).
    """
    case_dir_path = Path(case_dir).resolve()

    input_args: dict[str, Any] = {
        "technique_id": technique_id,
        "semantic_query": semantic_query,
        "top_k": top_k,
    }

    # 1. Exactly-one-input shape.
    if technique_id is not None and semantic_query is not None:
        _log_rejection(case_dir_path, _RejectionReason.BOTH_INPUTS, input_args)
        raise ValueError(
            "rag_query accepts exactly one of technique_id, semantic_query"
        )
    if technique_id is None and semantic_query is None:
        _log_rejection(case_dir_path, _RejectionReason.NO_INPUT, input_args)
        raise ValueError(
            "rag_query requires technique_id or semantic_query"
        )

    # 2. top_k bound.
    if top_k > _TOP_K_CAP or top_k < 1:
        _log_rejection(
            case_dir_path, _RejectionReason.TOP_K_TOO_LARGE, input_args
        )
        raise ValueError("top_k out of allowed range (1..20)")

    # 3. semantic_query length bound.
    if semantic_query is not None and len(semantic_query) > _QUERY_LENGTH_CAP:
        _log_rejection(
            case_dir_path, _RejectionReason.QUERY_TOO_LONG, input_args
        )
        raise ValueError("semantic_query exceeds 500 characters")

    # 4. technique_id shape — must match the canonical ATT&CK form.
    #    The retriever's short-circuit only fires on this shape; if the
    #    agent passed something else under technique_id, it meant the
    #    exact-ID semantic and we should reject rather than silently
    #    fall through to vector search (which would be the wrong
    #    semantic and would mislead the validator's hypothesis).
    if technique_id is not None and not _TECHNIQUE_ID_RE.match(technique_id):
        _log_rejection(
            case_dir_path,
            _RejectionReason.TECHNIQUE_ID_BAD_SHAPE,
            input_args,
        )
        raise ValueError(
            "technique_id must match T<4 digits>[.<3 digits>] form"
        )

    # 5. Construct the retriever (cheap; lazy model load) and resolve.
    retriever = Retriever()

    if technique_id is not None:
        # Pre-check existence: the retriever's default behavior is to
        # fall through to vector search if the ID isn't in the corpus,
        # which is a different contract from what this tool offers.
        if not _technique_id_in_corpus(retriever, technique_id):
            hits: list[RagHit] = []
            query_value = technique_id
            query_kind: str = "technique_id"
        else:
            results = retriever.search(technique_id, k=top_k)
            hits = [_to_hit(r.model_dump()) for r in results]
            query_value = technique_id
            query_kind = "technique_id"
    else:
        # semantic path. semantic_query is non-None here.
        results = retriever.search(semantic_query, k=top_k)  # type: ignore[arg-type]
        hits = [_to_hit(r.model_dump()) for r in results]
        query_value = semantic_query  # type: ignore[assignment]
        query_kind = "semantic"

    embedding_model_version = retriever.meta.get(
        "embedding_model_version", retriever.model_name
    )

    audit_line = peek_next_line_number(case_dir_path)
    result = RagQueryResult(
        audit_line=audit_line,
        query_kind=query_kind,  # type: ignore[arg-type]
        query_value=query_value,
        hits=hits,
        embedding_model_version=embedding_model_version,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_RAG_QUERY_TOOL,
        evidence_id=None,
        input_args=input_args,
        output=result,
    )
    return result


def _to_hit(record: dict) -> RagHit:
    """Project a `RagRecord.model_dump()` dict onto the agent-facing
    `RagHit` shape. `score` from the retriever is renamed to
    `similarity_score` at the boundary; `source` and `license` are
    dropped (corpus-level, not per-hit).
    """
    score = record.get("score")
    # Retriever fills score on every hit; defensive default keeps
    # construction stable if a future retriever path forgets to set
    # it. The schema bounds [0.0, 1.0] catch any out-of-range value.
    if score is None:
        score = 0.0
    return RagHit(
        technique_id=record["technique_id"],
        name=record["name"],
        description=record["description"],
        kill_chain_phases=record.get("kill_chain_phases", []),
        platforms=record.get("platforms", []),
        citation_url=record["citation_url"],
        similarity_score=float(score),
    )


__all__ = ["rag_query"]
