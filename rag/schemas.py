"""Pydantic schemas for the RAG corpus.

`RagRecord` is the typed boundary between the retriever and any
consumer (today: tests; week 6: validator subagent). Every record
carries enough metadata for an LLM consumer to ground a hypothesis
in a named, citable source — `technique_id`, `source`, `citation_url`,
`license` are all load-bearing for that grounding.

`description` is capped at 1000 characters at ingest time so a top-k
retrieval result fits comfortably in an LLM context block. The full
text is preserved in the upstream MITRE CTI STIX file at the pinned
revision (see rag/SOURCES.md) — analysts who need the rest can
re-fetch from source.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


_DESCRIPTION_LIMIT = 1000
_TRUNCATION_SUFFIX = " [truncated, see citation_url for full text]"


class RagRecord(BaseModel):
    """One retrievable corpus entry.

    Today: a MITRE ATT&CK technique. The schema is deliberately narrow
    rather than source-specific — when SANS poster sections and Sigma
    rules land in later PRs they will populate the same fields with
    different `source` and `citation_url` values. If a future source
    cannot be projected onto this shape, that's a design conversation,
    not a "subclass it" reflex.
    """

    technique_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str
    source: str = Field(min_length=1)
    citation_url: str = Field(min_length=1)
    license: str = Field(min_length=1)
    embedding_model_version: str = Field(min_length=1)

    # Optional ATT&CK metadata. Useful to the validator for narrowing
    # candidates by attack-chain phase or affected platform; absent for
    # non-ATT&CK sources, hence default-empty rather than required.
    kill_chain_phases: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)

    # Filled in by the retriever, not at ingest time. Stored on the
    # record so the consumer can sort, threshold, or display the score
    # alongside the citation without re-running the search.
    score: float | None = None

    model_config = ConfigDict(extra="forbid")


def cap_description(text: str, limit: int = _DESCRIPTION_LIMIT) -> str:
    """Truncate `text` to `limit` chars, appending a "see citation"
    suffix if a cut was made. The suffix points the consumer to the
    canonical source rather than leaving a sentence dangling — keeps
    the LLM from inventing the rest."""
    if len(text) <= limit:
        return text
    keep = limit - len(_TRUNCATION_SUFFIX)
    return text[:keep] + _TRUNCATION_SUFFIX


__all__ = ["RagRecord", "cap_description"]
