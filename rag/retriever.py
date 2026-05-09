"""Retrieval interface for the SIFT-Guard RAG corpus.

Loads a pre-built FAISS index and the parallel records JSON, embeds the
query string with the same model used at ingest time, and returns the
top-k records by cosine similarity.

Storage layout: a directory containing
  - `<name>.faiss` — FAISS IndexFlatIP over normalized embeddings
  - `<name>.records.json` — list[dict] of record payloads, parallel to
    the index by row position
  - `<name>.meta.json` — embedding model version, dimension, index
    size, build timestamp

Pre-normalized vectors + IndexFlatIP gives cosine similarity through
inner product; sklearn-style cosine is unnecessary and would force
re-normalization at query time.

Why a class rather than a free function: a search call typically
amortizes one model load across many queries. The class lets a
caller (e.g. the week-6 validator) construct once and reuse, while
the module-level `search` convenience covers the "one-off CLI query"
case at the cost of reloading the model. Keep both around until the
validator's call pattern is settled.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from rag.schemas import RagRecord


# Exact ATT&CK technique-ID shape: T1055 or T1055.001. The
# embedding model's tokenizer fragments 4-digit IDs into pieces
# shared across techniques (T1055 vs T1003 differ by one subtoken
# whose embedding contributes negligibly to the pooled vector), so
# a query of just "T1055" lands the right technique at rank 3 in
# our fixture rather than rank 1. Detecting the ID shape on the
# query and short-circuiting to a direct lookup is *not* hybrid
# retrieval — there is no second index, no score combination, no
# BM25. It is input normalization: when the query is the canonical
# identifier of a record, return that record. Vector search runs
# normally for every other shape.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Score assigned to an exact-ID hit. Cosine in [-1, 1]; an exact ID
# is by definition the most relevant record, so 1.0 is honest. A
# consumer thresholding on score sees this as "perfect".
_EXACT_ID_SCORE = 1.0


# Pinned. Bumping this requires re-ingesting the index; the meta.json
# `embedding_model_version` field is checked at load time so a stale
# index against a new model fails loudly rather than silently
# corrupting retrieval scores.
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

_INDEX_FILENAME = "attack-enterprise.faiss"
_RECORDS_FILENAME = "attack-enterprise.records.json"
_META_FILENAME = "attack-enterprise.meta.json"

# Default location: rag/data/ relative to the repo root. The package
# does not enforce this; callers can pass any directory.
_DEFAULT_INDEX_DIR = Path(__file__).resolve().parent / "data"


class Retriever:
    """Loads an on-disk RAG index and serves top-k similarity queries."""

    def __init__(
        self,
        index_dir: Path | str | None = None,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
    ) -> None:
        index_dir = Path(index_dir) if index_dir else _DEFAULT_INDEX_DIR

        index_path = index_dir / _INDEX_FILENAME
        records_path = index_dir / _RECORDS_FILENAME
        meta_path = index_dir / _META_FILENAME

        for required in (index_path, records_path, meta_path):
            if not required.exists():
                raise FileNotFoundError(
                    f"RAG index missing at {required}. Run "
                    "`python -m rag.ingest_attack` to build it."
                )

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("embedding_model_version") != model_name:
            # Refuse rather than silently mix model versions — scores
            # would be meaningless across different models.
            raise RuntimeError(
                f"index built with embedding_model_version="
                f"{meta.get('embedding_model_version')!r}, but Retriever "
                f"was constructed with model_name={model_name!r}. "
                "Re-ingest or pass the matching model."
            )

        self.index = faiss.read_index(str(index_path))
        self.records: list[dict[str, Any]] = json.loads(records_path.read_text(encoding="utf-8"))
        if len(self.records) != self.index.ntotal:
            raise RuntimeError(
                f"index/records mismatch: {self.index.ntotal} vectors "
                f"but {len(self.records)} records. Index is corrupt; "
                "re-ingest."
            )

        self.model_name = model_name
        self._model: SentenceTransformer | None = None
        self.meta = meta

    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load the model on first query.

        Construction-time loading would penalize callers that build a
        retriever to inspect metadata without searching."""
        if self._model is None:
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def search(self, query: str, k: int = 5) -> list[RagRecord]:
        """Top-k records by cosine similarity. Scores are in [-1, 1];
        for normalized embeddings on a typical sentence corpus, real
        hits land in roughly [0.3, 0.8].

        Exact-ID short-circuit: a query matching the canonical ATT&CK
        technique-ID shape (`T1055`, `T1055.001`) is looked up
        directly against the records table and returned at rank 1
        with `score == 1.0`. Vector search still runs and fills the
        remaining slots — useful for surfacing related techniques
        alongside the named one. See module-level comment on
        `_TECHNIQUE_ID_RE` for why this is necessary."""
        if not query.strip():
            raise ValueError("query must be non-empty")
        if k < 1:
            raise ValueError("k must be >= 1")

        # Cap at index size — FAISS would silently return fewer
        # without complaint, but explicit is clearer.
        k = min(k, self.index.ntotal)

        results: list[RagRecord] = []
        seen: set[int] = set()

        normalized_query = query.strip()
        if _TECHNIQUE_ID_RE.match(normalized_query):
            for idx, rec in enumerate(self.records):
                if rec.get("technique_id") == normalized_query:
                    payload = dict(rec)
                    payload["score"] = _EXACT_ID_SCORE
                    results.append(RagRecord.model_validate(payload))
                    seen.add(idx)
                    break
            # If the ID isn't in the corpus, fall through to vector
            # search — the user typed a plausible ID we don't have,
            # and a related technique is more useful than nothing.

        emb = self.model.encode([normalized_query], normalize_embeddings=True).astype(np.float32)

        # Pull more candidates than k so we have spares to fill the
        # gap left by the exact-ID hit (and any future dedup logic).
        distances, indices = self.index.search(emb, k + len(seen))

        for idx, score in zip(indices[0], distances[0]):
            if idx < 0:  # FAISS sentinel for "no result"
                continue
            if int(idx) in seen:
                continue
            if len(results) >= k:
                break
            payload = dict(self.records[idx])
            payload["score"] = float(score)
            results.append(RagRecord.model_validate(payload))
            seen.add(int(idx))

        return results


def search(
    query: str,
    k: int = 5,
    index_dir: Path | str | None = None,
    model_name: str = DEFAULT_EMBEDDING_MODEL,
) -> list[RagRecord]:
    """Convenience wrapper: build a Retriever and call search once.

    Reloads the model on every call. Use `Retriever(...).search(...)`
    directly when issuing more than one query."""
    return Retriever(index_dir=index_dir, model_name=model_name).search(query, k=k)


__all__ = ["DEFAULT_EMBEDDING_MODEL", "Retriever", "search"]
