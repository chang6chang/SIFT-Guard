"""Build the merged RAG FAISS index from multiple corpora.

Canonical entry point for re-ingesting the corpus going forward. Reads
the per-corpus record JSONs (ATT&CK and Sigma today; SANS posters
later), concatenates, embeds with the same model used at single-source
ingest time, and overwrites `rag/data/attack-enterprise.{faiss,
records.json,meta.json}` with the merged result.

Filename rationale: the retriever's file constants are
`attack-enterprise.*` (single-corpus historical name). Rather than
rename — which churns retriever, server tool, and four tests — we
keep the names and overwrite their contents with the merged corpus.
The corpus identity lives in `meta.json`'s `sources` list, which is
the authoritative description of what's in the index.

Usage:
    python -m rag.build_index
    python -m rag.build_index --skip-attack-fetch    # uses cached records.json
    python -m rag.build_index --skip-sigma-fetch     # uses cached records.json
    python -m rag.build_index --output-dir /custom/path

The script is idempotent given the same pinned source tags. Re-running
without bumping `ATTACK_TAG` or `SIGMA_TAG` writes byte-identical
files (sentence-transformers' all-MiniLM-L6-v2 is deterministic on
CPU; the merge sort key is the per-record SHA-stable
`(source, technique_id, citation_url)` tuple).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from rag import ingest_attack, ingest_sigma
from rag.retriever import (
    DEFAULT_EMBEDDING_MODEL,
    _INDEX_FILENAME,
    _META_FILENAME,
    _RECORDS_FILENAME,
)
from rag.schemas import RagRecord


# Per-corpus side-car file names. These hold the projected records for
# inspection / partial-rebuild flows. They are NOT what the retriever
# reads — `_RECORDS_FILENAME` is the merged file the retriever loads.
_ATTACK_RECORDS_SIDECAR = "attack-only.records.json"
_SIGMA_RECORDS_SIDECAR = "sigma-windows.records.json"


def _embedding_text(record: RagRecord) -> str:
    """Reuse the same composition as `ingest_attack._embedding_text`
    so ATT&CK records embed identically across the legacy
    single-source build and this merged build. Sigma records carry
    their detection summary in `description`, so the same composition
    naturally pulls that into the embedding."""
    return f"{record.technique_id} {record.name}. {record.description}"


def _load_or_build_attack_records(
    output_dir: Path,
    skip_fetch: bool,
    embedding_model_version: str,
) -> list[RagRecord]:
    """Either reload the ATT&CK records JSON from disk (if cached and
    --skip-attack-fetch was passed) or fetch the upstream STIX bundle
    and project it through `ingest_attack.build_records`.

    The cached path lives at `<output_dir>/attack-only.records.json`
    so it does NOT collide with `attack-enterprise.records.json`
    (which is the merged file the retriever reads).
    """
    cache = output_dir / _ATTACK_RECORDS_SIDECAR
    if skip_fetch and cache.exists():
        print(f"  reading cached ATT&CK records from {cache}", file=sys.stderr)
        return [
            RagRecord.model_validate(d)
            for d in json.loads(cache.read_text(encoding="utf-8"))
        ]
    print("Fetching MITRE ATT&CK STIX bundle ...", file=sys.stderr)
    bundle = ingest_attack.fetch_attack_bundle()
    records = ingest_attack.build_records(
        bundle, embedding_model_version=embedding_model_version
    )
    print(f"  {len(records)} ATT&CK records", file=sys.stderr)
    return records


def _load_or_build_sigma_records(
    output_dir: Path,
    skip_fetch: bool,
    embedding_model_version: str,
) -> list[RagRecord]:
    """Mirror of `_load_or_build_attack_records` for the Sigma side."""
    cache = output_dir / _SIGMA_RECORDS_SIDECAR
    if skip_fetch and cache.exists():
        print(f"  reading cached Sigma records from {cache}", file=sys.stderr)
        return [
            RagRecord.model_validate(d)
            for d in json.loads(cache.read_text(encoding="utf-8"))
        ]
    sigma_root = ingest_sigma.fetch_sigma_archive()
    print(f"Reading Sigma rules from {sigma_root} ...", file=sys.stderr)
    records = ingest_sigma.build_records(
        sigma_root, embedding_model_version=embedding_model_version
    )
    return records


def _write_sidecar(
    records: list[RagRecord], path: Path
) -> None:
    """Persist the per-corpus records list to a side-car JSON. Used
    by the --skip-*-fetch flags on subsequent runs to avoid re-hitting
    the network."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            [r.model_dump(mode="json") for r in records], indent=2
        ),
        encoding="utf-8",
    )


def _merge_and_sort(
    attack: list[RagRecord], sigma: list[RagRecord]
) -> list[RagRecord]:
    """Concatenate then sort deterministically.

    Sort key: (source, technique_id, citation_url).

    Why source-first: the exact-ID short-circuit in
    `Retriever.search()` returns the FIRST record matching a queried
    technique_id. Sorting by source first means the ATT&CK-source
    record always comes before any Sigma rule with the same
    technique_id, so a query for `technique_id="T1055"` lands the
    canonical ATT&CK definition at rank 1 with score=1.0 — Sigma
    rules tagged T1055 fill the rest via vector search, which is the
    intended behavior (definition first, then detections).

    `MITRE ATT&CK Enterprise ATT&CK-v19.0` < `SigmaHQ r2026-04-01`
    lexicographically, so plain string sort yields the right
    ATT&CK-before-Sigma order. If a future source breaks that
    invariant, this sort key gains a per-source-priority prefix.
    """
    return sorted(
        list(attack) + list(sigma),
        key=lambda r: (r.source, r.technique_id, r.citation_url),
    )


def write_combined_index(
    records: list[RagRecord],
    output_dir: Path,
    sources: list[dict[str, Any]],
    embedding_model_version: str = DEFAULT_EMBEDDING_MODEL,
) -> dict[str, Any]:
    """Encode the merged record list and overwrite the canonical
    retriever file-set in `output_dir`.

    Parallels `ingest_attack.build_index_files` but emits a
    multi-corpus meta.json shape:

      embedding_model_version, embedding_dim, record_count,
      sources: list[dict], built_at

    For backward-compat with tests / consumers that read the legacy
    single-source keys, when `sources` has exactly one entry we also
    emit `source` / `license` / (`attack_tag` if present) at the top
    level.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if not records:
        raise ValueError("no records to index")
    if not sources:
        raise ValueError("sources list is required for the merged meta")

    model = SentenceTransformer(embedding_model_version)
    dim = model.get_embedding_dimension()

    texts = [_embedding_text(r) for r in records]
    embeddings = model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=64,
    ).astype(np.float32)
    assert embeddings.shape == (len(records), dim), (
        f"unexpected embedding shape {embeddings.shape}"
    )

    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    index_path = output_dir / _INDEX_FILENAME
    records_path = output_dir / _RECORDS_FILENAME
    meta_path = output_dir / _META_FILENAME

    faiss.write_index(index, str(index_path))
    records_path.write_text(
        json.dumps(
            [r.model_dump(mode="json") for r in records], indent=2
        ),
        encoding="utf-8",
    )

    meta: dict[str, Any] = {
        "embedding_model_version": embedding_model_version,
        "embedding_dim": dim,
        "record_count": len(records),
        "sources": sources,
        "built_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    if len(sources) == 1:
        s = sources[0]
        meta["source"] = s["name"]
        meta["license"] = s["license"]
        if "tag" in s and "attack" in s["name"].lower():
            meta["attack_tag"] = s["tag"]
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the merged RAG FAISS index over MITRE ATT&CK + "
            "SigmaHQ Windows rules. Overwrites the canonical "
            "rag/data/attack-enterprise.{faiss,records.json,meta.json}."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "data",
        help="Index output directory. Default: rag/data/",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_EMBEDDING_MODEL,
        help=f"Embedding model. Default: {DEFAULT_EMBEDDING_MODEL}",
    )
    parser.add_argument(
        "--skip-attack-fetch",
        action="store_true",
        help=(
            "Use the cached attack-only.records.json instead of "
            "fetching the upstream STIX bundle."
        ),
    )
    parser.add_argument(
        "--skip-sigma-fetch",
        action="store_true",
        help=(
            "Use the cached sigma-windows.records.json instead of "
            "downloading the SigmaHQ tarball."
        ),
    )
    args = parser.parse_args(argv)

    attack = _load_or_build_attack_records(
        args.output_dir, args.skip_attack_fetch, args.model
    )
    sigma = _load_or_build_sigma_records(
        args.output_dir, args.skip_sigma_fetch, args.model
    )

    # Persist sidecars for subsequent --skip-*-fetch runs and for
    # inspection. Idempotent: same input → same output.
    _write_sidecar(attack, args.output_dir / _ATTACK_RECORDS_SIDECAR)
    _write_sidecar(sigma, args.output_dir / _SIGMA_RECORDS_SIDECAR)

    merged = _merge_and_sort(attack, sigma)
    print(
        f"Merged corpus: {len(attack)} ATT&CK + {len(sigma)} Sigma "
        f"= {len(merged)} records",
        file=sys.stderr,
    )

    sources = [
        {
            "name": ingest_attack.ATTACK_SOURCE,
            "license": ingest_attack.ATTACK_LICENSE,
            "tag": ingest_attack.ATTACK_TAG,
            "record_count": len(attack),
        },
        {
            "name": ingest_sigma.SIGMA_SOURCE,
            "license": ingest_sigma.SIGMA_LICENSE,
            "tag": ingest_sigma.SIGMA_TAG,
            "record_count": len(sigma),
        },
    ]

    print(
        f"Embedding + writing merged index → {args.output_dir} ...",
        file=sys.stderr,
    )
    meta = write_combined_index(
        merged,
        args.output_dir,
        sources=sources,
        embedding_model_version=args.model,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
