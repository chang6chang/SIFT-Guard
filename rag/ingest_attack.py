"""Build the MITRE ATT&CK enterprise FAISS index.

One-shot, idempotent given the pinned ATT&CK release: same input STIX
file + same model version → same index byte-for-byte (verified — sort
order is stable on technique_id, sentence-transformers' all-MiniLM-L6-v2
is deterministic on CPU). Re-running this script after the upstream
ATT&CK pin is bumped is the supported way to refresh the corpus.

Network dependency: downloads `enterprise-attack.json` from MITRE's
CTI repo at the pinned tag. Tests do NOT call this — they pass a
pre-extracted fixture into `build_records` / `build_index_files`.

Usage:
    python -m rag.ingest_attack
    python -m rag.ingest_attack --output-dir /custom/path
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from rag.retriever import (
    DEFAULT_EMBEDDING_MODEL,
    _INDEX_FILENAME,
    _META_FILENAME,
    _RECORDS_FILENAME,
)
from rag.schemas import RagRecord, cap_description


# Pinned ATT&CK release. Bump this — and re-run ingest — when the
# corpus needs refreshing. The tag's `&` is URL-encoded for raw
# fetches.
ATTACK_TAG = "ATT&CK-v19.0"
ATTACK_LICENSE = "CC-BY 4.0"
ATTACK_SOURCE = f"MITRE ATT&CK Enterprise {ATTACK_TAG}"


def attack_url() -> str:
    """Pinned-tag raw URL for the enterprise ATT&CK STIX bundle."""
    encoded_tag = urllib.parse.quote(ATTACK_TAG, safe="")
    return (
        f"https://raw.githubusercontent.com/mitre/cti/{encoded_tag}/"
        "enterprise-attack/enterprise-attack.json"
    )


def _technique_id_of(obj: dict[str, Any]) -> str | None:
    """Pull the human technique ID (e.g. ``T1055`` or ``T1055.001``)
    from a STIX attack-pattern's external_references. ATT&CK records
    these under source_name=="mitre-attack"."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
            return ref["external_id"]
    return None


def _citation_url_of(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and "url" in ref:
            return ref["url"]
    return None


def _kill_chain_phases(obj: dict[str, Any]) -> list[str]:
    """Phase names from kill_chain_phases entries whose chain matches
    ATT&CK. STIX permits multiple chains in one object, but enterprise
    ATT&CK uses ``mitre-attack`` exclusively for technique objects."""
    phases: list[str] = []
    for kc in obj.get("kill_chain_phases", []) or []:
        if kc.get("kill_chain_name") == "mitre-attack" and "phase_name" in kc:
            phases.append(kc["phase_name"])
    return phases


def build_records(
    stix_bundle: dict[str, Any],
    embedding_model_version: str = DEFAULT_EMBEDDING_MODEL,
) -> list[RagRecord]:
    """Project a STIX bundle dict into the ordered RagRecord list.

    Filters: type == "attack-pattern", not revoked, not deprecated.
    Sub-techniques are kept (their technique_id is e.g. T1055.001).
    Sort key is technique_id — stable across runs and across reorderings
    of the upstream JSON, which is the cheapest path to byte-identical
    rebuilds.
    """
    raw: list[RagRecord] = []
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked"):
            continue
        if obj.get("x_mitre_deprecated"):
            continue

        tid = _technique_id_of(obj)
        if tid is None:
            # Should not happen for a well-formed enterprise bundle;
            # skip the row rather than fabricate an ID.
            continue
        url = (
            _citation_url_of(obj) or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        )
        raw.append(
            RagRecord(
                technique_id=tid,
                name=obj.get("name") or tid,
                description=cap_description(obj.get("description") or ""),
                source=ATTACK_SOURCE,
                citation_url=url,
                license=ATTACK_LICENSE,
                embedding_model_version=embedding_model_version,
                kill_chain_phases=_kill_chain_phases(obj),
                platforms=list(obj.get("x_mitre_platforms") or []),
            )
        )
    raw.sort(key=lambda r: r.technique_id)
    return raw


def _embedding_text(record: RagRecord) -> str:
    """Compose the string fed to the encoder.

    Putting the technique_id first means an exact-ID query
    (``"T1055"``) anchors strongly on the tokenized prefix. The
    description is included so semantic queries (``"hidden process"``)
    have content to match against. We rely on the model's internal
    truncation rather than pre-cutting — all-MiniLM-L6-v2 caps at 256
    tokens which on natural English is roughly the first ~1000 chars,
    matching our stored description cap."""
    return f"{record.technique_id} {record.name}. {record.description}"


def build_index_files(
    records: list[RagRecord],
    output_dir: Path,
    embedding_model_version: str = DEFAULT_EMBEDDING_MODEL,
) -> dict[str, Any]:
    """Encode records, write FAISS index + records.json + meta.json.

    Returns the meta dict (also written to disk) so callers/tests can
    assert on the build outcome without re-reading the file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    model = SentenceTransformer(embedding_model_version)
    dim = model.get_embedding_dimension()

    # Empty corpus is a programmer error — refuse rather than emit an
    # empty FAISS index that retrieval will silently treat as "no
    # results for every query".
    if not records:
        raise ValueError("no records to index")

    texts = [_embedding_text(r) for r in records]
    embeddings = model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=64,
    ).astype(np.float32)
    assert embeddings.shape == (len(records), dim), f"unexpected embedding shape {embeddings.shape}"

    # IndexFlatIP over normalized vectors == cosine similarity.
    # No HNSW / IVF — the corpus is ~1k records, brute force fits in
    # ~3 MB and a single search is sub-millisecond.
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    index_path = output_dir / _INDEX_FILENAME
    records_path = output_dir / _RECORDS_FILENAME
    meta_path = output_dir / _META_FILENAME

    faiss.write_index(index, str(index_path))
    records_path.write_text(
        # `mode="json"` so pydantic emits ISO timestamps / enum strings
        # rather than Python objects.
        json.dumps([r.model_dump(mode="json") for r in records], indent=2),
        encoding="utf-8",
    )

    meta = {
        "embedding_model_version": embedding_model_version,
        "embedding_dim": dim,
        "record_count": len(records),
        "source": ATTACK_SOURCE,
        "license": ATTACK_LICENSE,
        "attack_tag": ATTACK_TAG,
        "built_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def fetch_attack_bundle() -> dict[str, Any]:
    """Download and parse the pinned enterprise ATT&CK STIX bundle."""
    url = attack_url()
    with urllib.request.urlopen(url, timeout=60) as resp:
        if resp.status != 200:
            raise RuntimeError(f"fetch failed: HTTP {resp.status} for {url}")
        return json.loads(resp.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the MITRE ATT&CK enterprise FAISS index. Downloads "
            "the pinned STIX bundle, parses it into RagRecords, embeds "
            "with sentence-transformers, and writes the index files."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "data",
        help="Directory to write the index files into. Default: rag/data/",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_EMBEDDING_MODEL,
        help=f"Embedding model. Default: {DEFAULT_EMBEDDING_MODEL}",
    )
    args = parser.parse_args(argv)

    print(f"Fetching {attack_url()} ...", file=sys.stderr)
    bundle = fetch_attack_bundle()
    print(
        f"  {len(bundle.get('objects', []))} STIX objects",
        file=sys.stderr,
    )

    records = build_records(bundle, embedding_model_version=args.model)
    print(f"  {len(records)} attack-pattern records after filter", file=sys.stderr)

    print(f"Embedding + writing index → {args.output_dir} ...", file=sys.stderr)
    meta = build_index_files(records, args.output_dir, embedding_model_version=args.model)
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
