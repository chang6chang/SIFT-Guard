# `rag/` — forensic knowledge corpus + retrieval

Local-only RAG over MITRE ATT&CK Enterprise + SigmaHQ Windows rules,
exposed as a single MCP tool (`mcp__sift-guard__rag_query`) that the
validator subagent calls during the CORRELATE stage of the
self-correction loop. The retriever runs entirely on CPU, embeddings
are deterministic for a given pinned model + corpus snapshot, and
every record carries `source` / `citation_url` / `license` so
correlation hypotheses can be grounded in named, attributable text.

For the source list, pinned tags, license terms, and citation format
see [`SOURCES.md`](./SOURCES.md). The built artifacts under
`rag/data/` are gitignored — regenerable from this script and too
big to commit.

## Quick start

```bash
# From the repo root, with the venv active.
pip install -e ".[rag]"        # pulls sentence-transformers + faiss-cpu
python -m rag.build_index      # downloads ATT&CK + SigmaHQ, embeds, writes rag/data/
```

`setup-sift-guard.sh` runs `build_index` automatically as Step 10
on a fresh install. The CLI smoke test only fails the run when the
index file is missing AND the build fails — a degraded run without
`rag_query` is preferred to no run at all.

After build, query from any Python process:

```python
from rag.retriever import search

for hit in search("hidden process injection", k=5):
    print(f"{hit.score:.3f}  {hit.technique_id}  {hit.name}  ({hit.source})")
```

The MCP tool wraps the same `search` function:
`mcp__sift-guard__rag_query(query="hidden process injection", k=5)`.
The validator's frontmatter
(`.claude/agents/validator.md`) is the only place this tool is
listed — analysts cannot call it directly.

## Stack and why

| Choice | Reason |
|---|---|
| `sentence-transformers/all-MiniLM-L6-v2` | 384-dim embeddings, CPU-fast, deterministic, no API call. Pinned to the version in `pyproject.toml`. |
| `faiss-cpu` (over `sqlite-vss`) | `sqlite-vss` installs cleanly via pip but its loadable extension links against `libblas.so.3`, which is not in the SIFT VM base image. `faiss-cpu` bundles its own BLAS in the wheel. |
| `IndexFlatIP` over normalized vectors | Cosine similarity through inner product — no separate normalization at query time. The corpus is ~2.8k records; brute-force is sub-millisecond on CPU and removes the HNSW / IVF tuning surface entirely. |
| Single merged index (ATT&CK + Sigma) | Same schema, same embedding model. Merge sort places ATT&CK records before Sigma records sharing a `technique_id` — a query for `T1055` returns the canonical definition at rank 1 followed by relevant detection rules via vector search. |

## Idempotency

Same pinned `ATTACK_TAG` + same pinned `SIGMA_TAG` + same model
version + same library versions → same FAISS index byte-for-byte.

1. `build_records` in each ingester sorts records on
   `(source, technique_id, citation_url)`, so input ordering noise
   in the upstream JSON / tarball doesn't reorder the index.
2. `sentence-transformers` is deterministic on CPU once the model
   is loaded (no dropout in `eval()`, no nondeterministic kernels
   in the stack).
3. FAISS `IndexFlatIP.add()` preserves insertion order;
   `faiss.write_index` is byte-stable for a given vector matrix.

If you bump `ATTACK_TAG` or `SIGMA_TAG` or the embedding model
pin, byte equality breaks by design — the `meta.json` sidecar
records all three pins so a mismatch is caught at retriever load
time and logged.

## Layout

```
rag/
├─ __init__.py
├─ schemas.py           # RagRecord pydantic model + cap_description
├─ retriever.py         # Retriever class + module-level search()
├─ ingest_attack.py     # MITRE ATT&CK STIX bundle → RagRecord list
├─ ingest_sigma.py      # SigmaHQ Windows rules tarball → RagRecord list
├─ build_index.py       # merge corpora + embed + write rag/data/
├─ SOURCES.md           # source inventory, pinned tags, licenses
├─ README.md            # you are here
└─ data/                # gitignored
   ├─ attack-enterprise.faiss            # FAISS IndexFlatIP (merged)
   ├─ attack-enterprise.records.json     # parallel record metadata
   ├─ attack-enterprise.meta.json        # pin info, dim, count, build time
   ├─ attack-only.records.json           # ATT&CK-only records (intermediate)
   └─ sigma-windows.records.json         # Sigma-only records (intermediate)
```

The retriever reads only the three `attack-enterprise.*` files; the
`attack-only.records.json` and `sigma-windows.records.json` files
are intermediate per-corpus dumps the merger consumes. They stay on
disk so an incremental rebuild (e.g. Sigma tag bump only) can reuse
the unchanged corpus without re-fetching from GitHub.

## Tests

Tests live in `tests/test_rag_ingest.py` and
`tests/test_rag_retriever.py`. They use the small fixture at
`tests/fixtures/rag_attack_sample.json` (5 active techniques + a
revoked + a deprecated + two non-attack-pattern objects to exercise
the filter). No network calls; the embedding model loads once and
is reused across the suite.

```bash
pytest -q tests/test_rag_ingest.py tests/test_rag_retriever.py
```

The first run downloads the model (~80 MB) into the
sentence-transformers cache (`~/.cache/huggingface/`). Subsequent
runs are sub-second.

## Not implemented (deferred)

- **SANS DFIR cheatsheet posters.** Adds PDF parsing and per-poster
  license verification. See `SOURCES.md` for the priority targets.
- **Hybrid keyword + vector search.** Current retrieval is
  pure-vector with an exact-ID short-circuit for `technique_id`
  queries. Adding BM25 over the description field would help on
  rare-term queries; the corpus is small enough that the FAISS
  scan still dominates wall-clock either way.
- **Per-source weighting.** Every record has equal weight at
  retrieval time. Boosting ATT&CK above Sigma (or vice versa) is
  one config-flag away if a use case emerges.
