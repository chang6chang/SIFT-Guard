# `rag/` — forensic knowledge corpus + retrieval

Standalone retrieval pipeline. Standalone meaning: not imported by the
MCP server, not invoked by any tool in the surface today. The week-6
validator subagent is the planned consumer; this PR exists so that
work has something to grind against rather than blocking on a
pipeline that doesn't yet build.

For the source list, licenses, and citation format see
[`SOURCES.md`](./SOURCES.md). The data this directory holds at
runtime — the pinned ATT&CK STIX bundle, the embedded FAISS index,
and its records sidecar — is gitignored under `rag/data/` because
it's regenerable from this script and too big to commit.

## Quick start

```bash
# From the repo root, with the venv active.
pip install -e .[rag]      # pulls sentence-transformers + faiss-cpu
python -m rag.ingest_attack   # downloads ATT&CK, builds rag/data/
```

That's the one command the prompt asks for. After it returns, you can
query the corpus from any Python:

```python
from rag.retriever import Retriever
r = Retriever()
for hit in r.search("hidden process injection", k=5):
    print(f"{hit.score:.3f}  {hit.technique_id}  {hit.name}")
```

## Stack and why

| Choice | Reason |
|---|---|
| `sentence-transformers/all-MiniLM-L6-v2` | 384-dim embeddings, CPU-fast, deterministic, no API call. Pinned to v5.4.1 of the library. |
| `faiss-cpu` (over `sqlite-vss`) | sqlite-vss installs cleanly via pip but its loadable extension links against `libblas.so.3`, which is not in the SIFT VM / WSL2 base image. faiss-cpu bundles its own BLAS in the wheel. The decision matrix says "if sqlite-vss won't install cleanly in 30 minutes, switch to faiss-cpu and document why" — see the prompt for week 3 day 5+. We hit the system-library wall in five minutes; switched. |
| `IndexFlatIP` over normalized vectors | Cosine similarity through inner product — no separate normalization at query time. The corpus is ~1k records; brute-force is sub-millisecond on CPU and removes the HNSW / IVF tuning surface entirely. |

## Idempotency

Same pinned ATT&CK tag + same model version + same library versions
→ same FAISS index byte-for-byte. The chain:

1. `build_records` sorts on `technique_id`, so input ordering noise
   in the upstream JSON doesn't reorder the index.
2. `sentence-transformers` is deterministic on CPU once the model is
   loaded (no dropout in `eval()`, no nondeterministic kernels in the
   stack).
3. FAISS `IndexFlatIP.add()` preserves insertion order; serialization
   via `faiss.write_index` is byte-stable for a given vector matrix.

If you bump `ATTACK_TAG` or the embedding model version, byte
equality breaks by design — the meta sidecar records both pins so
mismatch is caught at retriever load time.

## Layout

```
rag/
├─ __init__.py
├─ schemas.py           # RagRecord pydantic model + cap_description
├─ retriever.py         # Retriever class + module-level search()
├─ ingest_attack.py     # download + parse + embed + write index
├─ SOURCES.md           # source inventory + licenses
├─ README.md            # you are here
└─ data/                # gitignored
   ├─ attack-enterprise.faiss            # FAISS IndexFlatIP
   ├─ attack-enterprise.records.json     # parallel record metadata
   └─ attack-enterprise.meta.json        # pin info, dim, count, build time
```

## Tests

Tests live in `tests/test_rag_*.py`. They use the small fixture at
`tests/fixtures/rag_attack_sample.json` (5 active techniques + a
revoked + a deprecated + two non-attack-pattern objects to exercise
the filter). No network calls; the embedding model loads once and is
reused across the suite.

```bash
pytest -q tests/test_rag_ingest.py tests/test_rag_retriever.py
```

The first run downloads the model (~80 MB) into the
sentence-transformers cache (`~/.cache/huggingface/`). Subsequent
runs are sub-second.

## What this PR does not do

- Does not wire the retriever to the MCP server. There is no
  `rag_search` tool in `server/main.py`. That decision lands when the
  validator's call shape is settled, in week 6.
- Does not ingest SANS posters or Sigma rules. See `SOURCES.md` for
  the deferral reasoning.
- Does not implement re-ranking, hybrid keyword/vector search, or
  per-source weighting. Single similarity score, top-k, no surprises.
