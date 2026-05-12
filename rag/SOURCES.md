# RAG corpus sources

This file is the inventory of upstream knowledge sources the SIFT-Guard
RAG pipeline draws from. Every record returned by `rag.retriever.search`
carries its `source`, `citation_url`, and `license` so the validator
subagent can ground its correlation hypotheses in named, attributable
text.

When adding a new source, append a section here, set the `source` and
`license` fields on the records produced by the ingest script, and
document the parsing decisions so a re-run is reproducible.

---

## MITRE ATT&CK Enterprise

| Field | Value |
|---|---|
| Source name | `MITRE ATT&CK Enterprise <tag>` |
| Pinned release | `ATT&CK-v19.0` |
| Upstream URL | https://github.com/mitre/cti |
| File fetched | `enterprise-attack/enterprise-attack.json` (STIX 2.1 bundle) |
| Resolved URL | `https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.0/enterprise-attack/enterprise-attack.json` |
| License | **CC-BY 4.0** (https://creativecommons.org/licenses/by/4.0/) |
| Citation per record | The `external_references[0].url` for each technique, e.g. `https://attack.mitre.org/techniques/T1055/` |
| Records produced | One `RagRecord` per `attack-pattern` STIX object, excluding any with `revoked: true` or `x_mitre_deprecated: true` |
| Filtered fields | `technique_id`, `name`, `description` (capped at 1000 chars), `kill_chain_phases`, `x_mitre_platforms`, citation URL |

### Citation format (CC-BY 4.0 attribution)

When surfacing an ATT&CK record to the user (or to a downstream LLM),
the response must attribute MITRE. Recommended format:

> "MITRE ATT&CK®, *<Technique Name>*, <Technique ID>, <citation_url>.
> © The MITRE Corporation. Licensed under CC-BY 4.0."

The pinned tag (`ATT&CK-v19.0`) should be cited explicitly when
reproducibility matters — ATT&CK techniques can be revised, deprecated,
or revoked between releases, and a finding referencing T1055 means
something different against v15 vs v19.

### Refresh procedure

When MITRE ships a new ATT&CK release and we want to upgrade:

1. Edit `rag/ingest_attack.py`, change `ATTACK_TAG` to the new tag.
2. Run `python -m rag.build_index` (regenerates `rag/data/`).
3. Re-run unit tests — fixture covers structural invariants and is
   independent of the upstream version.
4. Run a smoke retrieval — the fixture-coverage test catches schema
   drift but not "MITRE renamed T1055" semantic drift.
5. Update this file's "Pinned release" row.
6. Commit: pin bump only — no source-tree changes.

---

## SigmaHQ Windows rules

| Field | Value |
|---|---|
| Source name | `SigmaHQ <tag>` |
| Pinned release | `r2026-04-01` |
| Upstream URL | https://github.com/SigmaHQ/sigma |
| File fetched | `sigma-r2026-04-01.tar.gz` (release tarball, ~7 MiB) |
| Resolved URL | `https://github.com/SigmaHQ/sigma/archive/refs/tags/r2026-04-01.tar.gz` |
| License | **DRL 1.1** (https://github.com/SigmaHQ/Detection-Rule-License) |
| Citation per record | GitHub blob URL at the pinned tag, e.g. `https://github.com/SigmaHQ/sigma/blob/r2026-04-01/rules/windows/process_creation/proc_creation_win_…yml` |
| Records produced | One `RagRecord` per file in `rules/windows/**/*.yml`, after filters below |
| Filtered fields | `technique_id` (first sorted `attack.tNNNN[.NNN]` tag, normalized to `T<digits>[.<digits>]`), `name` (rule title), `description` (rule description + logsource + detection condition + level + author + full ATT&CK tag list, capped at 1000 chars), `kill_chain_phases` (from `attack.<phase>` tags), `platforms = ["Windows"]` |

### Filters applied at ingest

- **Status filter:** rules with `status` ∈ {`deprecated`, `unsupported`} are skipped. SigmaHQ keeps `rules/windows/` clean of these as of `r2026-04-01` (they live under top-level `deprecated/` and `unsupported/` directories), but the filter is defensive against future layout changes.
- **ATT&CK-tag filter:** rules without any `attack.t<digits>[.<digits>]` tag are skipped, because `RagRecord.technique_id` is non-empty by schema and Sigma rules with no ATT&CK technique have no canonical ID to project onto that field. This is a documented filter, not a quality judgment — the dropped rules are typically generic Windows-event-log signatures.
- **Multiple ATT&CK tags:** the first sorted tag (e.g. `T1003` < `T1055.001`) becomes `technique_id`. The full tag list is preserved verbatim in `description`, so semantic search retrieves the rule on a query referencing any of its tagged techniques.

### Citation format (DRL 1.1 attribution)

DRL 1.1 requires preserving the rule's `author` field when sharing
or matching against the rule. Each `RagRecord.description` includes
the line `Authored by: <author>.`; the corpus-level
`RagRecord.license` field carries the DRL identifier. When the
validator surfaces a Sigma rule in a correlation hypothesis, the
recommended attribution is:

> "<Rule Title>, SigmaHQ <tag>, authored by <author>, <citation_url>.
> Licensed under DRL-1.1."

### Refresh procedure

1. Edit `rag/ingest_sigma.py`, change `SIGMA_TAG` to the new release tag (e.g. `r2026-07-01`).
2. Run `python -m rag.build_index` (regenerates `rag/data/`).
3. Re-run unit tests.
4. Update this file's "Pinned release" row.
5. Commit: pin bump only — no source-tree changes.

### Why a single merged index, not two

Both ATT&CK and Sigma records share the `RagRecord` schema and
the same embedding model, so a single FAISS index serves both.
The retriever's exact-ID short-circuit is sort-stable and the
merge sort key (`source, technique_id, citation_url`) places
ATT&CK records before Sigma records with the same `technique_id`
— a query for `technique_id="T1055"` lands the canonical ATT&CK
definition at rank 1 and fills the rest with relevant Sigma
detections via vector search. Two indexes would force the caller
to choose; one index lets the retriever choose for them.

---

## Deferred to a later PR

### SANS DFIR cheatsheet posters
Status: deferred. Adds PDF parsing, OCR fallback for image-heavy
sections. License varies per poster — typically permissive for
non-commercial educational reuse, but each must be verified
individually before extraction. The SANS Hunt Evil poster and the
SANS Windows Forensic Analysis poster are the priority targets.
