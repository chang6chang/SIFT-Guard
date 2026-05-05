# RAG corpus sources

This file is the inventory of upstream knowledge sources the SIFT-Guard
RAG pipeline draws from. Every record returned by `rag.retriever.search`
carries its `source`, `citation_url`, and `license` so the week-6
validator can ground hypotheses in named, attributable text.

When adding a new source, append a section here, set the `source` and
`license` fields on the records produced by the ingest script, and
document the parsing decisions so a re-run is reproducible.

---

## MITRE ATT&CK Enterprise — present in this PR

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
2. Run `python -m rag.ingest_attack` (regenerates `rag/data/`).
3. Re-run unit tests — fixture covers structural invariants and is
   independent of the upstream version.
4. Run a smoke retrieval — the fixture-coverage test catches schema
   drift but not "MITRE renamed T1055" semantic drift.
5. Update this file's "Pinned release" row.
6. Commit: pin bump only — no source-tree changes.

---

## Deferred to a later PR

Two more sources are planned for the corpus. They are intentionally
not in this PR — each has its own ingest pipeline (PDF parsing for
SANS, YAML parsing for Sigma) and would expand the surface area of a
test that should be focused on getting one source end-to-end.

### SANS DFIR cheatsheet posters
Status: deferred. Adds PDF parsing, OCR fallback for image-heavy
sections. License varies per poster — typically permissive for
non-commercial educational reuse, but each must be verified
individually before extraction. The SANS Hunt Evil poster and the
SANS Windows Forensic Analysis poster are the priority targets.

### Sigma detection rule corpus
Status: deferred. Adds YAML parsing of the upstream
`SigmaHQ/sigma` repository, filtered to `windows/` rules. Useful
for the validator to ground "this looks like persistence via
ScheduledTask" claims in a published detection. License: DRL
(Detection Rule License, MIT-compatible) — record per Sigma rule
file's `license` field.

Both expansions are scoped for the post-hackathon week: a 1-2 KB
Sigma rule has very different retrieval characteristics than a
multi-paragraph ATT&CK technique, and we don't yet know whether to
mix them in a single index or run separate indexes per source. Doing
ATT&CK first lets us answer that question with real numbers.
