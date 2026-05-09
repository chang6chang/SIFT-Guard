"""Build SigmaHQ Windows-rule RagRecord list for the merged corpus.

Companion to `rag.ingest_attack`. This module produces the
Sigma-side records; index-building is orchestrated by
`rag.build_index`, which calls into both ingest scripts and writes
a single merged FAISS index using `rag.ingest_attack.build_index_files`.

Scope:
  - rules/windows/**/*.yml from the SigmaHQ tarball at the pinned
    release tag (SIGMA_TAG below).
  - Skip rules with status in {"deprecated", "unsupported"}.
  - Skip rules with no ``attack.t<digits>[.<digits>]`` tag — the
    record's `technique_id` field is non-empty by schema, and
    Sigma rules without an ATT&CK technique tag have no canonical
    ID to project onto that field. Removing these rules is a
    documented filter, not a quality judgment.
  - Multiple ATT&CK tags on one rule → first sorted tag wins for
    `technique_id`; the full set is preserved in the description
    so semantic search retrieves on any of them.

License: DRL 1.1 (https://github.com/SigmaHQ/Detection-Rule-License).
DRL 1.1 is permissive (MIT-flavored) with attribution + license-
disclosure requirements. Each record's `description` carries the
rule's `author` field; the corpus-level `license` field carries
"DRL-1.1" so a downstream consumer can cite correctly.

Network dependency: `fetch_sigma_archive()` downloads the tarball
from GitHub at the pinned tag. Tests do NOT call it; they pass a
local rules directory into `build_records()`.

Usage:
    python -m rag.ingest_sigma
    python -m rag.ingest_sigma --output-dir /custom/path
    python -m rag.ingest_sigma --sigma-dir /already/extracted/sigma-r2026-04-01
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from rag.retriever import DEFAULT_EMBEDDING_MODEL
from rag.schemas import RagRecord, cap_description


# Pinned SigmaHQ release. Bump and re-run to refresh.
SIGMA_TAG = "r2026-04-01"
SIGMA_LICENSE = "DRL-1.1 (https://github.com/SigmaHQ/Detection-Rule-License)"
SIGMA_SOURCE = f"SigmaHQ {SIGMA_TAG}"
SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma"

# Status values that exclude a rule from the corpus. SigmaHQ keeps
# `rules/windows/` clean of `deprecated` / `unsupported` (those live
# under separate top-level dirs at the repo root), but we filter
# defensively: a future pin bump might shift the layout.
_EXCLUDED_STATUSES = frozenset({"deprecated", "unsupported"})

# Match the canonical ATT&CK technique tag form on Sigma's `tags`
# field. SigmaHQ uses lower-case `attack.tNNNN` and `attack.tNNNN.NNN`;
# normalization to upper-case `T<digits>[.<digits>]` happens at
# extraction time so the resulting RagRecord.technique_id matches the
# ATT&CK record namespace exactly (the retriever's exact-ID
# short-circuit and the rag_query tool's regex both expect upper-case).
_ATTACK_TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")


def fetch_sigma_archive(tag: str = SIGMA_TAG) -> Path:
    """Download the SigmaHQ source tarball at the pinned tag, extract
    it under a temporary directory, return the path to the extracted
    repo root.

    Idempotent if the same tag is already on disk under
    `/tmp/sigma-ingest/sigma-<tag>` — re-running skips the network call.
    """
    workdir = Path("/tmp/sigma-ingest")
    workdir.mkdir(parents=True, exist_ok=True)
    extracted = workdir / f"sigma-{tag}"
    if extracted.exists() and (extracted / "rules" / "windows").exists():
        return extracted

    url = f"{SIGMA_REPO_URL}/archive/refs/tags/{tag}.tar.gz"
    print(f"Fetching {url} ...", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=60) as resp:
        if resp.status != 200:
            raise RuntimeError(f"fetch failed: HTTP {resp.status} for {url}")
        data = resp.read()
    print(f"  {len(data) // (1024 * 1024)} MiB", file=sys.stderr)

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(path=workdir, filter="data")
    if not extracted.exists():
        raise RuntimeError(
            f"expected extracted dir at {extracted}; tarball top-level directory may have changed"
        )
    return extracted


def _normalized_attack_tags(tags: list[str] | None) -> list[str]:
    """Project Sigma's lower-case `attack.tNNNN[.NNN]` tags onto the
    ATT&CK upper-case form (`T1055`, `T1055.001`). Sorted ascending
    so the first element is deterministic."""
    if not tags:
        return []
    out: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        m = _ATTACK_TAG_RE.match(tag)
        if not m:
            continue
        major, minor = m.group(1), m.group(2)
        out.append(f"T{major}.{minor}" if minor else f"T{major}")
    return sorted(set(out))


def _kill_chain_phases(tags: list[str] | None) -> list[str]:
    """Map Sigma's `attack.<phase>` tags onto ATT&CK kill-chain phase
    names. Anything not matching `attack.<word>` (e.g. attack.tNNNN,
    attack.gNNNN, cve.*) is dropped. Sorted for determinism."""
    if not tags:
        return []
    phases: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        suffix = tag[len("attack.") :]
        if suffix.startswith(("t", "g", "s")) and suffix[1:2].isdigit():
            continue
        # Treat the remainder (e.g. "execution", "persistence") as a
        # phase name.
        phases.add(suffix)
    return sorted(phases)


def _condition_text(detection: dict | None) -> str:
    """Pull a brief detection-condition string from the parsed YAML.
    Sigma's `detection.condition` may be a string or a list of strings;
    fall back to "n/a" if neither is present."""
    if not isinstance(detection, dict):
        return "n/a"
    cond = detection.get("condition")
    if isinstance(cond, str):
        return cond
    if isinstance(cond, list):
        return " | ".join(str(c) for c in cond)
    return "n/a"


def _logsource_text(logsource: dict | None) -> str:
    """Render the rule's logsource block as `key=value` pairs."""
    if not isinstance(logsource, dict):
        return "n/a"
    parts = [f"{k}={v}" for k, v in logsource.items() if v]
    return ", ".join(parts) if parts else "n/a"


def _author_text(author: Any) -> str:
    """Sigma's `author` may be a string or a list. Either way, render
    it as a single string for description embedding (DRL 1.1 requires
    we preserve attribution)."""
    if isinstance(author, list):
        return ", ".join(str(a) for a in author if a)
    if isinstance(author, str):
        return author
    return "Sigma rule authors"


def _build_description(
    doc: dict,
    technique_ids: list[str],
    kill_chain_phases: list[str],
) -> str:
    """Compose the description fed to the encoder. Includes the
    detection logsource and condition so semantic search can match on
    detection-shape queries (e.g. "powershell EncodedCommand"), the
    full set of ATT&CK tags so a query for any of them retrieves the
    rule, and the rule author per DRL 1.1 attribution.

    Output capped at 1000 chars by `cap_description`.
    """
    rule_desc = (doc.get("description") or "").strip()
    detection = doc.get("detection")
    logsource = doc.get("logsource")
    parts = [
        rule_desc if rule_desc else "Sigma detection rule.",
        f"Logsource: {_logsource_text(logsource)}.",
        f"Detection condition: {_condition_text(detection)}.",
    ]
    level = doc.get("level")
    if level:
        parts.append(f"Severity level: {level}.")
    parts.append(f"Authored by: {_author_text(doc.get('author'))}.")
    if technique_ids:
        parts.append(f"ATT&CK techniques: {' '.join(technique_ids)}.")
    if kill_chain_phases:
        parts.append(f"Tactics: {' '.join(kill_chain_phases)}.")
    return cap_description(" ".join(parts))


def _citation_url(rel_path: str, tag: str = SIGMA_TAG) -> str:
    """GitHub blob URL for the rule at the pinned tag. The rule's
    `id` (UUID) doesn't address a stable URL on GitHub; the file path
    does, and is what a reviewer would clone-and-grep against."""
    return f"{SIGMA_REPO_URL}/blob/{tag}/{rel_path}"


def build_records(
    sigma_root: Path,
    embedding_model_version: str = DEFAULT_EMBEDDING_MODEL,
) -> list[RagRecord]:
    """Walk `<sigma_root>/rules/windows/**/*.yml`, project each rule
    onto a RagRecord, return the deterministically-sorted list.

    Filters:
      - Drops rules with `status` in {"deprecated", "unsupported"}.
      - Drops rules with no normalized `attack.tNNNN` tag (no
        technique_id to anchor on).
      - Drops rules whose YAML fails to parse (very rare in SigmaHQ;
        the parse error surfaces in stderr but does not abort the run).

    Sort order: (technique_id, citation_url) — stable across runs and
    across upstream filesystem-ordering changes, which keeps re-runs
    byte-identical at the records-list level.
    """
    rules_dir = sigma_root / "rules" / "windows"
    if not rules_dir.exists():
        raise FileNotFoundError(f"sigma rules dir missing at {rules_dir}; check sigma_root")

    records: list[RagRecord] = []
    skipped_status = 0
    skipped_no_tag = 0
    skipped_parse = 0

    for yml in sorted(rules_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            skipped_parse += 1
            print(f"  parse error in {yml}: {exc}", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            skipped_parse += 1
            continue

        if doc.get("status") in _EXCLUDED_STATUSES:
            skipped_status += 1
            continue

        technique_ids = _normalized_attack_tags(doc.get("tags"))
        if not technique_ids:
            skipped_no_tag += 1
            continue

        primary_tid = technique_ids[0]
        kc_phases = _kill_chain_phases(doc.get("tags"))

        title = (doc.get("title") or "").strip() or primary_tid
        rel_path = yml.relative_to(sigma_root).as_posix()

        records.append(
            RagRecord(
                technique_id=primary_tid,
                name=title,
                description=_build_description(doc, technique_ids, kc_phases),
                source=SIGMA_SOURCE,
                citation_url=_citation_url(rel_path),
                license=SIGMA_LICENSE,
                embedding_model_version=embedding_model_version,
                kill_chain_phases=kc_phases,
                # Every rule under rules/windows/ targets Windows.
                # Sigma's tags don't reliably express platform, so
                # we set this from the directory rather than scraping.
                platforms=["Windows"],
            )
        )

    records.sort(key=lambda r: (r.technique_id, r.citation_url))
    print(
        f"  {len(records)} sigma records "
        f"(skipped: {skipped_status} status / "
        f"{skipped_no_tag} no-attack-tag / "
        f"{skipped_parse} parse-error)",
        file=sys.stderr,
    )
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build SigmaHQ Windows-rule RagRecord list. With "
            "--records-out, emit a JSON file (used by tests / for "
            "inspection); without it, print a record-count summary "
            "and exit. The merged FAISS index is built by "
            "`rag.build_index` which calls into this module."
        )
    )
    parser.add_argument(
        "--sigma-dir",
        type=Path,
        default=None,
        help=(
            "Path to an already-extracted SigmaHQ source tree. "
            "If omitted, the tarball is downloaded at the pinned tag."
        ),
    )
    parser.add_argument(
        "--records-out",
        type=Path,
        default=None,
        help="If set, write the projected records JSON to this path.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_EMBEDDING_MODEL,
        help=f"Embedding-model version tag. Default: {DEFAULT_EMBEDDING_MODEL}",
    )
    args = parser.parse_args(argv)

    sigma_root = args.sigma_dir or fetch_sigma_archive()
    print(f"Reading Sigma rules from {sigma_root} ...", file=sys.stderr)
    records = build_records(sigma_root, embedding_model_version=args.model)

    if args.records_out:
        args.records_out.parent.mkdir(parents=True, exist_ok=True)
        args.records_out.write_text(
            json.dumps([r.model_dump(mode="json") for r in records], indent=2),
            encoding="utf-8",
        )
        print(f"  wrote {len(records)} records to {args.records_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
