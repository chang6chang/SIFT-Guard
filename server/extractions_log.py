"""Hash-chained JSONL writer for the SIFT-Guard extraction registry.

Tier-1 memory tools (`vol_pslist`, `vol_psscan`, `vol_pstree`,
`vol_netscan`) persist their full result JSON to
`<case_dir>/extractions/<evidence_id>/<plugin_name>.json` and append
one chain line to `<case_dir>/extractions.jsonl` recording the
`(evidence_id, plugin_name)` pair, the SHA-256 of the on-disk JSON
bytes, the record count, and the wall-clock runtime of the
Volatility invocation.

Each line carries the SHA-256 of the previous line's
`this_extraction_hash` in `prev_extraction_hash`, and its own
`this_extraction_hash` is SHA-256 over a canonical serialization of
every other field. Tampering with any field of any line breaks every
subsequent line's chain — same property as `server/audit.py`'s log.

Why a separate file (and a separate writer) from the audit chain:

  - The audit chain records *every* MCP tool invocation, including
    rejections, warnings, and cached re-reads. The extractions chain
    records only the moments a Volatility plugin's full output landed
    on disk — a much sparser sequence.
  - Distinct on-disk files mean a downstream consumer streaming
    extraction provenance does not have to filter out the cache-hit
    and rejection lines that dominate the audit chain.
  - Distinct hash field names (`prev_extraction_hash` /
    `this_extraction_hash` vs `prev_line_hash` / `this_line_hash` /
    `prev_finding_hash` / `this_finding_hash`) mean a line read out
    of context cannot be silently misinterpreted as one of the other
    chains' lines.

Why not yet extracted into a shared `HashChainedJsonl` base: per the
week-5 architecture prompt, the base-class extraction is the *next*
commit. Three duplicated chain writers (audit, findings, extractions)
is exactly the rule-of-three trigger; the abstraction lands cleanly
after this refactor stabilizes.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from server.schemas import ExtractionChainEntry

_EXTRACTIONS_FILENAME = "extractions.jsonl"
_GENESIS_PREV_HASH = "0" * 64


def _read_chain_state(extractions_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_extraction_hash) for the next append.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the next
    line number is one greater than the count of non-blank lines, and
    the previous-hash comes from the last non-blank line's
    `this_extraction_hash`.
    """
    if not extractions_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with extractions_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_extraction_hash"]


def append_extraction_entry(
    case_dir: Path | str,
    evidence_id: str,
    plugin_name: str,
    extraction_id: str,
    extraction_sha256: str,
    record_count: int,
    runtime_seconds: float,
    audit_line: int | None = None,
) -> ExtractionChainEntry:
    """Append one hash-chained record to `<case_dir>/extractions.jsonl`.

    Returns the constructed `ExtractionChainEntry` so the caller can
    embed `extractions_chain_line` and `this_extraction_hash` into
    the `ExtractionRef` it returns to the agent.

    `audit_line` (added 2026-05-06) is the audit-chain line where the
    originating tier-1 plugin invocation will be / was logged. New
    writes always pass it; legacy entries written before this field
    existed default to `None` on read. The chain hash includes it (or
    `None`) starting at the first line where the field is present —
    the existing 3 lines stay byte-identical because we only call this
    function for *new* writes.

    Single-process server: no file lock. If a future multi-process
    design is needed, route extraction writes through a writer-process
    queue rather than layering fcntl into this path.
    """
    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)
    extractions_path = case_dir_path / _EXTRACTIONS_FILENAME

    line_number, prev_extraction_hash = _read_chain_state(extractions_path)
    timestamp = datetime.now(tz=timezone.utc)

    chained_fields = dict(
        line_number=line_number,
        timestamp=timestamp,
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        extraction_id=extraction_id,
        extraction_sha256=extraction_sha256,
        record_count=record_count,
        runtime_seconds=runtime_seconds,
        audit_line=audit_line,
        prev_extraction_hash=prev_extraction_hash,
    )
    this_extraction_hash = ExtractionChainEntry.compute_this_extraction_hash(**chained_fields)

    entry = ExtractionChainEntry(
        line_number=line_number,
        timestamp=timestamp,
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        extraction_id=extraction_id,
        extraction_sha256=extraction_sha256,
        record_count=record_count,
        runtime_seconds=runtime_seconds,
        audit_line=audit_line,
        prev_extraction_hash=prev_extraction_hash,
        this_extraction_hash=this_extraction_hash,
    )

    serialized = entry.model_dump_json()
    with extractions_path.open("a", encoding="utf-8") as f:
        f.write(serialized + "\n")
        f.flush()
        os.fsync(f.fileno())

    return entry


def find_extraction_entry(
    case_dir: Path | str,
    evidence_id: str,
    plugin_name: str,
) -> ExtractionChainEntry | None:
    """Look up the chain entry for a given (evidence_id, plugin_name) pair.

    Returns `None` when no entry exists. The chain is append-only and
    pairs are idempotent (one extraction per pair), so the first match
    is the only match. Linear scan is fine — the chain stays small
    (4 plugins × N evidence files); this is not a hot path.
    """
    case_dir_path = Path(case_dir).resolve()
    extractions_path = case_dir_path / _EXTRACTIONS_FILENAME
    if not extractions_path.exists():
        return None
    with extractions_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            row = json.loads(stripped)
            if row.get("evidence_id") == evidence_id and row.get("plugin_name") == plugin_name:
                return ExtractionChainEntry.model_validate(row)
    return None


__all__ = [
    "append_extraction_entry",
    "find_extraction_entry",
]
