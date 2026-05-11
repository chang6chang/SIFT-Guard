"""Hash-chained JSONL writer for SIFT-Guard findings.

Findings written by `record_finding` land in
`<case_dir>/findings.jsonl` as one wrapper line per finding. Each
line carries the sha256 of the previous line's `this_finding_hash`
in `prev_finding_hash`, and its own `this_finding_hash` is sha256
over a canonical serialization of the rest of the record. Same
tamper-evident-chain property as `server/audit.py`'s log.

Why a separate file (and a separate writer) from the audit chain:

  - The audit chain records *what the server's parent process did*:
    every MCP tool invocation, including rejections and warnings.
    Findings are *what analysts claim*, structurally distinct from
    "I observed a tool call".
  - Distinct on-disk files mean a downstream consumer can stream
    one without parsing the other.
  - Distinct hash field names (`prev_finding_hash` /
    `this_finding_hash` vs `prev_line_hash` / `this_line_hash`)
    mean a line accidentally read from one file cannot be silently
    misinterpreted as the other.

Why not extracted into a shared `HashChainedJsonl` base: the shared
core is ~30 lines and reshaping `audit.py` to expose a generic base
class would be heavier than the duplication. Per CLAUDE.md
"three similar lines is better than premature abstraction" — two
consumers do not yet justify the abstraction. If a third hash-chained
log lands later, revisit.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from server._chain_lock import chain_write_lock
from server.schemas import DraftFinding, FindingChainEntry, FindingUpdate

_FINDINGS_FILENAME = "findings.jsonl"
_GENESIS_PREV_HASH = "0" * 64


def _read_chain_state(findings_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_finding_hash) for the next append.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the next
    line number is one greater than the count of non-blank lines, and
    the previous-hash comes from the last non-blank line's
    `this_finding_hash`.
    """
    if not findings_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with findings_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_finding_hash"]


def append_finding_entry(
    case_dir: Path | str, finding: DraftFinding | FindingUpdate
) -> FindingChainEntry:
    """Append one hash-chained record to `<case_dir>/findings.jsonl`.

    Accepts either a `DraftFinding` (analyst write via record_finding)
    or a `FindingUpdate` (orchestrator promotion via update_finding).
    Both kinds land in the SAME chain, distinguished by `record_kind`.
    Returns the constructed FindingChainEntry so the caller can digest
    it for the audit-chain `output_hash` without re-reading the
    on-disk line.

    Read-modify-write is wrapped in ``chain_write_lock`` so multiple
    parallel-dispatched subagents' MCP-server processes serialize
    against the chain head. Acquisition is exclusive + blocking;
    contention windows are sub-millisecond per write.
    """
    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)
    findings_path = case_dir_path / _FINDINGS_FILENAME

    with chain_write_lock(findings_path):
        line_number, prev_finding_hash = _read_chain_state(findings_path)
        timestamp = datetime.now(tz=timezone.utc)

        chained_fields = dict(
            line_number=line_number,
            timestamp=timestamp,
            finding=finding.model_dump(mode="json"),
            prev_finding_hash=prev_finding_hash,
        )
        this_finding_hash = FindingChainEntry.compute_this_finding_hash(**chained_fields)

        entry = FindingChainEntry(
            line_number=line_number,
            timestamp=timestamp,
            finding=finding,
            prev_finding_hash=prev_finding_hash,
            this_finding_hash=this_finding_hash,
        )

        serialized = entry.model_dump_json()
        with findings_path.open("a", encoding="utf-8") as f:
            f.write(serialized + "\n")
            f.flush()
            os.fsync(f.fileno())

    return entry


def read_finding_ids(case_dir: Path | str) -> set[str]:
    """Return the set of every `finding_id` that has appeared in
    `<case_dir>/findings.jsonl`, across both DRAFT and UPDATE entries.

    Used by `record_correlation` (validating that the
    target/related/finding_a/finding_b ids the validator names exist)
    and by `update_finding` (validating that the `finding_id` being
    updated has a prior DRAFT). Streamed line-by-line; malformed lines
    are skipped — id collection is a provenance check, not a chain
    integrity verification.
    """
    case_dir_path = Path(case_dir).resolve()
    findings_path = case_dir_path / _FINDINGS_FILENAME
    if not findings_path.exists():
        return set()

    ids: set[str] = set()
    with findings_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            payload = row.get("finding")
            if isinstance(payload, dict):
                fid = payload.get("finding_id")
                if isinstance(fid, str):
                    ids.add(fid)
    return ids


def read_finding_state(case_dir: Path | str, finding_id: str) -> tuple[str, str] | None:
    """Return `(state, confidence)` of the most-recent record for
    `finding_id`, last-write-wins across DRAFT and UPDATE entries.

    DRAFT entries carry `state` + `confidence` directly; UPDATE entries
    carry `new_state` + `new_confidence`. The chain is replayed in
    on-disk order — every entry matching `finding_id` updates the
    running state, so the final value is the latest. Returns `None` if
    no entry matches.

    Used by `update_finding` to derive `previous_state` and
    `previous_confidence` from the chain rather than trusting the
    orchestrator to supply them. Server-derived fields cannot be
    spoofed by a buggy or malicious orchestrator.
    """
    case_dir_path = Path(case_dir).resolve()
    findings_path = case_dir_path / _FINDINGS_FILENAME
    if not findings_path.exists():
        return None

    latest: tuple[str, str] | None = None
    with findings_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            payload = row.get("finding")
            if not isinstance(payload, dict):
                continue
            if payload.get("finding_id") != finding_id:
                continue
            kind = payload.get("record_kind", "draft")
            if kind == "update":
                state = payload.get("new_state")
                conf = payload.get("new_confidence")
            else:
                state = payload.get("state")
                conf = payload.get("confidence")
            if isinstance(state, str) and isinstance(conf, str):
                latest = (state, conf)
    return latest


__all__ = [
    "append_finding_entry",
    "read_finding_ids",
    "read_finding_state",
]
