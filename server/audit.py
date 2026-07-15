"""Hash-chained JSONL audit log writer for SIFT-Guard MCP tools.

Every MCP tool that touches case data calls `append_audit_entry` exactly
once per invocation. The log is line-oriented JSONL stored at
`<case_dir>/audit/sift-guard-mcp.jsonl`. Each line carries the sha256 of
the previous line's `this_line_hash` in `prev_line_hash`, and its own
`this_line_hash` is sha256 over a canonical serialization of the rest of
the record. Tampering with any field of any line breaks every subsequent
line's chain.

Design rule (see `docs/decisions-log.md` 2026-05-05 audit-logging principle):
this writer records only *parent-observable harness facts* — tool_name,
evidence_id, hashes of the inputs/outputs as the parent process saw them.
Subagent self-narrated claims about harness behavior do not flow through
here.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from server._chain_lock import chain_write_lock
from server.schemas import AuditLogEntry

_AUDIT_SUBDIR = "audit"
_AUDIT_FILENAME = "sift-guard-mcp.jsonl"
_GENESIS_PREV_HASH = "0" * 64


_TAIL_CHUNK_BYTES = 64 * 1024


def _read_last_nonblank_line(path: Path) -> str:
    """Return the last non-blank line of ``path`` without reading the
    whole file: seek to EOF and scan backwards in fixed-size chunks.

    Returns "" for a missing, empty, or all-blank file.
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return ""
    if size == 0:
        return ""

    with path.open("rb") as f:
        buffer = b""
        pos = size
        while pos > 0:
            read_from = max(0, pos - _TAIL_CHUNK_BYTES)
            f.seek(read_from)
            buffer = f.read(pos - read_from) + buffer
            pos = read_from
            # Trailing whitespace (the writer always ends lines with
            # "\n") is stripped before looking for the line break that
            # bounds the final record.
            tail = buffer.rstrip()
            if not tail:
                buffer = b""
                continue
            newline_index = tail.rfind(b"\n")
            if newline_index != -1 or pos == 0:
                return tail[newline_index + 1 :].decode("utf-8").strip()
    return ""


def _read_chain_state(audit_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_line_hash) for the next append.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the state
    comes from the last non-blank line's own record: `line_number + 1`
    and `this_line_hash`. The writer emits strictly sequential
    `line_number`s under `chain_write_lock`, so the last record's
    counter equals the non-blank line count — reading one line from
    EOF replaces the previous full-file scan, which made every append
    O(chain length).
    """
    last_line = _read_last_nonblank_line(audit_path)
    if not last_line:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return prev_record["line_number"] + 1, prev_record["this_line_hash"]


def append_audit_entry(
    case_dir: Path | str,
    tool_name: str,
    evidence_id: str | None,
    input_args: dict,
    output: BaseModel,
) -> AuditLogEntry:
    """Append one hash-chained record to the audit JSONL.

    Read-modify-write is wrapped in ``chain_write_lock`` so multiple
    MCP-server processes (one per parallel subagent dispatch) cannot
    race on the chain head. Pre-parallel-dispatch comment claimed
    "single-process server: no file lock"; that constraint has been
    relaxed by the orchestrator's switch to ThreadPoolExecutor-based
    subagent dispatch in commit 0b473e7's successor.
    """
    case_dir_path = Path(case_dir).resolve()
    audit_dir = case_dir_path / _AUDIT_SUBDIR
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / _AUDIT_FILENAME

    with chain_write_lock(audit_path):
        line_number, prev_line_hash = _read_chain_state(audit_path)
        timestamp = datetime.now(tz=timezone.utc)

        canonical_input = json.dumps(input_args, sort_keys=True, default=str)
        input_hash = hashlib.sha256(canonical_input.encode("utf-8")).hexdigest()
        output_hash = hashlib.sha256(output.model_dump_json().encode("utf-8")).hexdigest()

        chained_fields = dict(
            line_number=line_number,
            timestamp=timestamp,
            tool_name=tool_name,
            evidence_id=evidence_id,
            input_hash=input_hash,
            output_hash=output_hash,
            prev_line_hash=prev_line_hash,
        )
        this_line_hash = AuditLogEntry.compute_this_line_hash(**chained_fields)

        entry = AuditLogEntry(**chained_fields, this_line_hash=this_line_hash)

        serialized = entry.model_dump_json()
        with audit_path.open("a", encoding="utf-8") as f:
            f.write(serialized + "\n")
            f.flush()
            os.fsync(f.fileno())

    return entry


@contextmanager
def reserve_audit_line(case_dir: Path | str) -> Iterator[int]:
    """Hold the audit-chain lock across peek + append so the yielded
    line number is exactly the line the next audit write lands on.

    Used by tier-1 / tier-2 tools to pre-determine the audit line
    where their own success entry will land, so they can embed that
    line into the returned `ExtractionRef` (tier-1) or result model
    (tier-2). The agent then has the line number available without
    having to probe `record_finding`'s audit-chain validation by
    submitting placeholder findings.

    This replaces the pre-parallel-dispatch ``peek_next_line_number``,
    which read the chain head OUTSIDE the lock: with one MCP-server
    process per parallel subagent dispatch, a sibling process could
    append between the peek and the matching ``append_audit_entry``,
    leaving a stale line number embedded in the returned result.
    Holding ``chain_write_lock`` across the whole region closes that
    window; ``chain_write_lock`` is re-entrant per thread, so the
    enclosed ``append_audit_entry`` (success or rejection path)
    re-enters rather than deadlocking and consumes the reserved line.

    Keep the enclosed region short — model construction and same-case
    chain writes only, never subprocess work. Other chains'
    (extractions / findings / correlations) locks nest strictly inside
    this one, so lock order is always audit → other, never the
    reverse.
    """
    case_dir_path = Path(case_dir).resolve()
    audit_path = case_dir_path / _AUDIT_SUBDIR / _AUDIT_FILENAME
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with chain_write_lock(audit_path):
        line_number, _ = _read_chain_state(audit_path)
        yield line_number


__all__ = ["append_audit_entry", "reserve_audit_line"]
