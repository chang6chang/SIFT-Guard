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
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from server.schemas import AuditLogEntry

_AUDIT_SUBDIR = "audit"
_AUDIT_FILENAME = "sift-guard-mcp.jsonl"
_GENESIS_PREV_HASH = "0" * 64


def _read_chain_state(audit_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_line_hash) for the next append.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the next line
    number is one greater than the count of non-blank lines, and the
    previous-hash comes from the last non-blank line's `this_line_hash`.
    """
    if not audit_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with audit_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_line_hash"]


def append_audit_entry(
    case_dir: Path | str,
    tool_name: str,
    evidence_id: str | None,
    input_args: dict,
    output: BaseModel,
) -> AuditLogEntry:
    """Append one hash-chained record to the audit JSONL.

    Single-process server: no file lock. If a future multi-process design
    is needed, wrap this call in a writer-process queue rather than
    layering fcntl into the public path — keeping the writer trivial is
    what makes the chain easy to audit by hand.
    """
    case_dir_path = Path(case_dir).resolve()
    audit_dir = case_dir_path / _AUDIT_SUBDIR
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / _AUDIT_FILENAME

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


def peek_next_line_number(case_dir: Path | str) -> int:
    """Return the audit-chain line number that the next
    `append_audit_entry` would use.

    Used by tier-1 / tier-2 tools to pre-determine the audit line
    where their own success entry will land, so they can embed that
    line into the returned `ExtractionRef` (tier-1) or result model
    (tier-2). The agent then has the line number available without
    having to probe `record_finding`'s audit-chain validation by
    submitting placeholder findings.

    Single-process-server contract: between this peek and the matching
    `append_audit_entry` call there must be no other audit writes.
    The MCP server is single-process by construction (see
    `server/audit.py` module docstring); a future multi-process design
    would route writes through a queue and would need a different
    line-number-allocation primitive.
    """
    case_dir_path = Path(case_dir).resolve()
    audit_path = case_dir_path / _AUDIT_SUBDIR / _AUDIT_FILENAME
    line_number, _ = _read_chain_state(audit_path)
    return line_number


__all__ = ["append_audit_entry", "peek_next_line_number"]
