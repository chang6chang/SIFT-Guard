"""Tests for ``server._chain_lock`` — the cross-process mutex that
protects every hash-chained writer's read-modify-write.

Parallel analyst dispatch spawns one MCP-server child per analyst,
so the chain writers must serialize concurrent appends across
distinct processes. We test that here against the audit chain
(every other writer follows the same shape).

Test methodology:
  - Spawn N threads each writing one audit entry concurrently.
  - Each thread holds the lock just long enough to read state +
    append. Without the lock, two threads would compute the same
    ``next_line_number`` and produce duplicate / broken-chain
    lines. With the lock, the writes serialize and the chain
    reads back as a strict 1..N sequence with consistent
    ``prev_line_hash`` links.

For cross-process testing the GIL would mask the race entirely.
We use threads + the SAME process here as the cheap proxy — the
lock implementation (``fcntl.flock``) is process-level by design,
so the thread test reproduces the same semantics. A separate
``test_chain_lock_process_level`` could fork-exec but adds CI
overhead without strengthening the invariant we care about.
"""

from __future__ import annotations

import threading
from pathlib import Path

from pydantic import BaseModel

from server.audit import append_audit_entry
from server.schemas import AuditLogEntry


class _PayloadStub(BaseModel):
    """Minimal pydantic model to stand in for the output= argument."""

    value: int


def _read_audit_jsonl(case_dir: Path) -> list[AuditLogEntry]:
    audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
    entries: list[AuditLogEntry] = []
    for raw in audit_path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        entries.append(AuditLogEntry.model_validate_json(stripped))
    return entries


class TestParallelAuditAppends:
    def test_concurrent_appends_produce_a_valid_chain(self, tmp_path: Path):
        """16 threads each writing 1 audit entry. After all writes the
        chain must:
          - have exactly 16 lines
          - line_numbers form the contiguous range 1..16
          - every line's ``prev_line_hash`` matches the previous
            line's ``this_line_hash``.
        """
        case_dir = tmp_path / "case"

        def worker(i: int) -> None:
            append_audit_entry(
                case_dir=case_dir,
                tool_name="parallel_test",
                evidence_id=None,
                input_args={"i": i},
                output=_PayloadStub(value=i),
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        entries = _read_audit_jsonl(case_dir)
        # No drops, no duplicates.
        assert len(entries) == 16
        # Line numbers form 1..16 with no gaps.
        line_numbers = sorted(e.line_number for e in entries)
        assert line_numbers == list(range(1, 17))
        # Chain links: read in on-disk order, every prev hash
        # matches the previous line's this hash.
        prev_hash = "0" * 64
        for entry in entries:
            assert entry.prev_line_hash == prev_hash, (
                f"chain break at line {entry.line_number}: "
                f"expected prev={prev_hash}, got {entry.prev_line_hash}"
            )
            prev_hash = entry.this_line_hash

    def test_lock_file_sidecar_created_alongside_chain(self, tmp_path: Path):
        """The sidecar ``.lock`` file should be created next to the
        chain on first write. (Documented contract — the sudoers
        / sanitization tooling may want to know it's there.)"""
        case_dir = tmp_path / "case"
        append_audit_entry(
            case_dir=case_dir,
            tool_name="sentinel",
            evidence_id=None,
            input_args={},
            output=_PayloadStub(value=0),
        )
        lock_path = case_dir / "audit" / "sift-guard-mcp.jsonl.lock"
        assert lock_path.exists()
