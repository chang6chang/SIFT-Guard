"""Tests for `server.audit.reserve_audit_line` and the tail-read
chain-state path.

The reservation exists because the pre-parallel-dispatch
`peek_next_line_number` read the chain head OUTSIDE the lock: with one
MCP-server process per parallel subagent dispatch, a sibling writer
could append between the peek and the matching `append_audit_entry`,
leaving a stale `audit_line` embedded in the returned result. The
reservation holds `chain_write_lock` across peek + append; the lock is
re-entrant per thread so the enclosed append re-enters instead of
deadlocking.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from pydantic import BaseModel

from server.audit import _read_chain_state, append_audit_entry, reserve_audit_line

_GENESIS = "0" * 64


class _Payload(BaseModel):
    note: str


def _audit_path(case_dir: Path) -> Path:
    return case_dir / "audit" / "sift-guard-mcp.jsonl"


def _append(case_dir: Path, note: str):
    return append_audit_entry(
        case_dir=case_dir,
        tool_name="test_tool",
        evidence_id=None,
        input_args={"note": note},
        output=_Payload(note=note),
    )


class TestReserveAuditLine:
    def test_reserved_line_matches_enclosed_append(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"

        _append(case_dir, "line-1")

        # The enclosed append must land exactly on the reserved line.
        # Run in a worker thread with a join timeout so a re-entrancy
        # regression (which would deadlock on the flock) fails the
        # test instead of hanging the suite.
        result: dict = {}

        def scenario():
            with reserve_audit_line(case_dir) as reserved:
                entry = _append(case_dir, "line-2")
                result["reserved"] = reserved
                result["written"] = entry.line_number

        worker = threading.Thread(target=scenario, daemon=True)
        worker.start()
        worker.join(timeout=10)
        assert not worker.is_alive(), (
            "append inside reserve_audit_line deadlocked — chain_write_lock "
            "re-entrancy is broken"
        )
        assert result["reserved"] == 2
        assert result["written"] == 2

    def test_reservation_on_empty_chain_yields_line_one(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        with reserve_audit_line(case_dir) as reserved:
            entry = _append(case_dir, "first")
        assert reserved == 1
        assert entry.line_number == 1
        assert entry.prev_line_hash == _GENESIS

    def test_concurrent_reservations_serialize(self, tmp_path: Path):
        """Two threads racing reserve+append must each embed the line
        their append actually lands on — the original bug was exactly
        this pair drifting apart under concurrency."""
        case_dir = tmp_path / "case-data"
        barrier = threading.Barrier(2)
        observations: list[tuple[int, int]] = []
        observations_lock = threading.Lock()

        def worker(name: str):
            barrier.wait()
            for i in range(5):
                with reserve_audit_line(case_dir) as reserved:
                    entry = _append(case_dir, f"{name}-{i}")
                with observations_lock:
                    observations.append((reserved, entry.line_number))

        threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert all(not t.is_alive() for t in threads)

        # Every reservation matched its append...
        assert all(reserved == written for reserved, written in observations)
        # ...and the chain came out strictly sequential and unbroken.
        lines = [
            json.loads(line)
            for line in _audit_path(case_dir).read_text().splitlines()
            if line.strip()
        ]
        assert [e["line_number"] for e in lines] == list(range(1, 11))
        for prev, cur in zip(lines, lines[1:]):
            assert cur["prev_line_hash"] == prev["this_line_hash"]

    def test_abandoned_reservation_writes_nothing(self, tmp_path: Path):
        """If the caller raises between reserve and append, no line is
        consumed — the next writer gets the same number."""
        case_dir = tmp_path / "case-data"
        _append(case_dir, "line-1")

        try:
            with reserve_audit_line(case_dir) as reserved:
                assert reserved == 2
                raise RuntimeError("model construction failed")
        except RuntimeError:
            pass

        entry = _append(case_dir, "line-2")
        assert entry.line_number == 2


class TestReadChainStateTailRead:
    """`_read_chain_state` reads only the last line (seek from EOF)
    instead of scanning the whole file per append."""

    def test_matches_full_scan_semantics(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        last = None
        for i in range(25):
            last = _append(case_dir, f"line-{i}")

        next_line, prev_hash = _read_chain_state(_audit_path(case_dir))
        assert next_line == 26
        assert prev_hash == last.this_line_hash

    def test_missing_and_empty_files_are_genesis(self, tmp_path: Path):
        missing = tmp_path / "audit" / "nope.jsonl"
        assert _read_chain_state(missing) == (1, _GENESIS)

        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        assert _read_chain_state(empty) == (1, _GENESIS)

    def test_trailing_blank_lines_are_tolerated(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        entry = _append(case_dir, "only")
        with _audit_path(case_dir).open("a", encoding="utf-8") as f:
            f.write("\n\n  \n")

        next_line, prev_hash = _read_chain_state(_audit_path(case_dir))
        assert next_line == 2
        assert prev_hash == entry.this_line_hash

    def test_last_line_larger_than_tail_chunk(self, tmp_path: Path):
        """A record longer than one backwards-read chunk must still be
        recovered whole."""
        case_dir = tmp_path / "case-data"
        _append(case_dir, "small")
        big = _append(case_dir, "x" * (128 * 1024))

        next_line, prev_hash = _read_chain_state(_audit_path(case_dir))
        assert next_line == 3
        assert prev_hash == big.this_line_hash
