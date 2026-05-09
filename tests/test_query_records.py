"""Unit tests for `server.tools.analytical.query_records`.

The 10000-row size-budget test is the load-bearing one for the
architecture: it pins the constraint that no tier-1/tier-2 return
exceeds the 10 KB JSON budget regardless of input size.

Fixture pattern: each test builds a tmp case dir with one registered
evidence record (no real file bytes) and pre-writes the matching
extraction via `write_extraction`. Tier-2 tools only read stored
extractions, so we never touch SSH or Volatility from this file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from server.extractions import write_extraction
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    FieldFilter,
    NetscanResult,
    NetworkRecord,
    PslistResult,
    ProcessRecord,
)
from server.tools.analytical import query_records


EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _seed_case_dir(tmp_path: Path) -> Path:
    """Build a tmp case_dir with the single Rocba-stand-in record.

    No actual file bytes — query_records never touches the source
    image; tier-1 already extracted everything it needs.
    """
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    record = EvidenceRecord(
        evidence_id=EVIDENCE_ID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(case_dir / "evidence" / "Rocba-Memory.raw"),
        sha256="e" * 64,
        size_bytes=1024,
        artifact_class=ArtifactClass.MEMORY_IMAGE,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": "case-data",
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    return case_dir


def _pr(pid: int, ppid: int, name: str, exit_time: datetime | None = None) -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        ppid=ppid,
        image_file_name=name,
        offset_v=0,
        threads=1,
        handles=None,
        session_id=None,
        wow64=False,
        create_time=NOW_UTC,
        exit_time=exit_time,
    )


def _seed_pslist(case_dir: Path, processes: list[ProcessRecord]) -> None:
    result = PslistResult(
        evidence_id=EVIDENCE_ID,
        plugin_name="windows.pslist.PsList",
        volatility_version="2.27.0",
        processes=processes,
        command_executed="vol -f /tmp/x.raw -r json windows.pslist.PsList",
        runtime_seconds=14.7,
        invoked_at=NOW_UTC,
    )
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pslist.PsList",
        result,
        runtime_seconds=14.7,
    )


def _seed_netscan(case_dir: Path, records: list[NetworkRecord]) -> None:
    result = NetscanResult(
        evidence_id=EVIDENCE_ID,
        plugin_name="windows.netscan.NetScan",
        volatility_version="2.27.0",
        connections=records,
        command_executed="vol -f /tmp/x.raw -r json windows.netscan.NetScan",
        runtime_seconds=537.4,
        invoked_at=NOW_UTC,
    )
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.netscan.NetScan",
        result,
        runtime_seconds=537.4,
    )


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestQueryRecordsHappyPath:
    def test_returns_all_records_when_no_filters(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe")])

        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            case_dir=str(case_dir),
        )
        assert result.matched_count == 2
        assert result.returned_count == 2
        assert result.truncated is False
        assert {r["pid"] for r in result.records} == {4, 100}
        # Field-level evidence-delimiter discipline: pslist's
        # untrusted record-field set narrowed by the (here empty)
        # projection.
        assert result.untrusted_fields == ["image_file_name"]

    def test_eq_filter_narrows_records(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [_pr(4, 0, "System"), _pr(100, 4, "smss.exe"), _pr(200, 4, "smss.exe")],
        )
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            filters=[FieldFilter(field="image_file_name", op="eq", value="smss.exe")],
            case_dir=str(case_dir),
        )
        assert result.matched_count == 2
        assert {r["pid"] for r in result.records} == {100, 200}

    def test_projection_keeps_only_requested_fields(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            fields=["pid", "image_file_name"],
            case_dir=str(case_dir),
        )
        assert result.records == [{"pid": 4, "image_file_name": "System"}]

    def test_offset_and_limit_paginate(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [_pr(p, 0, f"p{p}.exe") for p in range(10)],
        )
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            limit=3,
            offset=5,
            case_dir=str(case_dir),
        )
        assert result.matched_count == 10
        assert result.returned_count == 3
        assert result.truncated is True
        assert {r["pid"] for r in result.records} == {5, 6, 7}

    def test_is_null_filter_finds_nulls(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [
                _pr(4, 0, "System", exit_time=None),
                _pr(100, 4, "exited.exe", exit_time=NOW_UTC),
            ],
        )
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            filters=[FieldFilter(field="exit_time", op="is_null")],
            case_dir=str(case_dir),
        )
        assert result.matched_count == 1
        assert result.records[0]["pid"] == 4

    def test_contains_op_substring_match(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_netscan(
            case_dir,
            [
                NetworkRecord(
                    proto="TCPv4",
                    local_addr="0.0.0.0",
                    local_port=445,
                    foreign_addr="0.0.0.0",
                    foreign_port=0,
                    state="LISTENING",
                    pid=4,
                    owner="System",
                    offset=0,
                    created=None,
                ),
                NetworkRecord(
                    proto="TCPv4",
                    local_addr="192.168.1.5",
                    local_port=53810,
                    foreign_addr="17.57.144.165",
                    foreign_port=5223,
                    state="ESTABLISHED",
                    pid=100,
                    owner="APSDaemon.exe",
                    offset=0,
                    created=None,
                ),
            ],
        )
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.netscan.NetScan",
            filters=[FieldFilter(field="owner", op="contains", value="Daemon")],
            case_dir=str(case_dir),
        )
        assert result.matched_count == 1
        assert result.records[0]["owner"] == "APSDaemon.exe"


# ---------------------------------------------------------------------------
# Rejection paths
# ---------------------------------------------------------------------------


class TestQueryRecordsRejections:
    def test_rejects_unknown_evidence_id(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError, match="evidence_id not found"):
            query_records(
                evidence_id=bogus,
                plugin_name="windows.pslist.PsList",
                case_dir=str(case_dir),
            )
        # Audit chain captured the rejection.
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "query_records:rejected_evidence_not_found"
        assert last["evidence_id"] == bogus

    def test_rejects_missing_extraction(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Don't seed any extraction.
        with pytest.raises(ValueError, match="no stored extraction"):
            query_records(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "query_records:rejected_extraction_not_found"

    def test_rejects_unknown_filter_field(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="unknown field"):
            query_records(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                filters=[FieldFilter(field="not_a_field", op="eq", value=1)],
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "query_records:rejected_unknown_field"

    def test_rejects_unknown_projection_field(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="unknown field"):
            query_records(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                fields=["pid", "not_a_field"],
                case_dir=str(case_dir),
            )

    def test_rejects_limit_above_cap(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="limit"):
            query_records(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                limit=201,
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "query_records:rejected_limit_too_large"


# ---------------------------------------------------------------------------
# Size-budget property test — the load-bearing one
# ---------------------------------------------------------------------------


class TestQueryRecordsAuditLinePlumbing:
    def test_result_carries_call_audit_line(self, tmp_path: Path):
        """Tier-2 contract: QueryRecordsResult.audit_line equals the
        audit-chain line where THIS query_records call was logged.
        The analyst can use it directly as `EvidenceRef.audit_line`
        with `source_tool="query_records"` in record_finding."""
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])

        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            case_dir=str(case_dir),
        )

        # audit_line populated.
        assert result.audit_line >= 1

        # Cross-check against the actual audit-chain entry.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        success_lines = [entry for entry in lines if entry["tool_name"] == "query_records"]
        assert len(success_lines) == 1
        assert result.audit_line == success_lines[0]["line_number"]

    def test_extraction_ref_carries_source_audit_line(self, tmp_path: Path):
        """The ExtractionRef inside the Result carries the SOURCE
        extraction's audit_line, populated by write_extraction at
        seeding time. That value is independent of the query_records
        call's own audit_line."""
        case_dir = _seed_case_dir(tmp_path)
        # Override _seed_pslist to use a known audit_line.
        from server.extractions import write_extraction
        from server.schemas import PslistResult

        write_extraction(
            case_dir,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            PslistResult(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                volatility_version="2.27.0",
                processes=[_pr(4, 0, "System")],
                command_executed="vol",
                runtime_seconds=14.7,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=14.7,
            audit_line=99,
        )
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            case_dir=str(case_dir),
        )
        assert result.extraction.audit_line == 99
        # The Result's own audit_line is independent of the source's.
        assert result.audit_line != 99


class TestQueryRecordsSizeBudget:
    def test_default_limit_full_projection_under_10kb(self, tmp_path: Path):
        """Tier-2 budget: at the default limit (50) with full projection,
        a 10000-row extraction's query result must fit the 10 KB
        ceiling. The hard cap (200) requires narrow projection per the
        architecture spec's "even with relatively wide projections"
        qualifier; default×full is the realistic worst case the agent
        hits without thinking about projection.
        """
        case_dir = _seed_case_dir(tmp_path)
        # Synthetic 10000-row pslist. Process names are bounded to
        # short strings so the full record is realistic — typical
        # Windows EPROCESS names average ~12 chars.
        records = [_pr(p, p % 17, f"proc{p % 1000}.exe") for p in range(1, 10001)]
        _seed_pslist(case_dir, records)

        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            case_dir=str(case_dir),
        )
        size = len(result.model_dump_json().encode("utf-8"))
        assert size < 10_240, (
            f"query_records default-limit full-projection return on a "
            f"10000-row extraction exceeded 10 KB: {size} bytes."
        )
        assert result.matched_count == 10_000
        assert result.returned_count == 50
        assert result.truncated is True

    def test_max_limit_narrow_projection_under_10kb(self, tmp_path: Path):
        """At the hard cap (200), the agent must project narrowly to
        stay in the budget. A 2-field projection (pid, image_file_name)
        on a 10000-row extraction × 200 returned ≈ 7 KB. Adding more
        fields pushes past the ceiling — that's the contract the agent
        is implicitly bound to when invoking with limit=200.
        """
        case_dir = _seed_case_dir(tmp_path)
        records = [_pr(p, p % 17, f"proc{p % 1000}.exe") for p in range(1, 10001)]
        _seed_pslist(case_dir, records)

        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            limit=200,
            fields=["pid", "image_file_name"],
            case_dir=str(case_dir),
        )
        size = len(result.model_dump_json().encode("utf-8"))
        assert size < 10_240, (
            f"query_records cap-limit narrow-projection exceeded 10 KB: {size} bytes."
        )
        assert result.returned_count == 200

    def test_summary_size_independent_of_input_size(self, tmp_path: Path):
        """Tier-1 budget property: a 10000-row pslist's *summary*
        (the tier-1 return shape) must serialize under 10 KB.

        Re-uses query_records' fixture seed because writing a summary
        directly here would duplicate test-only logic. The summary
        reaches the agent via vol_pslist's cache-hit path, which
        recomputes it from the loaded extraction. We probe that by
        importing the computer directly — same code path, no SSH.
        """
        from server.tools.memory import _compute_process_summary
        from server.schemas import ExtractionRef, PslistSummary

        case_dir = _seed_case_dir(tmp_path)
        records = [_pr(p, p % 17, f"proc{p % 1000}.exe") for p in range(1, 10001)]
        _seed_pslist(case_dir, records)

        # Synthetic ExtractionRef pinned to a known shape — the
        # summary's size budget is what's under test, not the
        # extraction-write path (covered in test_extractions.py).
        ref = ExtractionRef(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            extraction_id="11111111-1111-4111-8111-111111111111",
            record_count=10_000,
            extraction_sha256="0" * 64,
            extractions_chain_line=1,
            runtime_seconds=14.7,
            cached=False,
        )
        record_dicts = [r.model_dump(mode="json") for r in records]
        summary = _compute_process_summary(ref, record_dicts, PslistSummary)

        size = len(summary.model_dump_json().encode("utf-8"))
        assert size < 10_240, (
            f"PslistSummary on a 10000-row image exceeded 10 KB: "
            f"{size} bytes. Tier-1 size budget is broken."
        )
