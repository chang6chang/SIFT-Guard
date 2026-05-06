"""Unit tests for `server.tools.analytical.group_by`."""

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
    PslistResult,
    ProcessRecord,
)
from server.tools.analytical import group_by


EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _seed_case_dir(tmp_path: Path) -> Path:
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


def _pr(pid: int, ppid: int, name: str) -> ProcessRecord:
    return ProcessRecord(
        pid=pid, ppid=ppid, image_file_name=name, offset_v=0, threads=1,
        handles=None, session_id=None, wow64=False,
        create_time=NOW_UTC, exit_time=None,
    )


def _seed_pslist(case_dir: Path, processes: list[ProcessRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pslist.PsList",
        PslistResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            volatility_version="2.27.0",
            processes=processes,
            command_executed="vol -f /tmp/x.raw -r json windows.pslist.PsList",
            runtime_seconds=14.7,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=14.7,
    )


class TestGroupByHappyPath:
    def test_groups_by_image_name_sorted_descending(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [
                _pr(4, 0, "System"),
                _pr(100, 4, "smss.exe"),
                _pr(200, 4, "smss.exe"),
                _pr(300, 4, "csrss.exe"),
                _pr(400, 4, "smss.exe"),
            ],
        )
        result = group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="image_file_name",
            case_dir=str(case_dir),
        )
        assert result.field == "image_file_name"
        assert result.total_records == 5
        assert result.distinct_values == 3
        # First entry has the highest count.
        assert result.groups[0] == ("smss.exe", 3)
        # Counts sum to total_records.
        assert sum(c for _, c in result.groups) == 5

    def test_top_n_truncates(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [_pr(p, 0, f"name{p % 5}.exe") for p in range(20)],
        )
        result = group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="image_file_name",
            top_n=2,
            case_dir=str(case_dir),
        )
        assert len(result.groups) == 2
        # distinct_values reflects the full cardinality, not top_n.
        assert result.distinct_values == 5

    def test_pre_filter_then_group(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(
            case_dir,
            [
                _pr(4, 0, "System"),
                _pr(100, 4, "smss.exe"),
                _pr(200, 4, "smss.exe"),
                _pr(300, 8, "smss.exe"),  # different ppid
            ],
        )
        result = group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="image_file_name",
            filters=[FieldFilter(field="ppid", op="eq", value=4)],
            case_dir=str(case_dir),
        )
        # Only ppid==4 records contribute: System (1), smss.exe (2).
        # Wait: System has ppid 0 not 4. So only smss.exe (2) survives.
        assert result.total_records == 2
        assert result.groups == [("smss.exe", 2)]


class TestGroupByRejections:
    def test_unknown_field_rejected_and_audited(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="unknown field"):
            group_by(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                field="not_a_field",
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "group_by:rejected_unknown_field"

    def test_top_n_above_cap_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="top_n"):
            group_by(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                field="image_file_name",
                top_n=201,
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "group_by:rejected_limit_too_large"

    def test_extraction_missing_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError, match="no stored extraction"):
            group_by(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                field="image_file_name",
                case_dir=str(case_dir),
            )

    def test_unknown_filter_field_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        with pytest.raises(ValueError, match="unknown field"):
            group_by(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                field="image_file_name",
                filters=[FieldFilter(field="bogus", op="eq", value=1)],
                case_dir=str(case_dir),
            )


class TestGroupByAuditTrail:
    def test_success_writes_audit_line(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe")])
        group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="image_file_name",
            case_dir=str(case_dir),
        )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "group_by"
        assert last["evidence_id"] == EVIDENCE_ID
        assert len(last["input_hash"]) == 64
        assert len(last["output_hash"]) == 64
