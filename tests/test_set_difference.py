"""Unit tests for `server.tools.analytical.set_difference` — the
primary cross-plugin primitive.

Includes the load-bearing pslist-vs-psscan test: psscan ∖ pslist on
PID surfaces the count of EPROCESS pool entries the active-list walk
missed (the DKOM-hidden / terminated-but-resident set). The week-6
validator's flagship rule is one set_difference call.
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
    ProcessRecord,
    PslistResult,
    PsscanResult,
)
from server.tools.analytical import set_difference


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


def _pr(pid: int, ppid: int = 4, name: str = "x.exe") -> ProcessRecord:
    return ProcessRecord(
        pid=pid, ppid=ppid, image_file_name=name, offset_v=0, threads=1,
        handles=None, session_id=None, wow64=False,
        create_time=NOW_UTC, exit_time=None,
    )


def _seed_pair(case_dir: Path, pslist_pids: list[int], psscan_pids: list[int]) -> None:
    pslist_records = [_pr(p) for p in pslist_pids]
    psscan_records = [_pr(p) for p in psscan_pids]
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pslist.PsList",
        PslistResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            volatility_version="2.27.0",
            processes=pslist_records,
            command_executed="vol -f /tmp/x.raw -r json windows.pslist.PsList",
            runtime_seconds=14.7,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=14.7,
    )
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.psscan.PsScan",
        PsscanResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.psscan.PsScan",
            volatility_version="2.27.0",
            processes=psscan_records,
            command_executed="vol -f /tmp/x.raw -r json windows.psscan.PsScan",
            runtime_seconds=396.3,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=396.3,
    )


# ---------------------------------------------------------------------------
# The flagship cross-plugin test — the validator's load-bearing case
# ---------------------------------------------------------------------------


class TestSetDifferenceFlagshipCase:
    def test_psscan_minus_pslist_on_pid_returns_hidden_candidates(
        self, tmp_path: Path
    ):
        """psscan extension {pids} - pslist {pids} = the
        DKOM/terminated-process candidate set. With pslist={4,100,200}
        and psscan={4,100,200,300,400}, a_minus_b yields {300,400}."""
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(
            case_dir,
            pslist_pids=[4, 100, 200],
            psscan_pids=[4, 100, 200, 300, 400],
        )

        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            case_dir=str(case_dir),
        )
        # SET semantics on the join key — these answer "how many
        # distinct entities" questions for the validator.
        assert result.a_only_count == 2
        assert result.b_only_count == 0
        assert result.intersection_count == 3
        assert result.direction == "a_minus_b"

        # RECORD-count fields — surface alongside set counts so the
        # agent can tell entity-set deltas from pool-tag aliasing
        # noise. Synthetic fixture has no duplicates.
        assert result.a_record_count == 5
        assert result.b_record_count == 3
        assert result.a_duplicate_key_count == 0
        assert result.b_duplicate_key_count == 0

        # Returned records are PER-RECORD (not deduped by key) and
        # pulled from plugin_a (psscan). With no duplicate keys here,
        # per-record == per-key count.
        returned_pids = [r["pid"] for r in result.returned_records]
        assert sorted(returned_pids) == [300, 400]
        assert result.truncated is False

    def test_b_minus_a_swaps_direction(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(
            case_dir,
            pslist_pids=[4, 100, 200, 999],
            psscan_pids=[4, 100, 200, 300, 400],
        )
        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="b_minus_a",
            case_dir=str(case_dir),
        )
        # PIDs in pslist but not psscan: {999}.
        assert result.a_only_count == 2  # 300, 400
        assert result.b_only_count == 1  # 999
        assert result.intersection_count == 3
        # Returned records are pulled from plugin_b (pslist) for b_minus_a.
        returned_pids = {r["pid"] for r in result.returned_records}
        assert returned_pids == {999}

    def test_symmetric_returns_union_of_both_diffs(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(
            case_dir,
            pslist_pids=[4, 100, 999],
            psscan_pids=[4, 100, 300],
        )
        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="symmetric",
            case_dir=str(case_dir),
        )
        # symmetric set {999, 300}: 1 from each side.
        assert result.a_only_count == 1
        assert result.b_only_count == 1
        assert result.intersection_count == 2
        returned_pids = {r["pid"] for r in result.returned_records}
        assert returned_pids == {300, 999}


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


class TestSetDifferenceDuplicateKeys:
    def test_a_only_returns_all_records_for_duplicated_key(
        self, tmp_path: Path
    ):
        """When a key in plugin_a's a_only set has multiple records
        (pool-tag aliasing in psscan), all those records come back —
        per-record semantics, not per-key dedup. The 7900 case on
        Rocba: PID 7900 has 2 EPROCESS aliases in psscan and 0 in
        pslist; both should return."""
        case_dir = _seed_case_dir(tmp_path)
        # pslist has PIDs {4, 100}.
        # psscan has PIDs {4, 100, 7900, 7900, 9999}: 7900 appears
        # twice (pool alias). a_only set = {7900, 9999}.
        pslist_records = [_pr(4), _pr(100)]
        psscan_records = [
            _pr(4),
            _pr(100),
            _pr(7900, name="svchost.exe"),
            _pr(7900, name="svchost.exe"),
            _pr(9999, name="malware.exe"),
        ]
        from server.extractions import write_extraction
        from server.schemas import PslistResult, PsscanResult

        write_extraction(
            case_dir,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            PslistResult(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                volatility_version="2.27.0",
                processes=pslist_records,
                command_executed="vol",
                runtime_seconds=14.7,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=14.7,
        )
        write_extraction(
            case_dir,
            EVIDENCE_ID,
            "windows.psscan.PsScan",
            PsscanResult(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.psscan.PsScan",
                volatility_version="2.27.0",
                processes=psscan_records,
                command_executed="vol",
                runtime_seconds=396.0,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=396.0,
        )

        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            case_dir=str(case_dir),
        )

        # Set semantics: 2 unique PIDs in a_only (7900 and 9999).
        assert result.a_only_count == 2
        assert result.b_only_count == 0
        assert result.intersection_count == 2  # PIDs 4 and 100

        # Record / duplicate counts surface the pool-tag aliasing.
        assert result.a_record_count == 5
        assert result.b_record_count == 2
        # PID 7900 has 2 records in psscan; 1 record is the
        # "duplicate beyond first occurrence" — the count of extras
        # due to aliasing in plugin_a as a whole.
        assert result.a_duplicate_key_count == 1
        assert result.b_duplicate_key_count == 0

        # Per-record returned set: 3 records (PID 7900 ×2, PID 9999 ×1).
        returned_pids = [r["pid"] for r in result.returned_records]
        assert sorted(returned_pids) == [7900, 7900, 9999]


class TestSetDifferenceProjection:
    def test_fields_projection_narrows_returned_records(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(
            case_dir,
            pslist_pids=[4, 100],
            psscan_pids=[4, 100, 9999],
        )
        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            fields=["pid", "image_file_name"],
            case_dir=str(case_dir),
        )
        assert result.returned_records == [
            {"pid": 9999, "image_file_name": "x.exe"}
        ]


# ---------------------------------------------------------------------------
# Rejection paths
# ---------------------------------------------------------------------------


class TestSetDifferenceRejections:
    def test_same_plugin_a_and_b_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(case_dir, [4], [4])
        with pytest.raises(ValueError, match="differ"):
            set_difference(
                evidence_id=EVIDENCE_ID,
                plugin_a="windows.pslist.PsList",
                plugin_b="windows.pslist.PsList",
                key="pid",
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "set_difference:rejected_same_plugin"

    def test_invalid_key_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(case_dir, [4], [4])
        with pytest.raises(ValueError, match="key"):
            set_difference(
                evidence_id=EVIDENCE_ID,
                plugin_a="windows.psscan.PsScan",
                plugin_b="windows.pslist.PsList",
                key="not_a_field",
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "set_difference:rejected_invalid_key"

    def test_invalid_direction_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(case_dir, [4], [4])
        with pytest.raises(ValueError, match="direction"):
            set_difference(
                evidence_id=EVIDENCE_ID,
                plugin_a="windows.psscan.PsScan",
                plugin_b="windows.pslist.PsList",
                key="pid",
                direction="not_valid",
                case_dir=str(case_dir),
            )

    def test_extraction_missing_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Seed only one side.
        write_extraction(
            case_dir,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            PslistResult(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                volatility_version="2.27.0",
                processes=[_pr(4)],
                command_executed="vol",
                runtime_seconds=14.7,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=14.7,
        )
        with pytest.raises(ValueError, match="no stored extraction"):
            set_difference(
                evidence_id=EVIDENCE_ID,
                plugin_a="windows.psscan.PsScan",
                plugin_b="windows.pslist.PsList",
                key="pid",
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "set_difference:rejected_extraction_not_found"

    def test_limit_above_cap_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(case_dir, [4], [4])
        with pytest.raises(ValueError, match="limit"):
            set_difference(
                evidence_id=EVIDENCE_ID,
                plugin_a="windows.psscan.PsScan",
                plugin_b="windows.pslist.PsList",
                key="pid",
                limit=501,
                case_dir=str(case_dir),
            )

    def test_evidence_not_registered_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pair(case_dir, [4], [4])
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError, match="evidence_id not found"):
            set_difference(
                evidence_id=bogus,
                plugin_a="windows.psscan.PsScan",
                plugin_b="windows.pslist.PsList",
                key="pid",
                case_dir=str(case_dir),
            )
