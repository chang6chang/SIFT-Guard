"""Unit tests for `server.tools.memory.vol_cmdline`.

Mirrors `test_vol_pslist.py` / `test_vol_netscan.py`. Same mocking
seam — `server.tools.memory.run_vol_plugin` and
`server.tools.memory.get_vol_version` are patched at the
`server.tools.memory` namespace so no real SSH or VM is involved.
The fixture covers the diagnostic shape the analyst will see on
Rocba: System (PID 4) with a null cmdline (kernel-only, no
user-space parameters block), smss.exe with a populated kernel-side
path, and svchost.exe with a real -k netsvcs argument list.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.memory import vol_cmdline


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CMDLINE_FIXTURE = Path(__file__).parent / "fixtures" / "vol_cmdline_sample.json"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)
_GENESIS_PREV_HASH = "0" * 64


def _make_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MEMORY_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    filename: str = "Rocba-Memory.raw",
    absolute_path: str | None = None,
) -> Path:
    """Same helper shape as the other memory-tool unit tests; kept
    in-module for symmetry."""
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()
    if absolute_path is None:
        fake_evidence = evidence_dir / filename
        fake_evidence.write_bytes(b"\x00" * 1024)
        absolute_path = str(fake_evidence)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename=filename,
        absolute_path=absolute_path,
        sha256=VALID_SHA256,
        size_bytes=1024,
        artifact_class=artifact_class,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": case_dir.name,
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    return case_dir


def _bad_record_json() -> str:
    """Three cmdline rows; the middle row has PID -1 (violates ge=0)."""
    return json.dumps(
        [
            {"PID": 4, "Process": "System", "Args": None, "__children": []},
            {"PID": -1, "Process": "Bad", "Args": "x", "__children": []},
            {
                "PID": 100,
                "Process": "smss.exe",
                "Args": "\\SystemRoot\\System32\\smss.exe",
                "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolCmdlineResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_cmdline(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        assert bogus_id not in str(exc_info.value)

    def test_artifact_class_unknown_rejected_with_sanitized_message(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_cmdline(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert "evidence is not a memory image" in str(exc_info.value)
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — the chain must record every agent call
# ---------------------------------------------------------------------------


class TestVolCmdlineRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_cmdline(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_cmdline:rejected_evidence_not_found"
        assert entry["evidence_id"] == bogus_id
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64


# ---------------------------------------------------------------------------
# happy path — three records exercising null cmdline, populated path,
# and a real argv string
# ---------------------------------------------------------------------------


class TestVolCmdlineHappyPath:
    def test_returns_cmdline_summary_with_three_records(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = CMDLINE_FIXTURE.read_text(encoding="utf-8")
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.cmdline.CmdLine"
        )

        with (
            patch("server.tools.memory.get_vol_version", return_value="2.27.0"),
            patch(
                "server.tools.memory.run_vol_plugin",
                return_value=(fixture_stdout, fake_command, 41.2),
            ) as mock_run,
        ):
            summary = vol_cmdline(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # ExtractionRef is the agent-visible handle for the stored data.
        ref = summary.extraction
        assert ref.plugin_name == "windows.cmdline.CmdLine"
        assert ref.evidence_id == VALID_EVIDENCE_ID
        assert ref.record_count == 3
        assert ref.cached is False
        assert ref.runtime_seconds == 41.2
        assert ref.extractions_chain_line == 1
        assert len(ref.extraction_sha256) == 64

        # Summary distribution fields reflect the three sample rows.
        assert summary.unique_process_names == 3
        assert summary.null_cmdline_count == 1  # System / PID 4
        assert summary.with_cmdline_count == 2
        assert summary.distinct_cmdlines == 2
        assert summary.pid_range == (4, 7900)
        names_in_top = {n for n, _ in summary.top_process_names}
        assert names_in_top == {"System", "smss.exe", "svchost.exe"}

        # Field-level evidence-delimiter discipline — top_process_names
        # carries evidence-derived process names as keys; the
        # schema-default `untrusted_fields` flags that for the analyst.
        assert summary.untrusted_fields == ["top_process_names_keys"]

        # Summary stays under the tier-1 10 KB ceiling.
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        # The full CmdLineResult is now on disk; loading it gives back
        # the three records with their original fields.
        loaded_ref, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "windows.cmdline.CmdLine")
        assert loaded_ref.cached is True
        assert loaded_ref.runtime_seconds is None  # cache contract
        assert parsed["plugin_name"] == "windows.cmdline.CmdLine"
        assert parsed["volatility_version"] == "2.27.0"
        assert parsed["evidence_id"] == VALID_EVIDENCE_ID
        assert parsed["runtime_seconds"] == 41.2
        assert parsed["command_executed"] == fake_command
        records = parsed["processes"]
        assert len(records) == 3
        assert records[0]["pid"] == 4
        assert records[0]["process_name"] == "System"
        assert records[0]["cmdline"] is None
        assert records[1]["pid"] == 440
        assert records[1]["cmdline"] == "\\SystemRoot\\System32\\smss.exe"
        assert records[2]["pid"] == 7900
        assert "svchost.exe -k netsvcs" in records[2]["cmdline"]

        # The runner was called with the pinned plugin name and the
        # registered evidence path on disk.
        plugin_arg, image_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.cmdline.CmdLine"
        assert image_path_arg == str(case_dir / "evidence" / "Rocba-Memory.raw")

        # Extractions chain line was created with matching hash.
        chain_path = case_dir / "extractions.jsonl"
        chain_lines = [
            json.loads(line) for line in chain_path.read_text().splitlines() if line.strip()
        ]
        assert len(chain_lines) == 1
        assert chain_lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert chain_lines[0]["plugin_name"] == "windows.cmdline.CmdLine"
        assert chain_lines[0]["record_count"] == 3
        assert chain_lines[0]["extraction_sha256"] == ref.extraction_sha256

        # Audit log carries one success line; tool_name is bare
        # `vol_cmdline` (no `:cached` / `:rejected_*` suffix).
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        audit_lines = [
            json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()
        ]
        assert any(entry["tool_name"] == "vol_cmdline" for entry in audit_lines)


# ---------------------------------------------------------------------------
# per-record validation warnings
# ---------------------------------------------------------------------------


class TestVolCmdlineRecordWarnings:
    def test_one_bad_record_logged_as_warning_others_preserved(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        with (
            patch("server.tools.memory.get_vol_version", return_value="2.27.0"),
            patch(
                "server.tools.memory.run_vol_plugin",
                return_value=(_bad_record_json(), "ssh ... vol ...", 1.0),
            ),
        ):
            summary = vol_cmdline(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        assert summary.extraction.record_count == 2

        _, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "windows.cmdline.CmdLine")
        records = parsed["processes"]
        assert {r["pid"] for r in records} == {4, 100}

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_cmdline:record_validation_warning"
        assert lines[1]["tool_name"] == "vol_cmdline"
        assert lines[1]["prev_line_hash"] == lines[0]["this_line_hash"]
