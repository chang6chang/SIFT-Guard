"""Unit tests for `server.tools.disk.disk_mft_timeline`.

Mocks `server.tools.disk.mount_disk_image` and
`server.tools.disk.run_log2timeline_mft` at the disk-tool namespace
where disk.py looks them up. No real ewfmount / log2timeline /
psort is invoked.
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
from server.tools.disk import disk_mft_timeline


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MFT_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_mft_sample.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)
_GENESIS_PREV_HASH = "0" * 64


def _make_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.DISK_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    filename: str = "disk1.E01",
) -> Path:
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()
    fake_evidence = evidence_dir / filename
    fake_evidence.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename=filename,
        absolute_path=str(fake_evidence),
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


# ---------------------------------------------------------------------------
# Resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestDiskMftResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            disk_mft_timeline(bogus, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        assert bogus not in str(exc_info.value)

    def test_wrong_artifact_class_rejected(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.MEMORY_IMAGE)
        with pytest.raises(ValueError) as exc_info:
            disk_mft_timeline(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a disk image"


# ---------------------------------------------------------------------------
# Rejection audit lines
# ---------------------------------------------------------------------------


class TestDiskMftRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            disk_mft_timeline(bogus, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == ("disk_mft_timeline:rejected_evidence_not_found")
        assert entry["evidence_id"] == bogus
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64

    def test_mount_failure_writes_rejection_chain_line(self, tmp_path: Path):
        from server.runners.disk_mount import MountError

        case_dir = _make_case_dir(tmp_path)

        with patch(
            "server.tools.disk.mount_disk_image",
            side_effect=MountError("mount failed"),
        ):
            with pytest.raises(ValueError) as exc_info:
                disk_mft_timeline(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Sanitized — agent-visible message does not echo the
        # internal MountError.
        assert str(exc_info.value) == "disk-image mount failed"

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 1
        assert lines[0]["tool_name"] == ("disk_mft_timeline:rejected_mount_failed")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestDiskMftHappyPath:
    def test_returns_summary_with_four_records(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = MFT_FIXTURE.read_text(encoding="utf-8")
        fake_command = (
            "log2timeline.py --parsers mft --storage-file /tmp/x.plaso "
            "/mnt/sift_disk && psort.py -o json_line -w /tmp/x.jsonl /tmp/x.plaso"
        )
        fake_mount = "/mnt/sift_disk"

        with (
            patch(
                "server.tools.disk.mount_disk_image",
                return_value=fake_mount,
            ),
            patch(
                "server.tools.disk.run_log2timeline_mft",
                return_value=(fixture_stdout, fake_command, 42.0, "plaso 20240126"),
            ) as mock_run,
        ):
            summary = disk_mft_timeline(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        ref = summary.extraction
        assert ref.plugin_name == "disk.mft.MftTimeline"
        assert ref.evidence_id == VALID_EVIDENCE_ID
        assert ref.record_count == 4
        assert ref.cached is False
        assert ref.runtime_seconds == 42.0

        assert summary.entry_type_distribution == {
            "created": 1,
            "modified": 1,
            "accessed": 1,
            "mft_modified": 1,
        }
        assert summary.distinct_paths == 2
        assert {p for p, _ in summary.top_paths} == {
            "/Windows/System32/cmd.exe",
            "/Users/Public/notepad.exe",
        }
        assert summary.untrusted_fields == ["top_paths_keys"]

        # Tier-1 size budget.
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        # Stored extraction is loadable.
        loaded_ref, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "disk.mft.MftTimeline")
        assert loaded_ref.cached is True
        assert loaded_ref.runtime_seconds is None
        assert parsed["plugin_name"] == "disk.mft.MftTimeline"
        assert parsed["tool_version"] == "plaso 20240126"
        assert parsed["command_executed"] == fake_command
        entries = parsed["entries"]
        assert len(entries) == 4

        # Mount was called with the right evidence id; runner with
        # the resolved mount path.
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0] == fake_mount

        # Extractions chain line written + hash matches.
        chain_path = case_dir / "extractions.jsonl"
        chain_lines = [
            json.loads(line) for line in chain_path.read_text().splitlines() if line.strip()
        ]
        assert len(chain_lines) == 1
        assert chain_lines[0]["plugin_name"] == "disk.mft.MftTimeline"
        assert chain_lines[0]["record_count"] == 4
        assert chain_lines[0]["extraction_sha256"] == ref.extraction_sha256

        # Success audit line under the bare tool_name.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        audit_lines = [
            json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()
        ]
        assert any(entry["tool_name"] == "disk_mft_timeline" for entry in audit_lines)
