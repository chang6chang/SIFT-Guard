"""Unit tests for `server.tools.disk.disk_prefetch`."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.disk import disk_prefetch


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PREFETCH_FIXTURE = (
    PROJECT_ROOT / "tests" / "fixtures" / "disk_prefetch_sample.jsonl"
)

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


class TestDiskPrefetchResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            disk_prefetch(bogus, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"

    def test_wrong_artifact_class_rejected(self, tmp_path: Path):
        case_dir = _make_case_dir(
            tmp_path, artifact_class=ArtifactClass.MEMORY_IMAGE
        )
        with pytest.raises(ValueError) as exc_info:
            disk_prefetch(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a disk image"


class TestDiskPrefetchHappyPath:
    def test_returns_summary_with_three_executables(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PREFETCH_FIXTURE.read_text(encoding="utf-8")

        with patch(
            "server.tools.disk.mount_disk_image",
            return_value="/mnt/sift_disk",
        ), patch(
            "server.tools.disk.run_prefetch",
            return_value=(fixture_stdout, "pf2json /mnt/sift_disk/Windows/Prefetch", 5.0, "pf2json"),
        ):
            summary = disk_prefetch(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        ref = summary.extraction
        assert ref.plugin_name == "disk.prefetch.Prefetch"
        assert ref.record_count == 3
        assert ref.cached is False
        assert ref.runtime_seconds == 5.0

        assert summary.distinct_executables == 3
        # 12 + 3 + 1 = 16 total run count across the three .pf entries.
        assert summary.total_run_count == 16
        top_names = {n for n, _ in summary.top_executables}
        assert top_names == {"CMD.EXE", "POWERSHELL.EXE", "MIMIKATZ.EXE"}
        # MIMIKATZ.EXE's run-time (2024-03-21) is the latest in
        # the fixture.
        assert summary.latest_run_time is not None
        assert summary.latest_run_time.year == 2024
        assert summary.latest_run_time.month == 3
        assert summary.latest_run_time.day == 21

        assert summary.untrusted_fields == ["top_executables_keys"]
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        # Stored extraction is loadable.
        loaded_ref, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "disk.prefetch.Prefetch"
        )
        assert loaded_ref.cached is True
        entries = parsed["entries"]
        assert len(entries) == 3
        names = {e["executable_name"] for e in entries}
        assert names == {"CMD.EXE", "POWERSHELL.EXE", "MIMIKATZ.EXE"}

        # Audit success line under the bare tool_name.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        audit_lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert any(l["tool_name"] == "disk_prefetch" for l in audit_lines)
