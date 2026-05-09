"""Unit tests for `server.tools.disk.disk_registry`."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.disk import disk_registry


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGRIPPER_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_regripper_sample.txt"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


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


class TestDiskRegistryResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            disk_registry(bogus, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"


class TestDiskRegistryHappyPath:
    def test_returns_summary_across_three_hives(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = REGRIPPER_FIXTURE.read_text(encoding="utf-8")

        with (
            patch(
                "server.tools.disk.mount_disk_image",
                return_value="/mnt/sift_disk",
            ),
            patch(
                "server.tools.disk.run_regripper",
                return_value=(
                    fixture_stdout,
                    "rip.pl -r /mnt/sift_disk/Windows/System32/config/SYSTEM -f system",
                    12.0,
                    "rip.pl",
                ),
            ),
        ):
            summary = disk_registry(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        ref = summary.extraction
        assert ref.plugin_name == "disk.registry.Registry"
        # 3 SYSTEM values + 1 SOFTWARE value + 1 NTUSER.DAT value = 5.
        assert ref.record_count == 5
        assert ref.cached is False

        assert summary.hive_distribution == {
            "SYSTEM": 3,
            "SOFTWARE": 1,
            "NTUSER.DAT": 1,
        }
        # Run keys (SOFTWARE + NTUSER.DAT) bucket together; Services
        # (SYSTEM/.../Services/EvilSvc) gets its own bucket.
        assert summary.interesting_paths_distribution.get("Run", 0) == 2
        assert summary.interesting_paths_distribution.get("Services", 0) == 3

        assert summary.untrusted_fields == ["top_key_paths_keys"]
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        loaded_ref, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "disk.registry.Registry")
        keys = parsed["keys"]
        assert len(keys) == 5
        # value_data is at-most-500-chars per the schema cap.
        for k in keys:
            assert len(k["value_data"]) <= 500
        # Confirm one of the persistence keys was captured.
        evil_loader = next((k for k in keys if k["value_name"] == "EvilLoader"), None)
        assert evil_loader is not None
        assert evil_loader["hive_name"] == "SOFTWARE"
        assert "loader.exe" in evil_loader["value_data"]
