"""Unit tests for `server.tools.disk.disk_evtx`."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.disk import disk_evtx


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVTX_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_evtx_sample.jsonl"

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


class TestDiskEvtxResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            disk_evtx(bogus, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"


class TestDiskEvtxHappyPath:
    def test_returns_summary_with_three_events_logon_type_extracted(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = EVTX_FIXTURE.read_text(encoding="utf-8")

        with patch(
            "server.tools.disk.mount_disk_image",
            return_value="/mnt/sift_disk",
        ), patch(
            "server.tools.disk.run_evtx_dump",
            return_value=(
                fixture_stdout,
                "evtx_dump.py -o json /mnt/sift_disk/Windows/System32/winevt/Logs/Security.evtx",
                7.5,
                "evtx_dump.py",
            ),
        ):
            summary = disk_evtx(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        ref = summary.extraction
        assert ref.plugin_name == "disk.evtx.EventLog"
        assert ref.record_count == 3
        assert ref.cached is False

        # Distinct event ids: 4624, 4625, 7045 = 3.
        assert summary.distinct_event_ids == 3
        eid_dict = dict(summary.event_id_distribution)
        assert eid_dict.get(4624) == 1
        assert eid_dict.get(4625) == 1
        assert eid_dict.get(7045) == 1
        # Two channels: Security (2) + System (1).
        assert summary.channel_distribution == {
            "Security": 2,
            "System": 1,
        }
        assert summary.untrusted_fields == []
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        loaded_ref, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "disk.evtx.EventLog"
        )
        events = parsed["events"]
        assert len(events) == 3
        # Event 4624 — RDP-style logon (LogonType 10).
        e4624 = next(e for e in events if e["event_id"] == 4624)
        assert e4624["logon_type"] == 10
        assert e4624["channel"] == "Security"
        # Event 7045 — service install. logon_type is null;
        # message_summary contains the malicious image path.
        e7045 = next(e for e in events if e["event_id"] == 7045)
        assert e7045["logon_type"] is None
        assert "evil.exe" in e7045["message_summary"]
        # message_summary respects the 500-char schema cap.
        for e in events:
            assert len(e["message_summary"]) <= 500
