"""Tests that `host_id` flows through record_finding into
the persisted DraftFinding without breaking single-evidence
backward compatibility.

Schema-level tests; the full record_finding integration test
(tests/test_record_finding.py) covers the audit-chain plumbing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import yaml

from server.audit import append_audit_entry
from server.schemas import (
    ArtifactClass,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.findings import record_finding


VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    fake = case_dir / "evidence" / "Rocba-Memory.raw"
    fake.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=VALID_EVIDENCE_ID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(fake),
        sha256=VALID_SHA256,
        size_bytes=1024,
        artifact_class=ArtifactClass.MEMORY_IMAGE,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": case_dir.name,
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))

    # Seed an audit-chain entry that record_finding's evidence_refs
    # can cite (vol_pslist line=1).
    class _Stub:
        def model_dump_json(self):
            return json.dumps({"ok": True})

    append_audit_entry(
        case_dir=case_dir,
        tool_name="vol_pslist",
        evidence_id=VALID_EVIDENCE_ID,
        input_args={"evidence_id": VALID_EVIDENCE_ID},
        output=_Stub(),
    )
    return case_dir


class TestDraftFindingHostId:
    def test_default_is_none(self):
        df = DraftFinding(
            finding_id=str(uuid4()),
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            state="DRAFT",
            category="process_anomaly",
            severity="medium",
            confidence="MEDIUM",
            title="example finding title goes here",
            description="A long enough description to satisfy the schema "
            "minimum length constraint of fifty characters total.",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="example",
                )
            ],
            created_at=NOW_UTC,
        )
        assert df.host_id is None

    def test_host_id_round_trips(self):
        df = DraftFinding(
            finding_id=str(uuid4()),
            evidence_id=VALID_EVIDENCE_ID,
            analyst="disk_analyst",
            state="DRAFT",
            category="persistence",
            severity="high",
            confidence="HIGH",
            title="example finding title goes here",
            description="A long enough description to satisfy the schema "
            "minimum length constraint of fifty characters total.",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="example",
                )
            ],
            created_at=NOW_UTC,
            host_id="nfury",
        )
        assert df.host_id == "nfury"
        # Survives JSON round-trip.
        json_blob = df.model_dump_json()
        df2 = DraftFinding.model_validate_json(json_blob)
        assert df2.host_id == "nfury"


class TestRecordFindingHostId:
    def test_record_finding_persists_host_id(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        df = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="disk_analyst",
            category="persistence",
            severity="high",
            confidence="HIGH",
            title="Disk-side persistence finding example",
            description="A long enough description to satisfy the schema "
            "minimum length constraint of fifty characters total.",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            host_id="nfury",
            case_dir=str(case_dir),
        )
        assert df.host_id == "nfury"
        # Persisted to findings.jsonl with host_id set.
        findings_path = case_dir / "findings.jsonl"
        line = findings_path.read_text(encoding="utf-8").splitlines()[-1]
        entry = json.loads(line)
        assert entry["finding"]["host_id"] == "nfury"

    def test_record_finding_without_host_id_is_backward_compat(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        df = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_anomaly",
            severity="medium",
            confidence="MEDIUM",
            title="Memory-side anomaly finding example",
            description="A long enough description to satisfy the schema "
            "minimum length constraint of fifty characters total.",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            case_dir=str(case_dir),
        )
        assert df.host_id is None
