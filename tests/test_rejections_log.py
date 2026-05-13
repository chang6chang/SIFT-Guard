"""Tests for the side-channel ``audit/rejections.jsonl`` writer.

The hash-chained ``sift-guard-mcp.jsonl`` deliberately discards
agent-supplied input — only ``input_hash`` survives, which is why the
display printed ``input=None`` on every rejection. The side-channel
writer in ``server.rejections_log`` mirrors a *sanitized* copy of
``input_args`` to a non-chained debug log so the operator console can
render *what* was rejected.

Tests pin:

  - The on-disk shape: one JSONL line per rejection, keyed by audit
    ``line_number`` so the display can join cleanly.
  - Redaction: ``<evidence>...</evidence>`` substrings get stripped,
    long strings get truncated.
  - The hash chain is unaffected: chain integrity holds across a
    rejection that also writes to the side-channel.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from server.audit import append_audit_entry
from server.rejections_log import (
    _redact_value,
    append_rejection_record,
    iter_rejection_records,
)
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.findings import record_finding


VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    fake = case_dir / "evidence" / "fake-memory.raw"
    fake.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=VALID_EVIDENCE_ID,
        original_filename="fake-memory.raw",
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
    return case_dir


class TestRedactValue:
    def test_strips_evidence_block(self):
        text = (
            'before <evidence source="x" hash="y" untrusted="true">'
            "ATTACKER-CONTROLLED PAYLOAD"
            "</evidence> after"
        )
        out = _redact_value(text)
        assert "ATTACKER-CONTROLLED" not in out
        assert "<evidence redacted>" in out

    def test_strips_evidence_block_in_nested_dict(self):
        payload = {
            "title": "fine",
            "description": '<evidence source="r">secret</evidence>',
            "nested": {
                "field": [
                    '<evidence>more secret</evidence>',
                    "ok",
                ]
            },
        }
        out = _redact_value(payload)
        flat = json.dumps(out)
        assert "secret" not in flat
        assert "more secret" not in flat
        assert flat.count("<evidence redacted>") == 2

    def test_truncates_long_strings(self):
        long_s = "x" * 1000
        out = _redact_value(long_s)
        assert len(out) <= 200
        assert out.endswith("…")

    def test_passthrough_for_scalars(self):
        assert _redact_value(42) == 42
        assert _redact_value(None) is None
        assert _redact_value(True) is True


class TestAppendRejectionRecord:
    def _seed_audit_line(self, case_dir: Path):
        class _Stub:
            def model_dump_json(self):
                return json.dumps({"ok": True})

        return append_audit_entry(
            case_dir=case_dir,
            tool_name="query_records:rejected_unknown_field",
            evidence_id=VALID_EVIDENCE_ID,
            input_args={"plugin": "windows.pslist.PsList", "filter": {"field": "bogus"}},
            output=_Stub(),
        )

    def test_writes_one_line_per_rejection(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        entry = self._seed_audit_line(case_dir)
        append_rejection_record(
            case_dir,
            entry,
            {"plugin": "windows.pslist.PsList", "filter": {"field": "bogus"}},
        )

        records = iter_rejection_records(case_dir)
        assert len(records) == 1
        rec = records[0]
        assert rec["line_number"] == entry.line_number
        assert rec["tool_name"] == "query_records:rejected_unknown_field"
        assert rec["redacted_input"]["plugin"] == "windows.pslist.PsList"
        assert rec["redacted_input"]["filter"]["field"] == "bogus"

    def test_redacts_evidence_in_persisted_payload(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        entry = self._seed_audit_line(case_dir)
        append_rejection_record(
            case_dir,
            entry,
            {
                "title": '<evidence source="r">attacker payload</evidence> rest',
                "description": "ok",
            },
        )

        on_disk = (case_dir / "audit" / "rejections.jsonl").read_text(encoding="utf-8")
        assert "attacker payload" not in on_disk
        assert "<evidence redacted>" in on_disk


class TestRecordFindingRoutesToSideChannel:
    """End-to-end: a real record_finding rejection writes both the
    audit chain line AND the side-channel record."""

    def test_evidence_not_found_writes_redacted_input(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bad_evidence = "00000000-0000-0000-0000-deadbeefdead"

        try:
            record_finding(
                evidence_id=bad_evidence,
                analyst="process_analyst",
                category="process_anomaly",
                severity="medium",
                confidence="MEDIUM",
                title="Some title that is long enough for the schema",
                description=(
                    "A long enough description to satisfy the schema "
                    "minimum length constraint of fifty characters total."
                ),
                evidence_refs=[
                    EvidenceRef(
                        source_tool="vol_pslist",
                        audit_line=1,
                        detail="example",
                    )
                ],
                case_dir=str(case_dir),
            )
            raise AssertionError("rejection path should raise")
        except ValueError:
            pass

        records = iter_rejection_records(case_dir)
        assert len(records) == 1
        rec = records[0]
        assert rec["tool_name"] == "record_finding:rejected_evidence_not_found"
        # The agent-supplied input survived into the side channel.
        assert rec["redacted_input"]["analyst"] == "process_analyst"
        assert rec["redacted_input"]["confidence"] == "MEDIUM"
        assert rec["redacted_input"]["evidence_id"] == bad_evidence
        # And the audit chain still has the rejection line.
        audit_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text(encoding="utf-8")
            .strip()
            .splitlines()
        )
        last = json.loads(audit_lines[-1])
        assert last["tool_name"] == "record_finding:rejected_evidence_not_found"
        # And the audit chain still hashes inputs only — no echoed payload.
        assert "title" not in last
        assert "description" not in last
