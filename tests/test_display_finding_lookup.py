"""Tests for the display tail's ``_lookup_finding_by_hash`` helper.

The ``+ FIND`` console line needs the finding's ``host_id``, title
and confidence — none of which live on the audit chain (which carries
only ``output_hash``). The display joins the audit chain to the
findings chain by recomputing the SHA-256 of each findings.jsonl
line and matching against ``output_hash``. This test pins the join
key.

Regression context: an earlier implementation joined on the findings
entry's ``this_finding_hash`` field, which is hashed over the entry
*minus* ``this_finding_hash`` — not the same as the whole-entry
digest the audit chain stores. The console rendered ``host=—`` and
empty titles even after host_id was correctly persisted to disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from server.audit import append_audit_entry
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.findings import record_finding
from sift_guard.display import ProgressDisplay


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

    # Seed an audit-chain line that record_finding's evidence_refs
    # can point at.
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


def _last_audit_line(case_dir: Path) -> dict:
    audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    return json.loads(lines[-1])


class TestLookupFindingByHash:
    def test_join_recovers_host_id_after_record_finding(
        self, tmp_path: Path, monkeypatch
    ):
        case_dir = _make_case_dir(tmp_path)
        monkeypatch.setenv("SIFT_GUARD_HOST_ID", "nfury")

        df = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_anomaly",
            severity="medium",
            confidence="MEDIUM",
            title="Suspicious svchost child process spawned from outside services.exe",
            description=(
                "A long enough description to satisfy the schema minimum "
                "length constraint of fifty characters total."
            ),
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            case_dir=str(case_dir),
        )
        assert df.host_id == "nfury"

        # The audit-chain entry for record_finding has output_hash =
        # sha256(FindingChainEntry.model_dump_json()). The findings.jsonl
        # line is exactly that JSON. The display join rebuilds the
        # link from the line bytes.
        last_audit = _last_audit_line(case_dir)
        assert last_audit["tool_name"] == "record_finding"
        output_hash = last_audit["output_hash"]

        display = ProgressDisplay(case_dir=case_dir, stream=None)
        finding = display._lookup_finding_by_hash(output_hash)

        assert finding is not None
        assert finding["host_id"] == "nfury"
        assert finding["confidence"] == "MEDIUM"
        assert (
            finding["title"]
            == "Suspicious svchost child process spawned from outside services.exe"
        )

    def test_lookup_returns_none_for_unmatched_hash(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        display = ProgressDisplay(case_dir=case_dir, stream=None)
        # No findings.jsonl yet; lookup must return None, not crash.
        assert display._lookup_finding_by_hash("0" * 64) is None

    def test_lookup_returns_none_for_unknown_hash_with_findings_present(
        self, tmp_path: Path, monkeypatch
    ):
        case_dir = _make_case_dir(tmp_path)
        monkeypatch.setenv("SIFT_GUARD_HOST_ID", "nfury")
        record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_anomaly",
            severity="medium",
            confidence="MEDIUM",
            title="A finding for which we will NOT query its hash",
            description=(
                "A long enough description to satisfy the schema minimum "
                "length constraint of fifty characters total."
            ),
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            case_dir=str(case_dir),
        )

        display = ProgressDisplay(case_dir=case_dir, stream=None)
        # A hash that's syntactically valid but not in the file.
        assert display._lookup_finding_by_hash("f" * 64) is None


class TestLookupCorrelationByHash:
    """Parallel of the finding-hash join, this time for the ``+ CORR``
    console line. ``record_correlation`` writes a
    CorrelationChainEntry to ``correlations.jsonl`` exactly as
    ``entry.model_dump_json() + "\\n"``; the audit-chain ``output_hash``
    is sha256 of those bytes. The display join recomputes and
    matches."""

    def test_correlation_lookup_round_trip(
        self, tmp_path: Path, monkeypatch
    ):
        # Reuse the host-id env override to ensure the finding the
        # correlation will reference carries a host_id.
        case_dir = _make_case_dir(tmp_path)
        monkeypatch.setenv("SIFT_GUARD_HOST_ID", "nfury")

        df = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_anomaly",
            severity="medium",
            confidence="MEDIUM",
            title="Source finding for correlation lookup round-trip",
            description=(
                "A long enough description to satisfy the schema "
                "minimum length constraint of fifty characters total."
            ),
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            case_dir=str(case_dir),
        )

        # The CASE.yaml seeded by _make_case_dir uses case_dir.name
        # (here: "case-data") as the case_id.
        from server.tools.correlations import record_correlation

        record_correlation(
            case_id="case-data",
            iteration_number=1,
            correlation_type="strengthens",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded line",
                )
            ],
            hypothesis=(
                "Cross-validation: the finding's process anomaly is reinforced "
                "by a parallel observation in another evidence stream."
            ),
            target_finding_id=df.finding_id,
            case_dir=str(case_dir),
        )

        audit_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text(encoding="utf-8")
            .strip()
            .splitlines()
        )
        last = json.loads(audit_lines[-1])
        assert last["tool_name"] == "record_correlation"
        output_hash = last["output_hash"]

        display = ProgressDisplay(case_dir=case_dir, stream=None)
        correlation = display._lookup_correlation_by_hash(output_hash)
        assert correlation is not None
        assert correlation["correlation_type"] == "strengthens"
        assert correlation["target_finding_id"] == df.finding_id

    def test_correlation_lookup_missing_file_returns_none(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        display = ProgressDisplay(case_dir=case_dir, stream=None)
        assert display._lookup_correlation_by_hash("0" * 64) is None
