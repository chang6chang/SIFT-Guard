"""End-of-run evidence re-hash — CLAUDE.md 'Architectural enforcement
of evidence integrity': re-hash at end of every run; mismatch is fatal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from server.integrity import (
    EvidenceIntegrityError,
    assert_evidence_integrity,
    verify_evidence_integrity,
)


def _make_case(tmp_path: Path, content: bytes = b"evidence-bytes") -> tuple[Path, Path]:
    case_dir = tmp_path / "case-data"
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    f = evidence_dir / "mem.raw"
    f.write_bytes(content)
    doc = {
        "case_id": "case-data",
        "evidence": [
            {
                "evidence_id": "11111111-1111-4111-8111-111111111111",
                "original_filename": f.name,
                "absolute_path": str(f),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "artifact_class": "memory_image",
                "registered_at": "2026-07-14T00:00:00+00:00",
                "file_mode_after_registration": "0o444",
            }
        ],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc))
    return case_dir, f


class TestVerify:
    def test_intact_evidence_passes(self, tmp_path):
        case_dir, _ = _make_case(tmp_path)
        results = verify_evidence_integrity(case_dir)
        assert len(results) == 1 and results[0].ok

    def test_tampered_evidence_fails(self, tmp_path):
        case_dir, f = _make_case(tmp_path)
        f.chmod(0o644)
        f.write_bytes(b"TAMPERED")
        results = verify_evidence_integrity(case_dir)
        assert not results[0].ok
        assert results[0].sha256_actual != results[0].sha256_expected

    def test_missing_file_fails_with_error(self, tmp_path):
        case_dir, f = _make_case(tmp_path)
        f.chmod(0o644)
        f.unlink()
        results = verify_evidence_integrity(case_dir)
        assert not results[0].ok and results[0].error is not None

    def test_no_case_yaml_returns_empty(self, tmp_path):
        assert verify_evidence_integrity(tmp_path) == []

    def test_audit_lines_written(self, tmp_path):
        case_dir, _ = _make_case(tmp_path)
        verify_evidence_integrity(case_dir)
        audit = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(l) for l in audit.read_text().splitlines()]
        assert any(l["tool_name"] == "verify_evidence_integrity" for l in lines)

    def test_mismatch_audit_suffix(self, tmp_path):
        case_dir, f = _make_case(tmp_path)
        f.chmod(0o644)
        f.write_bytes(b"TAMPERED")
        verify_evidence_integrity(case_dir)
        audit = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(l) for l in audit.read_text().splitlines()]
        assert any(
            l["tool_name"] == "verify_evidence_integrity:mismatch" for l in lines
        )


class TestAssert:
    def test_raises_on_mismatch(self, tmp_path):
        case_dir, f = _make_case(tmp_path)
        f.chmod(0o644)
        f.write_bytes(b"TAMPERED")
        with pytest.raises(EvidenceIntegrityError):
            assert_evidence_integrity(case_dir)

    def test_passes_and_returns_results_when_intact(self, tmp_path):
        case_dir, _ = _make_case(tmp_path)
        results = assert_evidence_integrity(case_dir)
        assert all(r.ok for r in results)

    def test_error_message_names_no_paths(self, tmp_path):
        case_dir, f = _make_case(tmp_path)
        f.chmod(0o644)
        f.write_bytes(b"TAMPERED")
        with pytest.raises(EvidenceIntegrityError) as exc_info:
            assert_evidence_integrity(case_dir)
        assert str(f) not in str(exc_info.value)
