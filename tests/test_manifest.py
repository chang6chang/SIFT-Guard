"""Unit tests for `orchestrator.manifest`."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from orchestrator.manifest import (
    CaseManifest,
    EvidenceFile,
    HostEvidence,
    manifest_exists,
    read_manifest,
    write_manifest,
)


VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)


def _make_manifest(case_id: str = "case-data") -> CaseManifest:
    ef = EvidenceFile(
        evidence_id=VALID_EVIDENCE_ID,
        file_path="/case/evidence/nfury-memory.raw",
        evidence_type="memory",
        os_guess="Windows 7 64-bit",
        file_size_bytes=14_000_000_000,
    )
    host = HostEvidence(
        host_id="nfury",
        host_label="nfury",
        evidence_files=[ef],
    )
    return CaseManifest(
        case_id=case_id,
        hosts=[host],
        created_at=NOW_UTC,
    )


class TestEvidenceFile:
    def test_minimum_fields_validate(self):
        ef = EvidenceFile(
            evidence_id="abc",
            file_path="/x",
            evidence_type="memory",
            file_size_bytes=0,
        )
        assert ef.evidence_type == "memory"
        assert ef.os_guess is None

    def test_unknown_evidence_type_rejected(self):
        with pytest.raises(Exception):
            EvidenceFile(
                evidence_id="abc",
                file_path="/x",
                evidence_type="lolwut",  # type: ignore[arg-type]
                file_size_bytes=0,
            )

    def test_negative_size_rejected(self):
        with pytest.raises(Exception):
            EvidenceFile(
                evidence_id="abc",
                file_path="/x",
                evidence_type="memory",
                file_size_bytes=-1,
            )


class TestHostEvidence:
    def test_zero_evidence_files_rejected(self):
        with pytest.raises(Exception):
            HostEvidence(
                host_id="nfury",
                host_label="nfury",
                evidence_files=[],
            )

    def test_invalid_host_id_pattern_rejected(self):
        # Spaces / slashes / quotes don't pass the host_id pattern.
        with pytest.raises(Exception):
            HostEvidence(
                host_id="bad host id",
                host_label="bad",
                evidence_files=[
                    EvidenceFile(
                        evidence_id="x",
                        file_path="/y",
                        evidence_type="memory",
                        file_size_bytes=1,
                    )
                ],
            )


class TestCaseManifest:
    def test_naive_datetime_rejected(self):
        with pytest.raises(Exception):
            CaseManifest(
                case_id="case-data",
                hosts=[],
                created_at=datetime(2026, 5, 8, 12, 0, 0),  # naive
            )

    def test_evidence_count_aggregates_across_hosts(self, tmp_path: Path):
        m = _make_manifest()
        # Add a second host with two files.
        m.hosts.append(
            HostEvidence(
                host_id="controller",
                host_label="controller",
                evidence_files=[
                    EvidenceFile(
                        evidence_id="a",
                        file_path="/c/m.raw",
                        evidence_type="memory",
                        file_size_bytes=1,
                    ),
                    EvidenceFile(
                        evidence_id="b",
                        file_path="/c/d.E01",
                        evidence_type="disk",
                        file_size_bytes=1,
                    ),
                ],
            )
        )
        assert m.evidence_count == 3


class TestPersistence:
    def test_write_then_read_roundtrip(self, tmp_path: Path):
        m = _make_manifest()
        path = write_manifest(m, tmp_path)
        assert path.exists()
        assert manifest_exists(tmp_path)
        loaded = read_manifest(tmp_path)
        assert loaded.case_id == m.case_id
        assert len(loaded.hosts) == 1
        assert loaded.hosts[0].host_id == "nfury"
        assert loaded.hosts[0].evidence_files[0].evidence_id == VALID_EVIDENCE_ID
        # Datetime survives the round-trip with UTC offset preserved.
        assert loaded.created_at.tzinfo is not None

    def test_read_missing_manifest_raises_file_not_found(self, tmp_path: Path):
        assert not manifest_exists(tmp_path)
        with pytest.raises(FileNotFoundError):
            read_manifest(tmp_path)
