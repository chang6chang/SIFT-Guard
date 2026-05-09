"""Tests for `server.tools.evidence.register_evidence`.

Coverage targets per spec:
(a) returns a valid EvidenceRecord with the correct sha256
(b) the file is chmod 0o444 after registration
(c) CASE.yaml is created and contains the entry
(d) the audit log file gets a hash-chained line
(e) a second registration appends a second hash-chained line where
    prev_line_hash equals the first line's this_line_hash
(f) registering a non-existent path raises FileNotFoundError
"""

from __future__ import annotations

import hashlib
import json
import secrets
import stat
from pathlib import Path

import pytest
import yaml

from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.evidence import register_evidence


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """Case directory inside the test's tmp_path, with `evidence/`
    pre-created. Every fixture file lives under `evidence/` so the
    path-confinement check in `register_evidence` passes."""
    cd = tmp_path / "case-data"
    cd.mkdir()
    (cd / "evidence").mkdir()
    return cd


@pytest.fixture
def fixture_file(case_dir: Path) -> Path:
    """Create a 1 MB random file inside <case_dir>/evidence/."""
    fixture_path = case_dir / "evidence" / "fixture.dat"
    fixture_path.write_bytes(secrets.token_bytes(1 * 1024 * 1024))
    return fixture_path


def _audit_path(case_dir: Path) -> Path:
    return case_dir / "audit" / "sift-guard-mcp.jsonl"


def _case_yaml(case_dir: Path) -> Path:
    return case_dir / "CASE.yaml"


class TestRegisterEvidence:
    def test_returns_valid_record_with_correct_sha256(self, fixture_file: Path, case_dir: Path):
        expected_sha = hashlib.sha256(fixture_file.read_bytes()).hexdigest()

        record = register_evidence(str(fixture_file), case_dir=str(case_dir))

        assert isinstance(record, EvidenceRecord)
        assert record.sha256 == expected_sha
        assert record.size_bytes == 1 * 1024 * 1024
        assert record.original_filename == "fixture.dat"
        # 1 MB .dat with random bytes does not match any known magic
        # signature and the size is below the 100 MB memory-image
        # heuristic, so it must classify as UNKNOWN.
        assert record.artifact_class is ArtifactClass.UNKNOWN
        assert record.file_mode_after_registration == "0o444"

    def test_file_is_chmod_444_after_registration(self, fixture_file: Path, case_dir: Path):
        register_evidence(str(fixture_file), case_dir=str(case_dir))
        mode = stat.S_IMODE(fixture_file.stat().st_mode)
        assert mode == 0o444, f"expected 0o444, got {oct(mode)}"

    def test_case_yaml_created_with_entry(self, fixture_file: Path, case_dir: Path):
        record = register_evidence(str(fixture_file), case_dir=str(case_dir))

        case_yaml = _case_yaml(case_dir)
        assert case_yaml.exists()

        with case_yaml.open() as f:
            doc = yaml.safe_load(f)

        assert doc["case_id"] == case_dir.name
        assert "registered_at" in doc
        assert isinstance(doc["evidence"], list)
        assert len(doc["evidence"]) == 1
        entry = doc["evidence"][0]
        assert entry["evidence_id"] == record.evidence_id
        assert entry["sha256"] == record.sha256
        assert entry["original_filename"] == "fixture.dat"
        assert entry["artifact_class"] == "unknown"

    def test_audit_log_gets_hash_chained_line(self, fixture_file: Path, case_dir: Path):
        record = register_evidence(str(fixture_file), case_dir=str(case_dir))

        audit_path = _audit_path(case_dir)
        assert audit_path.exists()
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1

        entry = json.loads(lines[0])
        assert entry["line_number"] == 1
        assert entry["tool_name"] == "register_evidence"
        assert entry["evidence_id"] == record.evidence_id
        assert entry["prev_line_hash"] == "0" * 64
        assert len(entry["this_line_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["this_line_hash"])
        # The output_hash must be sha256 of the EvidenceRecord's JSON.
        expected_output_hash = hashlib.sha256(record.model_dump_json().encode("utf-8")).hexdigest()
        assert entry["output_hash"] == expected_output_hash

    def test_second_registration_appends_chained_line(self, case_dir: Path):
        evidence_dir = case_dir / "evidence"
        fix1 = evidence_dir / "first.dat"
        fix2 = evidence_dir / "second.dat"
        fix1.write_bytes(secrets.token_bytes(512))
        fix2.write_bytes(secrets.token_bytes(512))

        register_evidence(str(fix1), case_dir=str(case_dir))
        register_evidence(str(fix2), case_dir=str(case_dir))

        lines = _audit_path(case_dir).read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2

        line1 = json.loads(lines[0])
        line2 = json.loads(lines[1])
        assert line1["line_number"] == 1
        assert line2["line_number"] == 2
        assert line2["prev_line_hash"] == line1["this_line_hash"], (
            "second line's prev_line_hash must equal first line's this_line_hash — chain is broken"
        )

    def test_case_yaml_accumulates_entries_across_registrations(self, case_dir: Path):
        evidence_dir = case_dir / "evidence"
        fix1 = evidence_dir / "first.dat"
        fix2 = evidence_dir / "second.dat"
        fix1.write_bytes(secrets.token_bytes(512))
        fix2.write_bytes(secrets.token_bytes(512))

        register_evidence(str(fix1), case_dir=str(case_dir))
        register_evidence(str(fix2), case_dir=str(case_dir))

        with _case_yaml(case_dir).open() as f:
            doc = yaml.safe_load(f)

        assert len(doc["evidence"]) == 2
        # case_id is fixed at first registration; subsequent registrations
        # do not overwrite it.
        assert doc["case_id"] == case_dir.name

    def test_nonexistent_path_raises_file_not_found(self, case_dir: Path):
        with pytest.raises(FileNotFoundError):
            register_evidence(
                str(case_dir / "evidence" / "does-not-exist.dat"),
                case_dir=str(case_dir),
            )

    def test_nonexistent_path_does_not_create_audit_log(self, case_dir: Path):
        with pytest.raises(FileNotFoundError):
            register_evidence(
                str(case_dir / "evidence" / "does-not-exist.dat"),
                case_dir=str(case_dir),
            )
        # Failure must not poison the chain with a half-record.
        assert not _audit_path(case_dir).exists()
        assert not _case_yaml(case_dir).exists()

    def test_empty_evidence_id_field_is_a_real_uuid4_string(
        self, fixture_file: Path, case_dir: Path
    ):
        import uuid as uuid_mod

        record = register_evidence(str(fixture_file), case_dir=str(case_dir))
        parsed = uuid_mod.UUID(record.evidence_id)
        assert parsed.version == 4


_SANITIZED_CONFINEMENT_MSG = "Path outside evidence directory rejected"


class TestPathConfinement:
    """`register_evidence` must refuse any path that does not resolve under
    `<case_dir>/evidence/`. The check runs before the existence check, the
    magic-byte read, and any chmod, so a confinement failure leaves the
    filesystem untouched and the audit chain unbroken. The error message
    is sanitized — the offending path is never echoed back. Backs the
    decisions-log 2026-05-05 MCP error-message sanitization rule."""

    def test_path_outside_evidence_root_is_rejected(self, tmp_path: Path, case_dir: Path):
        outside = tmp_path / "outside.dat"
        outside.write_bytes(b"x" * 64)

        with pytest.raises(PermissionError) as exc_info:
            register_evidence(str(outside), case_dir=str(case_dir))

        assert str(exc_info.value) == _SANITIZED_CONFINEMENT_MSG
        # Sanitization: the offending path must not appear in the message.
        assert str(outside) not in str(exc_info.value)
        assert "outside.dat" not in str(exc_info.value)
        # No side effects: confinement runs before any write.
        assert not _audit_path(case_dir).exists()
        assert not _case_yaml(case_dir).exists()

    def test_dotdot_traversal_outside_evidence_root_is_rejected(
        self, tmp_path: Path, case_dir: Path
    ):
        # Real file lives outside evidence/. Agent attempts to reach it
        # by traversing up from inside evidence/. resolve(strict=False)
        # collapses the ../, exposing that the canonical path is not
        # under evidence_root.
        outside = tmp_path / "outside.dat"
        outside.write_bytes(b"x" * 64)
        evidence_dir = case_dir / "evidence"
        traversal = evidence_dir / ".." / ".." / "outside.dat"

        with pytest.raises(PermissionError) as exc_info:
            register_evidence(str(traversal), case_dir=str(case_dir))

        assert str(exc_info.value) == _SANITIZED_CONFINEMENT_MSG
        assert not _audit_path(case_dir).exists()
        assert not _case_yaml(case_dir).exists()

    def test_symlink_inside_evidence_pointing_outside_is_rejected(
        self, tmp_path: Path, case_dir: Path
    ):
        # Real file outside evidence/.
        target = tmp_path / "secret.dat"
        target.write_bytes(b"sensitive")
        original_target_mode = stat.S_IMODE(target.stat().st_mode)

        # Symlink inside evidence/ pointing at the outside file.
        # resolve(strict=False) follows the symlink to its target, which
        # is outside evidence_root, and relative_to() then raises.
        link = case_dir / "evidence" / "decoy.dat"
        link.symlink_to(target)

        with pytest.raises(PermissionError) as exc_info:
            register_evidence(str(link), case_dir=str(case_dir))

        assert str(exc_info.value) == _SANITIZED_CONFINEMENT_MSG
        # The target file outside evidence/ must not have been chmodded
        # to 0o444 — confinement blocks the call before the chmod runs.
        assert stat.S_IMODE(target.stat().st_mode) == original_target_mode
        assert not _audit_path(case_dir).exists()
        assert not _case_yaml(case_dir).exists()
