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


class TestRegisterEvidenceInPlace:
    """``confine_to_evidence_dir=False`` — the orchestrator-internal
    code path used by ``sift-guard analyze --no-copy``. The MCP-exposed
    register_evidence still enforces confinement (the kwarg defaults
    to True); only the CLI's own pre-flight bypasses it."""

    def test_registers_path_outside_evidence_dir(self, tmp_path: Path, case_dir: Path):
        # Source file lives outside <case_dir>/evidence/.
        source = tmp_path / "outside-source.dat"
        source.write_bytes(secrets.token_bytes(64 * 1024))
        expected_sha = hashlib.sha256(source.read_bytes()).hexdigest()

        record = register_evidence(
            str(source),
            case_dir=str(case_dir),
            confine_to_evidence_dir=False,
        )

        assert record.absolute_path == str(source.resolve())
        assert record.sha256 == expected_sha
        # Original gets chmod 444 even though it lives outside the
        # case dir — the "register" contract is the same.
        assert stat.S_IMODE(source.stat().st_mode) == 0o444

    def test_default_still_rejects_outside_paths(self, tmp_path: Path, case_dir: Path):
        """The default value of confine_to_evidence_dir must remain True
        so the MCP tool can't be tricked into registering arbitrary files."""
        source = tmp_path / "outside-source.dat"
        source.write_bytes(b"x")
        with pytest.raises(PermissionError):
            register_evidence(str(source), case_dir=str(case_dir))


class TestRegisterEvidenceIdempotency:
    """Re-running ``sift-guard analyze`` against the same case_dir
    must not re-hash already-registered evidence. Skip is gated on
    BOTH (a) file mode 0o444 AND (b) CASE.yaml has a matching entry."""

    def test_second_call_skips_rehash_and_returns_existing_record(
        self, fixture_file: Path, case_dir: Path, monkeypatch
    ):
        first = register_evidence(str(fixture_file), case_dir=str(case_dir))

        # Spy on the hasher — second call must NOT recompute.
        from server.tools import evidence as evidence_module

        rehash_called = {"count": 0}
        original_hasher = evidence_module._stream_sha256_and_magic

        def counting_hasher(*args, **kwargs):
            rehash_called["count"] += 1
            return original_hasher(*args, **kwargs)

        monkeypatch.setattr(evidence_module, "_stream_sha256_and_magic", counting_hasher)

        second = register_evidence(str(fixture_file), case_dir=str(case_dir))

        assert second.evidence_id == first.evidence_id
        assert second.sha256 == first.sha256
        assert rehash_called["count"] == 0, (
            "second registration must not re-hash a file with mode 0o444 + CASE.yaml entry"
        )

    def test_skip_writes_audit_entry(
        self, fixture_file: Path, case_dir: Path
    ):
        register_evidence(str(fixture_file), case_dir=str(case_dir))
        register_evidence(str(fixture_file), case_dir=str(case_dir))

        audit_lines = [
            json.loads(line)
            for line in _audit_path(case_dir).read_text().splitlines()
            if line.strip()
        ]
        # First line: full register_evidence. Second line:
        # register_evidence:idempotent_skip — the skip path must still
        # extend the audit chain so it's not an unrecorded probe.
        tool_names = [entry["tool_name"] for entry in audit_lines]
        assert tool_names == [
            "register_evidence",
            "register_evidence:idempotent_skip",
        ]

    def test_skip_does_not_fire_without_case_yaml_entry(
        self, tmp_path: Path, case_dir: Path, monkeypatch
    ):
        """File already chmod 444 but NEVER registered (no CASE.yaml
        entry yet). Should NOT skip — the chmod alone isn't enough."""
        path = case_dir / "evidence" / "preexisting.dat"
        path.write_bytes(secrets.token_bytes(32 * 1024))
        path.chmod(0o444)

        from server.tools import evidence as evidence_module

        rehash_called = {"count": 0}
        original = evidence_module._stream_sha256_and_magic

        def counting(*args, **kwargs):
            rehash_called["count"] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(evidence_module, "_stream_sha256_and_magic", counting)

        register_evidence(str(path), case_dir=str(case_dir))

        assert rehash_called["count"] == 1, (
            "first registration must hash even when file is already 0o444"
        )


class TestServerMainCaseDirEnv:
    """The MCP server resolves CASE_DIR from SIFT_GUARD_CASE_DIR at
    import time. The orchestrator's per-case .mcp.json injects this
    via the ``env`` block so every spawned MCP-server child writes
    to the operator's case_dir, not the legacy ``case-data`` default.
    Regression test for the 2026-05-12 SRL re-run incident."""

    def test_env_var_overrides_default(self, tmp_path: Path, monkeypatch):
        # Module-level resolution is one-shot at import; reimport to
        # re-evaluate the env var.
        custom = tmp_path / "explicit-case"
        monkeypatch.setenv("SIFT_GUARD_CASE_DIR", str(custom))

        import importlib

        import server.main as server_main

        importlib.reload(server_main)
        try:
            assert server_main.CASE_DIR == str(custom)
        finally:
            # Restore default behavior for the rest of the suite.
            monkeypatch.delenv("SIFT_GUARD_CASE_DIR", raising=False)
            importlib.reload(server_main)
            assert server_main.CASE_DIR == "case-data"

    def test_unset_env_var_falls_back_to_case_data(self, monkeypatch):
        monkeypatch.delenv("SIFT_GUARD_CASE_DIR", raising=False)
        import importlib

        import server.main as server_main

        importlib.reload(server_main)
        assert server_main.CASE_DIR == "case-data"
