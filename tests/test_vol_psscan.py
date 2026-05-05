"""Unit tests for `server.tools.memory.vol_psscan`.

Mirrors the structure of ``tests/test_vol_pslist.py`` line-for-line.
Differences live in:

    - the plugin name asserted (windows.psscan.PsScan)
    - the rejection tool_name prefix (vol_psscan:rejected_*)
    - the warning tool_name (vol_psscan:record_validation_warning)
    - the fixture file (vol_psscan_sample.json) — includes one exited
      record (non-null ExitTime) which is psscan's diagnostic value
      proposition over pslist

The audit-chain extension test (``TestAuditChain``) reads the actual
on-disk ``case-data/CASE.yaml`` and audit log to seed a tmp_path-isolated
case dir, then verifies the new audit line links to the copied chain.
The on-disk audit log itself is never written — checked at the end.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.memory import translate_to_vm_path, vol_psscan


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PSSCAN_FIXTURE = Path(__file__).parent / "fixtures" / "vol_psscan_sample.json"
ON_DISK_CASE_YAML = PROJECT_ROOT / "case-data" / "CASE.yaml"
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MEMORY_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    filename: str = "Rocba-Memory.raw",
    absolute_path: str | None = None,
) -> Path:
    """Build a tmp case dir with a CASE.yaml entry for one piece of evidence.

    Identical helper to test_vol_pslist's — kept in-module rather than
    extracted so each test file is self-contained and a reader can grep
    for `_make_case_dir` and find the version that matched its asserts."""
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()
    if absolute_path is None:
        fake_evidence = evidence_dir / filename
        fake_evidence.write_bytes(b"\x00" * 1024)
        absolute_path = str(fake_evidence)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename=filename,
        absolute_path=absolute_path,
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


def _bad_record_json() -> str:
    """Three-row psscan output with a middle record that fails
    ProcessRecord validation (PID -1 violates `ge=0`). Flanking rows are
    valid. The invalid row's other fields (including ExitTime) are
    structurally correct so the only validation failure is the negative
    PID — keeps the test focused on the per-record skip behavior."""
    return json.dumps(
        [
            {
                "PID": 4, "PPID": 0, "ImageFileName": "System",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
            {
                "PID": -1, "PPID": 0, "ImageFileName": "Bad",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
            {
                "PID": 100, "PPID": 4, "ImageFileName": "smss.exe",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolPsscanResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_psscan(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        # Sanitized: the attempted evidence_id is not echoed back.
        assert bogus_id not in str(exc_info.value)

    def test_artifact_class_unknown_rejected_with_sanitized_message(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_psscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a memory image"
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — the chain must record every agent call,
# including rejections, otherwise rejection becomes an unrecorded
# probe channel. Symmetric to test_vol_pslist's TestVolPslistRejectionAudit
# — and explicitly asserts the prefix is `vol_psscan:rejected_*`, not
# `vol_pslist:rejected_*`, so a copy-paste bug that wired psscan's
# rejections through pslist's helper would be caught.
# ---------------------------------------------------------------------------


_GENESIS_PREV_HASH = "0" * 64


class TestVolPsscanRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_psscan(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_psscan:rejected_evidence_not_found"
        assert entry["evidence_id"] == bogus_id
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["this_line_hash"])

    def test_wrong_artifact_class_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(
            tmp_path, artifact_class=ArtifactClass.UNKNOWN
        )

        with pytest.raises(ValueError):
            vol_psscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"]
            == "vol_psscan:rejected_wrong_artifact_class"
        )
        assert entry["evidence_id"] == VALID_EVIDENCE_ID
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH

    def test_path_translation_failed_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, absolute_path="/tmp/Foo.raw")

        with pytest.raises(ValueError) as exc_info:
            vol_psscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Sanitized: the offending path is not echoed back to the agent.
        assert "/tmp/Foo.raw" not in str(exc_info.value)
        assert "expected host prefix" in str(exc_info.value)

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"]
            == "vol_psscan:rejected_path_translation_failed"
        )
        assert entry["evidence_id"] == VALID_EVIDENCE_ID
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


class TestVolPsscanHappyPath:
    def test_returns_psscan_result_with_three_records(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PSSCAN_FIXTURE.read_text(encoding="utf-8")
        # Runtime intentionally set well above the pslist test's value
        # so a future copy-paste bug that wired vol_psscan through the
        # pslist mock would be caught — pslist on Rocba is ~5s, psscan
        # is ~400s. Anything in between is suspicious.
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.psscan.PsScan"
        )

        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, fake_command, 396.3),
        ) as mock_run:
            result = vol_psscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        assert result.plugin_name == "windows.psscan.PsScan"
        assert result.volatility_version == "2.27.0"
        assert result.evidence_id == VALID_EVIDENCE_ID
        assert result.runtime_seconds == 396.3
        assert result.command_executed == fake_command

        assert len(result.processes) == 3
        assert result.processes[0].pid == 4
        assert result.processes[0].image_file_name == "System"
        assert result.processes[0].exit_time is None
        assert result.processes[1].pid == 100
        assert result.processes[1].image_file_name == "Registry"

        # Third record exercises psscan's diagnostic value: a process
        # with a non-null ExitTime. pslist's linked-list walk on a
        # post-exit image typically would not surface this row.
        assert result.processes[2].pid == 7784
        assert result.processes[2].image_file_name == "Teams.exe"
        assert result.processes[2].exit_time is not None
        assert result.processes[2].exit_time.year == 2020

        # The runner was called with the pinned plugin name AND the
        # bumped 900s timeout — psscan is ~30-50× slower than pslist
        # and the runner's 300s default would time out.
        plugin_arg, vm_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.psscan.PsScan"
        assert vm_path_arg == "/mnt/rocba/Rocba-Memory.raw"
        assert mock_run.call_args.kwargs.get("timeout_seconds") == 900, (
            "vol_psscan must override run_vol_plugin's 300s default — "
            "psscan against Rocba was 6m36s observed"
        )


# ---------------------------------------------------------------------------
# per-record validation warnings
# ---------------------------------------------------------------------------


class TestVolPsscanRecordWarnings:
    def test_one_bad_record_logged_as_warning_others_preserved(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(_bad_record_json(), "ssh ... vol ...", 396.0),
        ):
            result = vol_psscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # The two valid records survived; the PID -1 row is gone.
        assert len(result.processes) == 2
        assert {p.pid for p in result.processes} == {4, 100}

        # Audit log: 1 warning entry + 1 main result entry, in that
        # order. The warning's tool_name names the failure mode so a
        # reader can grep for it. Distinct from the pslist warning
        # tool_name so a chain reader can tell the two apart.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_psscan:record_validation_warning"
        assert lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert lines[1]["tool_name"] == "vol_psscan"
        # Chain link: the main result line points at the warning line's
        # this_line_hash.
        assert lines[1]["prev_line_hash"] == lines[0]["this_line_hash"]


# ---------------------------------------------------------------------------
# audit-chain extension from the real on-disk chain
# ---------------------------------------------------------------------------


class TestAuditChain:
    def test_audit_chain_extends_from_existing_on_disk_chain(
        self, tmp_path: Path
    ):
        """Seed the tmp case dir from the real on-disk CASE.yaml + audit
        log and verify vol_psscan's new audit line links to the copied
        chain's last `this_line_hash`. The on-disk audit log is never
        written — verified at the end."""
        on_disk_audit_before = ON_DISK_AUDIT_LOG.read_bytes()

        case_dir = tmp_path / "case-data"
        (case_dir / "audit").mkdir(parents=True)
        (case_dir / "evidence").mkdir(parents=True)
        shutil.copy(ON_DISK_CASE_YAML, case_dir / "CASE.yaml")
        shutil.copy(
            ON_DISK_AUDIT_LOG, case_dir / "audit" / "sift-guard-mcp.jsonl"
        )

        case_yaml_path = case_dir / "CASE.yaml"
        doc = yaml.safe_load(case_yaml_path.read_text())
        rocba_entry = next(
            e for e in doc["evidence"]
            if e["original_filename"] == "Rocba-Memory.raw"
        )
        rocba_evidence_id = rocba_entry["evidence_id"]
        fake_rocba = case_dir / "evidence" / "Rocba-Memory.raw"
        fake_rocba.write_bytes(b"\x00" * 1024)
        rocba_entry["absolute_path"] = str(fake_rocba)
        case_yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False))

        seeded_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        seeded_count = len(seeded_lines)
        assert seeded_count >= 2, (
            "expected the on-disk chain to have at least 2 lines"
        )
        last_seeded = json.loads(seeded_lines[-1])
        expected_prev = last_seeded["this_line_hash"]

        fixture_stdout = PSSCAN_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 396.0),
        ):
            vol_psscan(rocba_evidence_id, case_dir=str(case_dir))

        new_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        assert len(new_lines) == seeded_count + 1
        new_entry = json.loads(new_lines[-1])
        assert new_entry["tool_name"] == "vol_psscan"
        assert new_entry["evidence_id"] == rocba_evidence_id
        assert new_entry["prev_line_hash"] == expected_prev, (
            "vol_psscan's audit line failed to link to the prior "
            "chain — chain is broken"
        )
        assert new_entry["line_number"] == seeded_count + 1

        assert ON_DISK_AUDIT_LOG.read_bytes() == on_disk_audit_before, (
            "on-disk audit log was modified by the test — isolation "
            "is broken"
        )
