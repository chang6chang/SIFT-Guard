"""Unit tests for `server.tools.memory.vol_netscan`.

Mirrors `test_vol_pstree.py` / `test_vol_psscan.py`. The fixture
covers all four protocol families plus a null-PID kernel-only
record — the diagnostic shape the validator will need to recognise:

  - TCPv4 LISTENING     (System PID 4, classic SMB/445 listener)
  - TCPv4 ESTABLISHED   (real outbound connection with port and
                          foreign address)
  - UDPv4 with empty State (UDP is connectionless; netscan emits
                          state == "" not null)
  - TCPv6 LISTENING     (IPv6 address handled without truncation)
  - UDPv4 with null PID + null Owner (kernel-only endpoint)
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
from server.tools.memory import translate_to_vm_path, vol_netscan


PROJECT_ROOT = Path(__file__).resolve().parent.parent
NETSCAN_FIXTURE = Path(__file__).parent / "fixtures" / "vol_netscan_sample.json"
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
    """Same helper shape as the other memory-tool unit tests; kept
    in-module for symmetry."""
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
    """Three netscan rows; the middle one has LocalPort -1 (violates
    ge=0 le=65535 on the schema). Flanking rows are valid TCPv4
    records. The bad one must be skipped with a warning, the good
    ones must survive."""
    return json.dumps(
        [
            {
                "Created": "2024-01-01T00:00:00+00:00",
                "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                "LocalAddr": "0.0.0.0", "LocalPort": 80,
                "Offset": 100, "Owner": "System", "PID": 4,
                "Proto": "TCPv4", "State": "LISTENING",
                "__children": [],
            },
            {
                "Created": "2024-01-01T00:00:00+00:00",
                "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                "LocalAddr": "0.0.0.0", "LocalPort": -1,
                "Offset": 200, "Owner": "Bad", "PID": 99,
                "Proto": "TCPv4", "State": "LISTENING",
                "__children": [],
            },
            {
                "Created": "2024-01-01T00:00:00+00:00",
                "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                "LocalAddr": "0.0.0.0", "LocalPort": 443,
                "Offset": 300, "Owner": "System", "PID": 4,
                "Proto": "TCPv4", "State": "LISTENING",
                "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolNetscanResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_netscan(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        assert bogus_id not in str(exc_info.value)

    def test_artifact_class_unknown_rejected_with_sanitized_message(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_netscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a memory image"
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — assert the prefix is `vol_netscan:rejected_*`
# ---------------------------------------------------------------------------


_GENESIS_PREV_HASH = "0" * 64


class TestVolNetscanRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_netscan(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_netscan:rejected_evidence_not_found"
        assert entry["evidence_id"] == bogus_id
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64

    def test_wrong_artifact_class_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError):
            vol_netscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        assert (
            lines[0]["tool_name"]
            == "vol_netscan:rejected_wrong_artifact_class"
        )

    def test_path_translation_failed_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, absolute_path="/tmp/Foo.raw")
        with pytest.raises(ValueError) as exc_info:
            vol_netscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert "/tmp/Foo.raw" not in str(exc_info.value)
        assert "expected host prefix" in str(exc_info.value)
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        assert (
            lines[0]["tool_name"]
            == "vol_netscan:rejected_path_translation_failed"
        )


# ---------------------------------------------------------------------------
# happy path — five records exercising the TCP/UDP + v4/v6 + null-PID
# matrix the prompt asked for
# ---------------------------------------------------------------------------


class TestVolNetscanHappyPath:
    def test_returns_netscan_result_with_all_five_protocol_cases(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = NETSCAN_FIXTURE.read_text(encoding="utf-8")
        # Runtime > psscan's mock value to surface a copy-paste bug if
        # vol_netscan ever wires through the wrong run_vol_plugin
        # mock. 537 was the actual integration time.
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.netscan.NetScan"
        )

        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, fake_command, 537.4),
        ) as mock_run:
            result = vol_netscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        assert result.plugin_name == "windows.netscan.NetScan"
        assert result.volatility_version == "2.27.0"
        assert result.evidence_id == VALID_EVIDENCE_ID
        assert result.runtime_seconds == 537.4
        assert result.command_executed == fake_command

        assert len(result.connections) == 5

        # (a) TCPv4 LISTENING — System PID 4 holding port 445.
        smb = result.connections[0]
        assert smb.proto == "TCPv4"
        assert smb.state == "LISTENING"
        assert smb.local_addr == "0.0.0.0"
        assert smb.local_port == 445
        assert smb.pid == 4 and smb.owner == "System"

        # (b) TCPv4 ESTABLISHED — real outbound connection with both
        # foreign address and foreign port populated.
        apsd = result.connections[1]
        assert apsd.proto == "TCPv4"
        assert apsd.state == "ESTABLISHED"
        assert apsd.foreign_addr == "17.57.144.165"
        assert apsd.foreign_port == 5223
        assert apsd.local_port == 53810

        # (c) UDPv4 with empty state — UDP is connectionless; netscan
        # emits state == "" rather than null. Schema accepts the empty
        # string.
        udp = result.connections[2]
        assert udp.proto == "UDPv4"
        assert udp.state == "", "UDP records must keep empty-string state"
        assert udp.foreign_addr == "*"  # wildcard for unbound
        assert udp.local_port == 1900

        # (d) IPv6 — long colon-hex address must survive without
        # truncation. (No length cap on local_addr.)
        v6 = result.connections[3]
        assert v6.proto == "TCPv6"
        assert v6.local_addr == "fe80::d18c:bb1:3264:8c8"
        assert ":" in v6.local_addr and len(v6.local_addr) > 15

        # (e) Null PID + null Owner — kernel-only endpoint or socket
        # whose owning process exited but pool entry survived. Schema
        # must accept None for both.
        kernel = result.connections[4]
        assert kernel.pid is None and kernel.owner is None
        assert kernel.proto == "UDPv4"
        assert kernel.local_port == 5353

        # The runner was called with the pinned plugin name AND the
        # 1200s netscan timeout — vol_pslist's 300s default would time
        # out partway through netscan's 8-9 minute pool scan.
        plugin_arg, vm_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.netscan.NetScan"
        assert vm_path_arg == "/mnt/rocba/Rocba-Memory.raw"
        assert mock_run.call_args.kwargs.get("timeout_seconds") == 1200, (
            "vol_netscan must override run_vol_plugin's 300s default — "
            "netscan against Rocba was 8m57s observed"
        )


# ---------------------------------------------------------------------------
# per-record validation warnings (per-row skip, like pslist/psscan;
# unlike pstree's per-subtree skip)
# ---------------------------------------------------------------------------


class TestVolNetscanRecordWarnings:
    def test_one_bad_record_logged_as_warning_others_preserved(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(_bad_record_json(), "ssh ... vol ...", 540.0),
        ):
            result = vol_netscan(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Two valid records survived, the LocalPort=-1 row is gone.
        assert len(result.connections) == 2
        assert {c.local_port for c in result.connections} == {80, 443}

        # Audit log: 1 warning + 1 main result line, in that order.
        # tool_name distinct from the other plugins' warnings so a
        # chain reader can grep distinctly.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_netscan:record_validation_warning"
        assert lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert lines[1]["tool_name"] == "vol_netscan"
        assert lines[1]["prev_line_hash"] == lines[0]["this_line_hash"]


# ---------------------------------------------------------------------------
# audit-chain extension from the real on-disk chain
# ---------------------------------------------------------------------------


class TestAuditChain:
    def test_audit_chain_extends_from_existing_on_disk_chain(
        self, tmp_path: Path
    ):
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
        last_seeded = json.loads(seeded_lines[-1])
        expected_prev = last_seeded["this_line_hash"]

        fixture_stdout = NETSCAN_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 540.0),
        ):
            vol_netscan(rocba_evidence_id, case_dir=str(case_dir))

        new_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        assert len(new_lines) == seeded_count + 1
        new_entry = json.loads(new_lines[-1])
        assert new_entry["tool_name"] == "vol_netscan"
        assert new_entry["evidence_id"] == rocba_evidence_id
        assert new_entry["prev_line_hash"] == expected_prev, (
            "vol_netscan's audit line failed to link to the prior "
            "chain — chain is broken"
        )
        assert new_entry["line_number"] == seeded_count + 1

        assert ON_DISK_AUDIT_LOG.read_bytes() == on_disk_audit_before, (
            "on-disk audit log was modified by the test — isolation "
            "is broken"
        )
