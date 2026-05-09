"""Unit tests for `server.tools.memory.vol_malfind`.

Mirrors `test_vol_pslist.py` / `test_vol_netscan.py`. The fixture
covers the diagnostic shape the analyst will see on a Rocba-style
case: two RWX VAD detections in a single svchost (PID 7900,
multiple-detections-per-PID is the malfind norm) plus one
PAGE_EXECUTE_WRITECOPY detection in explorer.exe with a null
disassembly field — the disassembler bails on some byte sequences
and Vol surfaces null in the JSON output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord, MalfindRecord
from server.tools.memory import vol_malfind


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MALFIND_FIXTURE = Path(__file__).parent / "fixtures" / "vol_malfind_sample.json"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)
_GENESIS_PREV_HASH = "0" * 64


def _make_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MEMORY_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    filename: str = "Rocba-Memory.raw",
    absolute_path: str | None = None,
) -> Path:
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
    """Three malfind rows; the middle row has PID -1 (violates ge=0)."""
    return json.dumps(
        [
            {
                "PID": 100,
                "Process": "smss.exe",
                "Start VPN": "0x100000",
                "End VPN": "0x100fff",
                "Tag": "VadS",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "CommitCharge": 1,
                "PrivateMemory": 1,
                "File output": "Disabled",
                "Hexdump": "deadbeef",
                "Disasm": None,
                "Notes": "",
                "__children": [],
            },
            {
                "PID": -1,
                "Process": "Bad",
                "Start VPN": "0x200000",
                "End VPN": "0x200fff",
                "Tag": "VadS",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "CommitCharge": 1,
                "PrivateMemory": 1,
                "File output": "Disabled",
                "Hexdump": "00",
                "Disasm": None,
                "Notes": "",
                "__children": [],
            },
            {
                "PID": 200,
                "Process": "lsass.exe",
                "Start VPN": "0x300000",
                "End VPN": "0x300fff",
                "Tag": "VadS",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "CommitCharge": 1,
                "PrivateMemory": 1,
                "File output": "Disabled",
                "Hexdump": "cafebabe",
                "Disasm": None,
                "Notes": "",
                "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolMalfindResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_malfind(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        assert bogus_id not in str(exc_info.value)

    def test_artifact_class_unknown_rejected_with_sanitized_message(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_malfind(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a memory image"
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — chain must record every agent call
# ---------------------------------------------------------------------------


class TestVolMalfindRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_malfind(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_malfind:rejected_evidence_not_found"
        assert entry["evidence_id"] == bogus_id
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64


# ---------------------------------------------------------------------------
# happy path — three detections (two RWX in one svchost + one
# PAGE_EXECUTE_WRITECOPY in explorer)
# ---------------------------------------------------------------------------


class TestVolMalfindHappyPath:
    def test_returns_malfind_summary_with_three_detections(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = MALFIND_FIXTURE.read_text(encoding="utf-8")
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.malfind.Malfind"
        )

        with (
            patch("server.tools.memory.get_vol_version", return_value="2.27.0"),
            patch(
                "server.tools.memory.run_vol_plugin",
                return_value=(fixture_stdout, fake_command, 73.5),
            ) as mock_run,
        ):
            summary = vol_malfind(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        ref = summary.extraction
        assert ref.plugin_name == "windows.malfind.Malfind"
        assert ref.evidence_id == VALID_EVIDENCE_ID
        assert ref.record_count == 3
        assert ref.cached is False
        assert ref.runtime_seconds == 73.5
        assert ref.extractions_chain_line == 1
        assert len(ref.extraction_sha256) == 64

        assert summary.unique_process_names == 2  # svchost + explorer
        assert summary.pid_range == (1234, 7900)
        # PID 7900 / svchost.exe owns 2 detections; explorer 1.
        detections_dict = dict(summary.detections_by_process)
        assert detections_dict.get("svchost.exe") == 2
        assert detections_dict.get("explorer.exe") == 1
        # Two RWX detections + one WRITECOPY.
        assert summary.protection_distribution == {
            "PAGE_EXECUTE_READWRITE": 2,
            "PAGE_EXECUTE_WRITECOPY": 1,
        }
        assert summary.vad_tag_distribution == {"VadS": 2, "Vad ": 1}

        assert summary.untrusted_fields == ["detections_by_process_keys"]

        # Summary stays under the tier-1 10 KB ceiling.
        assert len(summary.model_dump_json().encode("utf-8")) <= 10_000

        # Stored extraction has the full detection list.
        loaded_ref, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "windows.malfind.Malfind")
        assert loaded_ref.cached is True
        assert loaded_ref.runtime_seconds is None
        assert parsed["plugin_name"] == "windows.malfind.Malfind"
        assert parsed["volatility_version"] == "2.27.0"
        assert parsed["runtime_seconds"] == 73.5
        assert parsed["command_executed"] == fake_command
        detections = parsed["detections"]
        assert len(detections) == 3

        # First svchost detection — MZ header signature.
        first = detections[0]
        assert first["pid"] == 7900
        assert first["process_name"] == "svchost.exe"
        assert first["protection"] == "PAGE_EXECUTE_READWRITE"
        assert first["vad_tag"] == "VadS"
        assert first["vad_start"] == "0x1f0000"
        assert first["hex_dump"].startswith("4d5a")  # MZ
        assert "dec ebp" in first["disassembly"]

        # Third detection — explorer with null disassembly.
        third = detections[2]
        assert third["pid"] == 1234
        assert third["process_name"] == "explorer.exe"
        assert third["protection"] == "PAGE_EXECUTE_WRITECOPY"
        assert third["disassembly"] is None

        # Runner called with the pinned plugin name and translated VM path.
        plugin_arg, vm_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.malfind.Malfind"
        assert vm_path_arg == "/mnt/rocba/Rocba-Memory.raw"

        # Extractions chain line written with matching hash + record count.
        chain_path = case_dir / "extractions.jsonl"
        chain_lines = [
            json.loads(line) for line in chain_path.read_text().splitlines() if line.strip()
        ]
        assert len(chain_lines) == 1
        assert chain_lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert chain_lines[0]["plugin_name"] == "windows.malfind.Malfind"
        assert chain_lines[0]["record_count"] == 3
        assert chain_lines[0]["extraction_sha256"] == ref.extraction_sha256

        # Audit log carries the success line under the bare tool_name.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        audit_lines = [
            json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()
        ]
        assert any(entry["tool_name"] == "vol_malfind" for entry in audit_lines)


# ---------------------------------------------------------------------------
# per-record validation warnings (per-row skip)
# ---------------------------------------------------------------------------


class TestVolMalfindRecordWarnings:
    def test_one_bad_record_logged_as_warning_others_preserved(self, tmp_path: Path):
        case_dir = _make_case_dir(tmp_path)
        with (
            patch("server.tools.memory.get_vol_version", return_value="2.27.0"),
            patch(
                "server.tools.memory.run_vol_plugin",
                return_value=(_bad_record_json(), "ssh ... vol ...", 1.0),
            ),
        ):
            summary = vol_malfind(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        assert summary.extraction.record_count == 2

        _, parsed = load_extraction(case_dir, VALID_EVIDENCE_ID, "windows.malfind.Malfind")
        detections = parsed["detections"]
        assert {d["pid"] for d in detections} == {100, 200}

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_malfind:record_validation_warning"
        assert lines[1]["tool_name"] == "vol_malfind"
        assert lines[1]["prev_line_hash"] == lines[0]["this_line_hash"]


# ---------------------------------------------------------------------------
# Regression: Vol3's `Start VPN` field is sometimes a hex string and
# sometimes a raw integer depending on the SIFT VM's Vol3 build. The
# SRL-2015 first run dropped 100% of malfind rows (261/261 across four
# hosts) because the int form failed the schema's `vad_start: str`
# validator. The pre-validator on MalfindRecord coerces int → hex string.
# ---------------------------------------------------------------------------


class TestMalfindRecordVadStartCoercion:
    _ROW_BASE = {
        "pid": 812,
        "process_name": "LogonUI.exe",
        "vad_tag": "VadS",
        "protection": "PAGE_EXECUTE_READWRITE",
        "hex_dump": "00 " * 64,
        "disassembly": None,
    }

    def test_int_vad_start_coerced_to_hex_string(self):
        m = MalfindRecord(vad_start=46137344, **self._ROW_BASE)
        assert m.vad_start == "0x2c00000"
        assert isinstance(m.vad_start, str)

    def test_hex_string_vad_start_passes_through_unchanged(self):
        m = MalfindRecord(vad_start="0x7ff700000000", **self._ROW_BASE)
        assert m.vad_start == "0x7ff700000000"

    def test_zero_address_coerces_to_0x0(self):
        m = MalfindRecord(vad_start=0, **self._ROW_BASE)
        # `hex(0)` produces `"0x0"` which is min_length=1-positive. Schema OK.
        assert m.vad_start == "0x0"


class TestParseMalfindIntegerStartVpn:
    """End-to-end: feed the parser a row-with-int-Start-VPN (the shape
    Vol3 actually emits in the SRL-2015 SIFT build) and confirm the
    record validates."""

    def test_int_start_vpn_round_trips_via_parser(self):
        from server.runners.sift_vm import parse_malfind_json

        raw = json.dumps(
            [
                {
                    "PID": 812,
                    "Process": "LogonUI.exe",
                    "Start VPN": 46137344,  # int — the failure shape
                    "End VPN": 46141439,
                    "Tag": "VadS",
                    "Protection": "PAGE_EXECUTE_READWRITE",
                    "CommitCharge": 1,
                    "PrivateMemory": 1,
                    "File output": "Disabled",
                    "Hexdump": "00 " * 64,
                    "Disasm": "0x2c00000:\tnop",
                    "Notes": None,
                    "__children": [],
                }
            ]
        )
        rows = parse_malfind_json(raw)
        assert len(rows) == 1
        # Parser hands int through; schema coerces it.
        assert rows[0]["vad_start"] == 46137344
        m = MalfindRecord(**rows[0])
        assert m.vad_start == "0x2c00000"
