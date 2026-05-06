"""Unit tests for `server.tools.memory.vol_pstree`.

Mirrors `test_vol_psscan.py`'s structure with pstree-specific
adjustments:

  - the plugin name asserted (windows.pstree.PsTree)
  - the rejection tool_name prefix (vol_pstree:rejected_*)
  - the warning tool_name (vol_pstree:record_validation_warning)
  - the fixture file (vol_pstree_sample.json) — covers three cases
    the prompt asked for: normal parent-child, deep-nested chain,
    orphan (PPID not in tree)
  - validation behavior is per-top-level-subtree (not per-row);
    pydantic's recursive validation skips the whole subtree if any
    descendant fails

The audit-chain extension test reads the actual on-disk
``case-data/CASE.yaml`` and audit log to seed a tmp_path-isolated
case dir, then verifies the new audit line links to the copied chain.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.memory import translate_to_vm_path, vol_pstree


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PSTREE_FIXTURE = Path(__file__).parent / "fixtures" / "vol_pstree_sample.json"
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
    """Same helper shape as test_vol_pslist / test_vol_psscan. Kept
    in-module for symmetry with those files; if a fourth memory tool
    lands, we extract this then."""
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


def _bad_subtree_json() -> str:
    """Two top-level subtrees: the first has a deeply-nested child with
    PID -1 (violates ge=0); the second is well-formed. Pydantic
    validates the whole subtree on construction, so the bad descendant
    causes the entire first top-level to be skipped — leaving only the
    well-formed System subtree.

    This is the test that pins the per-top-level-subtree skip behavior
    documented in vol_pstree's docstring."""
    return json.dumps(
        [
            {
                "PID": 828, "PPID": 752, "ImageFileName": "services.exe",
                "Offset(V)": 0, "Threads": 5, "Handles": None,
                "SessionId": 0, "Wow64": False, "Audit": None, "Cmd": None,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "Path": None,
                "__children": [
                    {
                        "PID": -1, "PPID": 828, "ImageFileName": "Bad",
                        "Offset(V)": 0, "Threads": 1, "Handles": None,
                        "SessionId": 0, "Wow64": False, "Audit": None,
                        "Cmd": None, "Path": None,
                        "CreateTime": "2024-01-01T00:00:00+00:00",
                        "ExitTime": None,
                        "__children": [],
                    },
                ],
            },
            {
                "PID": 4, "PPID": 0, "ImageFileName": "System",
                "Offset(V)": 0, "Threads": 197, "Handles": None,
                "SessionId": None, "Wow64": False, "Audit": None,
                "Cmd": None, "Path": None,
                "CreateTime": "2024-01-01T00:00:00+00:00",
                "ExitTime": None, "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolPstreeResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_pstree(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        assert bogus_id not in str(exc_info.value)

    def test_artifact_class_unknown_rejected_with_sanitized_message(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_pstree(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a memory image"
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — same architectural rule as the other two
# memory tools. Asserts the prefix is `vol_pstree:rejected_*`, not
# `vol_pslist`/`vol_psscan` — the extracted helper is parameterized
# on tool_name and a copy-paste bug would route through the wrong one.
# ---------------------------------------------------------------------------


_GENESIS_PREV_HASH = "0" * 64


class TestVolPstreeRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_pstree(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_pstree:rejected_evidence_not_found"
        assert entry["evidence_id"] == bogus_id
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64

    def test_wrong_artifact_class_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(
            tmp_path, artifact_class=ArtifactClass.UNKNOWN
        )
        with pytest.raises(ValueError):
            vol_pstree(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"] == "vol_pstree:rejected_wrong_artifact_class"
        )

    def test_path_translation_failed_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, absolute_path="/tmp/Foo.raw")
        with pytest.raises(ValueError) as exc_info:
            vol_pstree(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert "/tmp/Foo.raw" not in str(exc_info.value)
        assert "expected host prefix" in str(exc_info.value)
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"]
            == "vol_pstree:rejected_path_translation_failed"
        )


# ---------------------------------------------------------------------------
# happy path — recursive structure preserved, three covered cases
# (normal parent-child, deep-nested chain, orphan with PPID not in tree)
# ---------------------------------------------------------------------------


class TestVolPstreeHappyPath:
    def test_returns_pstree_result_with_recursive_structure(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PSTREE_FIXTURE.read_text(encoding="utf-8")
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.pstree.PsTree"
        )

        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, fake_command, 29.5),
        ) as mock_run:
            summary = vol_pstree(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Tier-1 contract: PstreeSummary returned, full tree on disk.
        ref = summary.extraction
        assert ref.plugin_name == "windows.pstree.PsTree"
        assert ref.evidence_id == VALID_EVIDENCE_ID
        assert ref.runtime_seconds == 29.5
        assert ref.cached is False
        assert ref.record_count == 3  # three top-level subtrees

        # Summary-level shape signal.
        assert summary.top_level_root_count == 3
        # System->smss.exe is depth 1; services.exe->svchost->consent
        # is depth 2; chrome.exe (orphan) is depth 0. Max is 2.
        assert summary.max_depth == 2
        assert summary.depth_distribution[0] == 3  # three roots
        # Orphans: services.exe (ppid 752 not in tree) AND chrome.exe
        # (ppid 99999 not in tree). System's ppid=0 is excluded by
        # definition (PID 4 / System is the canonical kernel root).
        # Two orphans total — the fixture's services.exe-rooted
        # subtree was a real Windows lineage in the live image, but
        # the parent (likely wininit.exe / SMSS) is not in this
        # three-record fixture.
        assert summary.orphan_count == 2

        # Field-level evidence-delimiter discipline. PstreeSummary
        # surfaces only counts and depth integers — no
        # evidence-derived strings escape into the summary, so the
        # list is empty. Untrusted strings (image_file_name, audit,
        # cmd, path) are reached only via the tier-2 `subtree` tool.
        assert summary.untrusted_fields == []

        # Stored extraction has the full recursive tree with the same
        # provenance metadata we never expose in the summary.
        _, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "windows.pstree.PsTree"
        )
        assert parsed["plugin_name"] == "windows.pstree.PsTree"
        assert parsed["volatility_version"] == "2.27.0"
        assert parsed["runtime_seconds"] == 29.5
        assert parsed["command_executed"] == fake_command

        records = parsed["processes"]
        assert len(records) == 3

        # (a) Normal parent-child — System has one child (smss.exe).
        system = next(p for p in records if p["image_file_name"] == "System")
        assert system["pid"] == 4 and system["ppid"] == 0
        assert len(system["children"]) == 1
        assert system["children"][0]["image_file_name"] == "smss.exe"
        assert system["children"][0]["ppid"] == 4
        # Pstree-specific: smss.exe has audit/cmd/path populated; System
        # itself is the kernel and has them all null.
        assert system["audit"] is None
        assert system["children"][0]["audit"] is not None
        assert system["children"][0]["cmd"] is not None
        assert system["children"][0]["path"] is not None

        # (b) Deep-nested chain — services.exe → svchost.exe → consent.exe
        services = next(
            p for p in records if p["image_file_name"] == "services.exe"
        )
        assert len(services["children"]) == 1
        svchost = services["children"][0]
        assert svchost["image_file_name"] == "svchost.exe"
        assert svchost["cmd"] == "C:\\Windows\\system32\\svchost.exe -k netsvcs"
        assert len(svchost["children"]) == 1
        consent = svchost["children"][0]
        assert consent["image_file_name"] == "consent.exe"
        assert consent["pid"] == 9876
        assert consent["children"] == []

        # (c) Orphan — chrome.exe has PPID=99999, which is not any
        # process's PID anywhere in the tree.
        chrome = next(
            p for p in records if p["image_file_name"] == "chrome.exe"
        )
        assert chrome["ppid"] == 99999, (
            "orphaned chrome.exe must keep its raw PPID — the "
            "validator will need it to detect that the parent is gone"
        )
        assert chrome["children"] == []

        # Runner was called with the pinned plugin name and translated
        # VM path (no host path leaks).
        plugin_arg, vm_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.pstree.PsTree"
        assert vm_path_arg == "/mnt/rocba/Rocba-Memory.raw"


# ---------------------------------------------------------------------------
# per-subtree validation warnings (per-top-level-subtree skip)
# ---------------------------------------------------------------------------


class TestVolPstreeRecordWarnings:
    def test_bad_descendant_skips_whole_subtree_others_preserved(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(_bad_subtree_json(), "ssh ... vol ...", 30.0),
        ):
            summary = vol_pstree(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # First top-level (services.exe with bad descendant) was
        # skipped; second (System, well-formed) survived.
        assert summary.extraction.record_count == 1
        _, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "windows.pstree.PsTree"
        )
        assert len(parsed["processes"]) == 1
        assert parsed["processes"][0]["image_file_name"] == "System"

        # Audit chain: 1 warning + 1 main result line, in that order.
        # Warning's tool_name marks it as a pstree warning so a
        # chain reader can grep distinctly from pslist/psscan warnings.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_pstree:record_validation_warning"
        assert lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert lines[1]["tool_name"] == "vol_pstree"
        # Chain link.
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

        fixture_stdout = PSTREE_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 29.5),
        ):
            vol_pstree(rocba_evidence_id, case_dir=str(case_dir))

        new_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        assert len(new_lines) == seeded_count + 1
        new_entry = json.loads(new_lines[-1])
        assert new_entry["tool_name"] == "vol_pstree"
        assert new_entry["evidence_id"] == rocba_evidence_id
        assert new_entry["prev_line_hash"] == expected_prev, (
            "vol_pstree's audit line failed to link to the prior "
            "chain — chain is broken"
        )
        assert new_entry["line_number"] == seeded_count + 1

        assert ON_DISK_AUDIT_LOG.read_bytes() == on_disk_audit_before, (
            "on-disk audit log was modified by the test — isolation "
            "is broken"
        )
