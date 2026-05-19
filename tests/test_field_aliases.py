"""Tests for the per-plugin field-name alias map in
``server.tools.analytical``.

Context: the 2026-05-13 SRL-2015 run burned tokens on a tight loop
of ``query_records:rejected_unknown_field`` rejections. The analysts
were asking for malfind fields by their natural names (``start``,
``tag``, ``disasm``, ``hexdump``) while the server's allow-list and
the on-disk extraction used the canonical column names (``vad_start``,
``vad_tag``, ``disassembly``, ``hex_dump``). The side-channel
rejection log (commit a036662) surfaced the offenders; this test
pins the resolution.

Aliases are intentionally one-way (alias → canonical). Asking for a
truly-unknown name (``end``, ``commit_charge``, etc.) is still
rejected — the schema's job is to surface genuine analyst confusion,
not silently absorb every guess.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from server.audit import append_audit_entry
from server.extractions import write_extraction
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    FieldFilter,
    MalfindRecord,
    MalfindResult,
    ProcessTreeRecord,
    PstreeResult,
)
from server.tools.analytical import (
    _canonicalize_field,
    _canonicalize_filters,
    group_by,
    query_records,
    subtree,
)


VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_with_malfind(tmp_path: Path) -> Path:
    """Build a case dir with a valid malfind extraction on disk."""
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

    # Seed an audit-chain line so the load_or_reject path stays clean.
    class _Stub:
        def model_dump_json(self):
            return json.dumps({"ok": True})

    append_audit_entry(
        case_dir=case_dir,
        tool_name="vol_malfind",
        evidence_id=VALID_EVIDENCE_ID,
        input_args={"evidence_id": VALID_EVIDENCE_ID},
        output=_Stub(),
    )

    # Two malfind detections with the real Volatility-3 field names.
    result = MalfindResult(
        evidence_id=VALID_EVIDENCE_ID,
        plugin_name="windows.malfind.Malfind",
        volatility_version="2.27.0",
        detections=[
            MalfindRecord(
                pid=6404,
                process_name="svchost.exe",
                vad_start="0x7ff700000000",
                vad_tag="VadS",
                protection="PAGE_EXECUTE_READWRITE",
                hex_dump="4d 5a 90 00",
                disassembly="push rbp",
            ),
            MalfindRecord(
                pid=1234,
                process_name="explorer.exe",
                vad_start="0x7ff8aabbccdd",
                vad_tag="Vad ",
                protection="PAGE_READWRITE",
                hex_dump="00 00 00",
                disassembly="ret",
            ),
        ],
        command_executed="vol -f /tmp/x.raw -r json windows.malfind.Malfind",
        runtime_seconds=12.3,
        invoked_at=NOW_UTC,
    )
    write_extraction(
        case_dir,
        VALID_EVIDENCE_ID,
        "windows.malfind.Malfind",
        result,
        runtime_seconds=12.3,
    )
    return case_dir


class TestCanonicalize:
    def test_known_alias_resolves(self):
        assert _canonicalize_field("windows.malfind.Malfind", "start") == "vad_start"
        assert _canonicalize_field("windows.malfind.Malfind", "tag") == "vad_tag"
        assert _canonicalize_field("windows.malfind.Malfind", "disasm") == "disassembly"
        assert _canonicalize_field("windows.malfind.Malfind", "hexdump") == "hex_dump"
        assert (
            _canonicalize_field("windows.pslist.PsList", "process_name")
            == "image_file_name"
        )

    def test_canonical_name_is_idempotent(self):
        assert (
            _canonicalize_field("windows.malfind.Malfind", "vad_start") == "vad_start"
        )

    def test_unknown_alias_passes_through(self):
        # Truly unknown — still gets passed to _validate_fields and
        # rejected there. The map only resolves what we know.
        assert _canonicalize_field("windows.malfind.Malfind", "end") == "end"
        assert _canonicalize_field("windows.malfind.Malfind", "commit_charge") == "commit_charge"

    def test_filter_canonicalization_returns_new_objects(self):
        filters = [
            FieldFilter(field="tag", op="eq", value="VadS"),
            FieldFilter(field="pid", op="eq", value=6404),
        ]
        out = _canonicalize_filters("windows.malfind.Malfind", filters)
        # tag → vad_tag; pid was already canonical and is returned as-is.
        assert out[0].field == "vad_tag"
        assert out[1].field == "pid"
        assert out[1] is filters[1]  # same object — no needless copy


class TestQueryRecordsAliasing:
    def test_malfind_alias_projection(self, tmp_path: Path):
        case_dir = _make_case_with_malfind(tmp_path)
        result = query_records(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.malfind.Malfind",
            fields=["pid", "tag", "disasm", "hexdump"],
            case_dir=str(case_dir),
        )
        assert result.returned_count == 2
        first = result.records[0]
        # Projected keys use the CANONICAL names — the analyst sees
        # what's actually on disk, and downstream tools can pattern-
        # match against the published Volatility 3 column names.
        assert "vad_tag" in first
        assert "disassembly" in first
        assert "hex_dump" in first
        # The analyst's alias names should NOT appear in the result.
        assert "tag" not in first
        assert "disasm" not in first
        assert "hexdump" not in first

    def test_malfind_alias_filter(self, tmp_path: Path):
        case_dir = _make_case_with_malfind(tmp_path)
        result = query_records(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.malfind.Malfind",
            filters=[FieldFilter(field="tag", op="eq", value="VadS")],
            fields=["pid", "vad_tag"],
            case_dir=str(case_dir),
        )
        # Only one detection had tag=VadS; the alias resolves to
        # vad_tag and the filter matches.
        assert result.matched_count == 1
        assert result.records[0]["pid"] == 6404

    def test_truly_unknown_projection_field_is_dropped_not_rejected(
        self, tmp_path: Path
    ):
        # Updated behavior (2026-05-19): unknown projection fields are
        # soft-dropped rather than hard-rejected. The call succeeds
        # with the unknown name absent from the records; a telemetry
        # audit suffix marks the drop. Filter fields still hard-reject
        # — covered by the existing
        # ``test_unknown_filter_field_rejects`` test.
        case_dir = _make_case_with_malfind(tmp_path)
        result = query_records(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.malfind.Malfind",
            fields=["pid", "commit_charge"],
            case_dir=str(case_dir),
        )
        # commit_charge is gone from the projection; pid survives.
        for record in result.records:
            assert "commit_charge" not in record
            assert "pid" in record

    def test_audit_input_args_preserve_original_alias(self, tmp_path: Path):
        """Operators reading the audit chain see what the analyst
        actually submitted — the alias resolution is internal to the
        execution path, not retroactively rewritten in the audit
        trail. Useful for tracking which aliases are hot and for
        debugging analyst behavior."""
        case_dir = _make_case_with_malfind(tmp_path)
        query_records(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.malfind.Malfind",
            fields=["pid", "disasm", "hexdump"],
            case_dir=str(case_dir),
        )
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        last_three = audit_path.read_text(encoding="utf-8").strip().splitlines()
        # The last audit line is query_records success; its
        # input_args are not stored (only hash), but the tool_name
        # is greppable as success (no :rejected_ suffix).
        last = json.loads(last_three[-1])
        assert last["tool_name"] == "query_records"
        # Critically: no rejection was emitted for the alias path.
        assert ":rejected_" not in last["tool_name"]


class TestGroupByAliasing:
    def test_group_by_with_alias_axis(self, tmp_path: Path):
        case_dir = _make_case_with_malfind(tmp_path)
        result = group_by(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.malfind.Malfind",
            field="tag",  # alias → vad_tag
            case_dir=str(case_dir),
        )
        # field echoed in the result reflects the canonical column.
        assert result.field == "vad_tag"
        assert result.total_records == 2
        # Two distinct vad_tag values (VadS, "Vad ").
        assert result.distinct_values == 2


class TestSubtreeAliasing:
    def test_subtree_canonical_projection_unaffected(self, tmp_path: Path):
        # Subtree is pstree-only; the alias for pstree is
        # process_name → image_file_name. Build a minimal pstree
        # extraction to exercise the projection path.
        case_dir = _make_case_with_malfind(tmp_path)

        def _node(pid: int, ppid: int, name: str, children) -> ProcessTreeRecord:
            return ProcessTreeRecord(
                pid=pid,
                ppid=ppid,
                image_file_name=name,
                offset_v=0,
                threads=1,
                handles=None,
                session_id=None,
                wow64=False,
                create_time=NOW_UTC,
                exit_time=None,
                audit=None,
                cmd=None,
                path=None,
                children=children,
            )

        pstree = PstreeResult(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            volatility_version="2.27.0",
            processes=[
                _node(4, 0, "System", [_node(600, 4, "smss.exe", [])])
            ],
            command_executed="vol -f /tmp/x.raw -r json windows.pstree.PsTree",
            runtime_seconds=18.2,
            invoked_at=NOW_UTC,
        )
        write_extraction(
            case_dir,
            VALID_EVIDENCE_ID,
            "windows.pstree.PsTree",
            pstree,
            runtime_seconds=18.2,
        )
        result = subtree(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=4,
            max_depth=2,
            fields=["pid", "process_name"],  # alias → image_file_name
            case_dir=str(case_dir),
        )
        assert len(result.nodes) == 2
        # Projected keys are canonical.
        assert "image_file_name" in result.nodes[0]
        assert "process_name" not in result.nodes[0]
