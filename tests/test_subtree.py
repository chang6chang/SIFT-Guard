"""Unit tests for `server.tools.analytical.subtree` — pstree-only
subtree extraction with depth bound and 200-node truncation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from server.extractions import write_extraction
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    ProcessTreeRecord,
    PstreeResult,
)
from server.tools.analytical import subtree


EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _seed_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    record = EvidenceRecord(
        evidence_id=EVIDENCE_ID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(case_dir / "evidence" / "Rocba-Memory.raw"),
        sha256="e" * 64,
        size_bytes=1024,
        artifact_class=ArtifactClass.MEMORY_IMAGE,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": "case-data",
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    return case_dir


def _node(pid: int, ppid: int, name: str, children: list | None = None) -> ProcessTreeRecord:
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
        children=children or [],
    )


def _seed_pstree(case_dir: Path, processes: list[ProcessTreeRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pstree.PsTree",
        PstreeResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            volatility_version="2.27.0",
            processes=processes,
            command_executed="vol -f /tmp/x.raw -r json windows.pstree.PsTree",
            runtime_seconds=29.5,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=29.5,
    )


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestSubtreeHappyPath:
    def test_extracts_subtree_from_root(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # System (4) -> smss.exe (440) -> csrss.exe (550)
        tree = _node(4, 0, "System", [
            _node(440, 4, "smss.exe", [
                _node(550, 440, "csrss.exe"),
            ]),
        ])
        _seed_pstree(case_dir, [tree])

        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=4,
            case_dir=str(case_dir),
        )
        assert result.root_found is True
        assert result.root_pid == 4
        assert result.descendant_count == 2  # smss + csrss
        assert result.depth_traversed == 2
        # Flat node list with depth annotation.
        depths = [n["depth"] for n in result.nodes]
        assert depths == [0, 1, 2]
        assert result.truncated is False

    def test_max_depth_bounds_traversal(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # 5-deep chain: A -> B -> C -> D -> E
        leaf = _node(5, 4, "E")
        d_node = _node(4, 3, "D", [leaf])
        c_node = _node(3, 2, "C", [d_node])
        b_node = _node(2, 1, "B", [c_node])
        root = _node(1, 0, "A", [b_node])
        _seed_pstree(case_dir, [root])

        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=1,
            max_depth=2,
            case_dir=str(case_dir),
        )
        # max_depth=2: visit root (0), B (1), C (2). D not visited.
        depths = sorted(n["depth"] for n in result.nodes)
        assert depths == [0, 1, 2]
        assert result.descendant_count == 2

    def test_subtree_from_descendant_root(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        leaf = _node(550, 440, "csrss.exe")
        smss = _node(440, 4, "smss.exe", [leaf])
        system = _node(4, 0, "System", [smss])
        _seed_pstree(case_dir, [system])

        # Walk from smss instead of System.
        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=440,
            case_dir=str(case_dir),
        )
        assert result.root_pid == 440
        assert result.descendant_count == 1
        depths_to_pids = {n["depth"]: n["pid"] for n in result.nodes}
        assert depths_to_pids == {0: 440, 1: 550}


# ---------------------------------------------------------------------------
# Rejection paths
# ---------------------------------------------------------------------------


class TestSubtreeRejections:
    def test_root_pid_not_found_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_node(4, 0, "System")])
        with pytest.raises(ValueError, match="root_pid not found"):
            subtree(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pstree.PsTree",
                root_pid=9999,
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "subtree:rejected_root_not_found"

    def test_max_depth_above_cap_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_node(4, 0, "System")])
        with pytest.raises(ValueError, match="max_depth"):
            subtree(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pstree.PsTree",
                root_pid=4,
                max_depth=11,
                case_dir=str(case_dir),
            )
        audit = (case_dir / "audit" / "sift-guard-mcp.jsonl").read_text().splitlines()
        last = json.loads(audit[-1])
        assert last["tool_name"] == "subtree:rejected_limit_too_large"

    def test_extraction_not_found_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError, match="no stored extraction"):
            subtree(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pstree.PsTree",
                root_pid=4,
                case_dir=str(case_dir),
            )

    def test_evidence_not_registered_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_node(4, 0, "System")])
        bogus = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError, match="evidence_id not found"):
            subtree(
                evidence_id=bogus,
                plugin_name="windows.pstree.PsTree",
                root_pid=4,
                case_dir=str(case_dir),
            )

    def test_unknown_field_in_projection_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_node(4, 0, "System")])
        with pytest.raises(ValueError, match="unknown field"):
            subtree(
                evidence_id=EVIDENCE_ID,
                plugin_name="windows.pstree.PsTree",
                root_pid=4,
                fields=["pid", "not_a_field"],
                case_dir=str(case_dir),
            )


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


class TestSubtreeTruncation:
    def test_wide_subtree_truncates_at_200_nodes(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Root with 250 direct children (a Teams.exe-like fan-out).
        children = [_node(i + 1000, 4, f"child{i}.exe") for i in range(250)]
        root = _node(4, 0, "Teams.exe", children)
        _seed_pstree(case_dir, [root])

        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=4,
            case_dir=str(case_dir),
        )
        # Visited up to the 200-node truncation cap.
        assert len(result.nodes) == 200
        assert result.truncated is True
