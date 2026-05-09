"""CLI subcommand routing tests for `orchestrator.main`.

Mocks the underlying `run_loop` / `run_loop_multi_host` /
`register_evidence` calls so the test exercises the argument
parsing + dispatch logic only.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from orchestrator import main as om
from orchestrator.loop import LoopOutcome


# Magic-byte signatures used to seed scan candidates.
_LIME_HEADER = b"\x4c\x69\x4d\x45" + b"\x00" * 12
_E01_HEADER = b"\x45\x56\x46\x09\x0d\x0a\xff\x00" + b"\x00" * 8


def _empty_outcome() -> LoopOutcome:
    return LoopOutcome(
        iterations=[],
        termination_reason="R_a_zero_unresolved",
        cumulative_tokens_uncached=0,
    )


class TestRunSubcommand:
    def test_run_invokes_run_loop_with_right_args(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: case-data\n")

        captured: dict = {}

        def fake_run_loop(**kwargs):
            captured.update(kwargs)
            return _empty_outcome()

        with patch.object(om, "run_loop", fake_run_loop):
            rc = om.main(
                [
                    "run",
                    "--case-dir",
                    str(case_dir),
                    "--evidence-id",
                    "550e8400-e29b-41d4-a716-446655440000",
                    "--max-iterations",
                    "3",
                ]
            )
        assert rc == 0
        assert captured["evidence_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert captured["max_iterations"] == 3
        assert "token_budget" not in captured  # default → no override

    def test_run_passes_through_token_budget_override(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: case-data\n")
        captured: dict = {}

        def fake_run_loop(**kwargs):
            captured.update(kwargs)
            return _empty_outcome()

        with patch.object(om, "run_loop", fake_run_loop):
            rc = om.main(
                [
                    "run",
                    "--case-dir",
                    str(case_dir),
                    "--evidence-id",
                    "550e8400-e29b-41d4-a716-446655440000",
                    "--token-budget",
                    "123456",
                ]
            )
        assert rc == 0
        assert captured["token_budget"] == 123456

    def test_run_missing_case_yaml_returns_2(self, tmp_path: Path):
        # case_dir without CASE.yaml — the command bails early.
        empty = tmp_path / "case-data"
        empty.mkdir()
        rc = om.main(
            [
                "run",
                "--case-dir",
                str(empty),
                "--evidence-id",
                "550e8400-e29b-41d4-a716-446655440000",
            ]
        )
        assert rc == 2


class TestRunCaseSubcommand:
    def _seed_evidence(self, evidence_dir: Path) -> None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "nfury-memory.raw").write_bytes(_LIME_HEADER)
        (evidence_dir / "nfury-disk.E01").write_bytes(_E01_HEADER)
        (evidence_dir / "controller-memory.raw").write_bytes(_LIME_HEADER)

    def test_scan_only_skips_loop_dispatch(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        evidence_dir = case_dir / "evidence"
        self._seed_evidence(evidence_dir)

        # Mock register_evidence so we don't chmod real files.
        # Each call returns a fake EvidenceRecord-shaped object with
        # the fields the manifest builder reads.
        from server.schemas import ArtifactClass, EvidenceRecord
        from datetime import datetime, timezone
        from uuid import uuid4

        def fake_register(filepath, case_dir):
            return EvidenceRecord(
                evidence_id=str(uuid4()),
                original_filename=Path(filepath).name,
                absolute_path=filepath,
                sha256="a" * 64,
                size_bytes=1024,
                artifact_class=ArtifactClass.MEMORY_IMAGE,
                registered_at=datetime.now(tz=timezone.utc),
                file_mode_after_registration="0o444",
            )

        with (
            patch.object(om, "register_evidence", fake_register),
            patch.object(om, "run_loop_multi_host") as mock_loop,
        ):
            rc = om.main(
                [
                    "run-case",
                    "--case-dir",
                    str(case_dir),
                    "--evidence-dir",
                    str(evidence_dir),
                    "--scan-only",
                ]
            )

        assert rc == 0
        mock_loop.assert_not_called()
        # Manifest written.
        from orchestrator.manifest import read_manifest

        m = read_manifest(case_dir)
        assert len(m.hosts) == 2  # nfury + controller
        assert {h.host_id for h in m.hosts} == {"nfury", "controller"}

    def test_run_case_with_no_evidence_returns_3(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        # No evidence files — only an unrelated readme.
        (evidence_dir / "readme.txt").write_text("no evidence here")
        rc = om.main(
            [
                "run-case",
                "--case-dir",
                str(case_dir),
                "--evidence-dir",
                str(evidence_dir),
                "--scan-only",
            ]
        )
        assert rc == 3

    def test_run_case_default_token_budget_scales_with_host_count(self, tmp_path: Path):
        case_dir = tmp_path / "case-data"
        evidence_dir = case_dir / "evidence"
        self._seed_evidence(evidence_dir)
        from server.schemas import ArtifactClass, EvidenceRecord
        from datetime import datetime, timezone
        from uuid import uuid4

        captured: dict = {}

        def fake_register(filepath, case_dir):
            return EvidenceRecord(
                evidence_id=str(uuid4()),
                original_filename=Path(filepath).name,
                absolute_path=filepath,
                sha256="a" * 64,
                size_bytes=1024,
                artifact_class=ArtifactClass.MEMORY_IMAGE,
                registered_at=datetime.now(tz=timezone.utc),
                file_mode_after_registration="0o444",
            )

        def fake_loop(**kwargs):
            captured.update(kwargs)
            return _empty_outcome()

        with (
            patch.object(om, "register_evidence", fake_register),
            patch.object(om, "run_loop_multi_host", fake_loop),
        ):
            om.main(
                [
                    "run-case",
                    "--case-dir",
                    str(case_dir),
                    "--evidence-dir",
                    str(evidence_dir),
                ]
            )
        # 2 hosts → 500K + 250K * 2 = 1M.
        assert captured["token_budget"] == 1_000_000


class TestArgparseStructure:
    def test_subcommand_required(self, tmp_path: Path):
        with pytest.raises(SystemExit):
            om.main([])

    def test_unknown_subcommand_rejected(self):
        with pytest.raises(SystemExit):
            om.main(["bogus"])
