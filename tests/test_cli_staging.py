"""Tests for ``sift-guard analyze`` evidence staging.

Two staging modes:

  - ``--no-copy`` (default): originals are chmod 444'd in place,
    symlinks land under ``<case>/evidence/<host>/``, manifest's
    file_path is the source path.
  - ``--copy``: originals are deep-copied into ``<case>/evidence/<host>/``,
    originals stay untouched (no chmod).

The tests synthesize tiny evidence files under a tmp dir, run the
two helper functions directly (no subprocess, no Claude Code), and
inspect the resulting case-dir tree + CASE.yaml + manifest.
"""

from __future__ import annotations

import secrets
import stat
from pathlib import Path

from sift_guard.cli import (
    _build_manifest_from_case_dir,
    _build_manifest_from_originals,
    _stage_evidence,
    _stage_evidence_symlinks,
)


def _make_source_tree(source: Path) -> list[Path]:
    """Two-host source tree mirroring the SRL-2015 layout: a memory
    image under nfury/, a disk image under controller/. Just enough
    bytes for the inventory scanner's magic-byte probe to classify
    them (16 bytes for the .001 split-image type heuristic; the
    .E01 detector wants the EVF header)."""
    source.mkdir(parents=True, exist_ok=True)

    nfury = source / "nfury"
    nfury.mkdir()
    mem = nfury / "nfury-memory.001"
    mem.write_bytes(b"\x00" * 16)

    controller = source / "controller"
    controller.mkdir()
    # E01 magic header so the inventory scanner classifies as disk.
    disk = controller / "controller.E01"
    disk.write_bytes(b"\x45\x56\x46\x09\x0d\x0a\xff\x00" + secrets.token_bytes(64))

    return [mem, disk]


class TestSymlinkStaging:
    def test_symlinks_created_under_case_dir(self, tmp_path: Path):
        source = tmp_path / "source"
        files = _make_source_tree(source)
        case_dir = tmp_path / "case-out"

        count = _stage_evidence_symlinks(source, case_dir)
        assert count == len(files)

        # Each source file has a matching symlink in case_dir/evidence/<host>/.
        for original in files:
            host_id = original.parent.name
            link = case_dir / "evidence" / host_id / original.name
            assert link.is_symlink(), f"{link} should be a symlink"
            # readlink target equals the resolved source.
            assert Path(link).resolve() == original.resolve()

    def test_re_running_is_idempotent(self, tmp_path: Path):
        source = tmp_path / "source"
        _make_source_tree(source)
        case_dir = tmp_path / "case-out"

        first = _stage_evidence_symlinks(source, case_dir)
        second = _stage_evidence_symlinks(source, case_dir)
        assert first == second
        # All symlinks still point at the source (re-creating them
        # should be a no-op when they already exist and are correct).
        for link in (case_dir / "evidence").rglob("*"):
            if link.is_symlink():
                assert link.exists()

    def test_existing_regular_file_is_not_clobbered(self, tmp_path: Path):
        source = tmp_path / "source"
        _make_source_tree(source)
        case_dir = tmp_path / "case-out"
        # Manually place a regular file where a symlink would go.
        host_dir = case_dir / "evidence" / "nfury"
        host_dir.mkdir(parents=True)
        manual = host_dir / "nfury-memory.001"
        manual.write_bytes(b"do-not-clobber")

        _stage_evidence_symlinks(source, case_dir)

        assert manual.exists() and not manual.is_symlink()
        assert manual.read_bytes() == b"do-not-clobber"


class TestSymlinkManifestBuild:
    def test_manifest_file_path_is_source_path(self, tmp_path: Path):
        source = tmp_path / "source"
        files = _make_source_tree(source)
        case_dir = tmp_path / "case-out"
        # Symlinks first so the case dir has the navigation tree.
        _stage_evidence_symlinks(source, case_dir)

        manifest = _build_manifest_from_originals(source, case_dir)

        assert len(manifest.hosts) == 2
        # Manifest's file_path entries point at the SOURCE paths, not
        # at the symlinks under case_dir.
        all_paths = [
            Path(ef.file_path).resolve()
            for host in manifest.hosts
            for ef in host.evidence_files
        ]
        for source_file in files:
            assert source_file.resolve() in all_paths

    def test_source_files_are_chmod_444_after_registration(self, tmp_path: Path):
        source = tmp_path / "source"
        files = _make_source_tree(source)
        case_dir = tmp_path / "case-out"
        _stage_evidence_symlinks(source, case_dir)

        _build_manifest_from_originals(source, case_dir)

        for source_file in files:
            mode = stat.S_IMODE(source_file.stat().st_mode)
            assert mode == 0o444, f"{source_file} expected 0o444, got {oct(mode)}"


class TestCopyStagingStillWorks:
    """``--copy`` (opt-in) preserves the legacy behavior: originals
    are unchanged, copies live under case_dir/evidence/."""

    def test_copy_leaves_originals_untouched(self, tmp_path: Path):
        source = tmp_path / "source"
        files = _make_source_tree(source)
        case_dir = tmp_path / "case-out"
        original_modes = {f: stat.S_IMODE(f.stat().st_mode) for f in files}

        _stage_evidence(source, case_dir)

        for f, mode in original_modes.items():
            assert stat.S_IMODE(f.stat().st_mode) == mode, (
                f"{f} mode changed during --copy stage"
            )
        # Copies exist at case_dir/evidence/<host>/<name>.
        for f in files:
            copied = case_dir / "evidence" / f.parent.name / f.name
            assert copied.is_file() and not copied.is_symlink()

    def test_copy_then_build_manifest_writes_case_yaml(self, tmp_path: Path):
        source = tmp_path / "source"
        _make_source_tree(source)
        case_dir = tmp_path / "case-out"

        _stage_evidence(source, case_dir)
        manifest = _build_manifest_from_case_dir(case_dir)

        assert len(manifest.hosts) == 2
        case_yaml = case_dir / "CASE.yaml"
        assert case_yaml.exists()
