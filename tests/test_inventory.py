"""Unit tests for `orchestrator.inventory`."""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.inventory import (
    _extract_host_token,
    _refine_evidence_type_by_magic,
    format_inventory_table,
    scan_evidence_directory,
)
from orchestrator.manifest import EvidenceFile, HostEvidence


# Magic-byte signatures we care about in tests.
_LIME_HEADER = b"\x4c\x69\x4d\x45" + b"\x00" * 12
_E01_HEADER = b"\x45\x56\x46\x09\x0d\x0a\xff\x00" + b"\x00" * 8
_VHDX_HEADER = b"\x76\x68\x64\x78\x66\x69\x6c\x65" + b"\x00" * 8


class TestExtractHostToken:
    def test_strips_platform_role_and_ip(self):
        assert _extract_host_token("win7-64-nfury-10.3.58.6") == "nfury"

    def test_strips_role_only(self):
        assert _extract_host_token("nfury-memory") == "nfury"
        assert _extract_host_token("nfury-disk") == "nfury"
        assert _extract_host_token("controller-memory") == "controller"

    def test_pure_hostname_passes_through(self):
        # No platform / role / IP to strip — token is the full stem.
        assert _extract_host_token("IT-W10-PC1") == "IT-W10-PC1"

    def test_returns_none_for_pure_role(self):
        # Stripping leaves nothing — caller falls back to filename stem.
        assert _extract_host_token("memory") is None
        assert _extract_host_token("disk-image") is None


class TestRefineByMagic:
    def test_lime_header_promotes_unknown_to_memory(self, tmp_path: Path):
        p = tmp_path / "x.aff4"
        p.write_bytes(_LIME_HEADER)
        assert _refine_evidence_type_by_magic(p, "unknown") == "memory"

    def test_e01_header_promotes_unknown_to_disk(self, tmp_path: Path):
        p = tmp_path / "x.aff4"
        p.write_bytes(_E01_HEADER)
        assert _refine_evidence_type_by_magic(p, "unknown") == "disk"

    def test_vhdx_header_keeps_disk(self, tmp_path: Path):
        p = tmp_path / "x.vhdx"
        p.write_bytes(_VHDX_HEADER)
        assert _refine_evidence_type_by_magic(p, "disk") == "disk"

    def test_no_magic_match_keeps_extension_guess(self, tmp_path: Path):
        p = tmp_path / "x.raw"
        p.write_bytes(b"\x00" * 16)
        assert _refine_evidence_type_by_magic(p, "memory") == "memory"


class TestScanEvidenceDirectory:
    def _seed(self, evidence_dir: Path) -> None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        # nfury host: memory raw + disk E01 (E01 magic for the disk
        # so the type detection survives a renamed extension).
        (evidence_dir / "win7-64-nfury-10.3.58.6.raw").write_bytes(
            b"\x00" * 16
        )
        (evidence_dir / "nfury-disk.E01").write_bytes(_E01_HEADER)
        # controller host: memory raw with LiME magic.
        (evidence_dir / "controller-memory.raw").write_bytes(_LIME_HEADER)
        # An unknown-extension file that should be skipped.
        (evidence_dir / "readme.txt").write_text("ignore me")

    def test_groups_files_by_host_token(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = scan_evidence_directory(evidence_dir)
        host_ids = [host_id for host_id, _, _ in result]
        # Sorted alphabetically by host_id.
        assert host_ids == ["controller", "nfury"]

    def test_per_host_evidence_types_match_magic_detection(
        self, tmp_path: Path
    ):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = dict(
            (host_id, [(p.name, t) for p, t, _ in files])
            for host_id, _, files in scan_evidence_directory(evidence_dir)
        )
        assert ("controller-memory.raw", "memory") in result["controller"]
        nfury_types = dict(result["nfury"])
        assert nfury_types["win7-64-nfury-10.3.58.6.raw"] == "memory"
        assert nfury_types["nfury-disk.E01"] == "disk"

    def test_unknown_extensions_skipped(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        all_filenames = [
            p.name
            for _, _, files in scan_evidence_directory(evidence_dir)
            for p, _, _ in files
        ]
        assert "readme.txt" not in all_filenames

    def test_singleton_host_when_no_token_extractable(
        self, tmp_path: Path
    ):
        # `disk-image.E01` strips to nothing → singleton bucket
        # named after the stem.
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "disk-image.E01").write_bytes(_E01_HEADER)
        result = scan_evidence_directory(evidence_dir)
        assert len(result) == 1
        host_id, host_label, _ = result[0]
        assert host_id == "disk-image"
        assert host_label == "disk-image"

    def test_missing_directory_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            scan_evidence_directory(tmp_path / "no-such-dir")


class TestSplitImageDetection:
    """`.001` (FTK Imager split-image) extension handling."""

    def test_memory_in_filename_promotes_001_to_memory(self, tmp_path: Path):
        from orchestrator.inventory import _detect_evidence_type_by_extension
        p = tmp_path / "nfury-memory.001"
        p.write_bytes(b"\x00" * 16)
        assert _detect_evidence_type_by_extension(p) == "memory"

    def test_no_memory_in_filename_keeps_001_as_unknown(
        self, tmp_path: Path
    ):
        # SRL-2015 disk split images use `name.E01`; bare `.001`
        # without a "memory" hint is conservatively unknown.
        from orchestrator.inventory import _detect_evidence_type_by_extension
        p = tmp_path / "nfury.001"
        p.write_bytes(b"\x00" * 16)
        assert _detect_evidence_type_by_extension(p) == "unknown"

    def test_memory_substring_match_is_case_insensitive(self, tmp_path: Path):
        from orchestrator.inventory import _detect_evidence_type_by_extension
        p = tmp_path / "Nfury-MEMORY.001"
        p.write_bytes(b"\x00" * 16)
        assert _detect_evidence_type_by_extension(p) == "memory"


class TestNonEvidenceFiltering:
    """Skip rules for known non-evidence files + directories."""

    def test_baseline_subdir_is_skipped(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        baseline = evidence_dir / "baseline"
        baseline.mkdir(parents=True)
        # A genuinely-shaped disk image, but under baseline/ → skip.
        from tests.test_inventory import _E01_HEADER  # noqa: F401
        (baseline / "win7-baseline.img").write_bytes(b"\x00" * 16)
        # And a real evidence file at the top-level so the result
        # set is non-empty.
        (evidence_dir / "nfury-memory.raw").write_bytes(b"\x00" * 16)
        result = scan_evidence_directory(evidence_dir)
        all_paths = [p.name for _, _, files in result for p, _, _ in files]
        assert "win7-baseline.img" not in all_paths
        assert "nfury-memory.raw" in all_paths

    def test_precooked_subdir_is_skipped(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        precooked = evidence_dir / "precooked"
        precooked.mkdir(parents=True)
        # Even an arguably-eligible extension under precooked/ is
        # skipped — the directory contract overrides the extension
        # guess.
        (precooked / "stale.raw").write_bytes(b"\x00" * 16)
        (evidence_dir / "real-memory.raw").write_bytes(b"\x00" * 16)
        result = scan_evidence_directory(evidence_dir)
        all_paths = [p.name for _, _, files in result for p, _, _ in files]
        assert "stale.raw" not in all_paths
        assert "real-memory.raw" in all_paths

    def test_mans_extension_is_skipped(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "session.mans").write_bytes(b"\x00" * 16)
        (evidence_dir / "nfury-memory.raw").write_bytes(b"\x00" * 16)
        result = scan_evidence_directory(evidence_dir)
        all_paths = [p.name for _, _, files in result for p, _, _ in files]
        assert "session.mans" not in all_paths
        assert "nfury-memory.raw" in all_paths


class TestSrlDatasetLayout:
    """End-to-end fixture matching the SRL-2015 / SANS Standard
    Forensic Case directory layout: 4 hosts × (memory .001 + disk
    .E01) plus precooked/ and baseline/ noise that must NOT appear
    in the manifest output."""

    _HOSTS = ("nfury", "nromanoff", "controller", "tdungan")

    def _seed(self, evidence_dir: Path) -> None:
        from tests.test_inventory import _E01_HEADER

        evidence_dir.mkdir(parents=True, exist_ok=True)
        for host in self._HOSTS:
            host_dir = evidence_dir / host
            host_dir.mkdir()
            # Memory split-image first segment.
            (host_dir / f"{host}-memory.001").write_bytes(b"\x00" * 16)
            # Disk image (E01 header so magic-byte detection
            # confirms the type).
            (host_dir / f"{host}.E01").write_bytes(_E01_HEADER)
            # Mandiant Memoryze session — must be skipped.
            (host_dir / f"{host}.mans").write_bytes(b"\x00" * 16)

        # precooked/ — common DFIR convention for parsed output.
        # All extensions are non-evidence; the directory rule is
        # what catches them in case any one extension drifts back
        # into the scan set.
        precooked = evidence_dir / "precooked"
        precooked.mkdir()
        for name in (
            "timeline.csv",
            "plaso.dump",
            "notes.txt",
            "findings.xlsx",
            "timeline.body",
            "iocs.ioc",
        ):
            (precooked / name).write_bytes(b"\x00" * 16)

        # baseline/ — pristine reference images that must not be
        # registered as evidence.
        baseline = evidence_dir / "baseline"
        baseline.mkdir()
        (baseline / "win7-baseline.img").write_bytes(b"\x00" * 16)
        (baseline / "win10-baseline.img").write_bytes(b"\x00" * 16)

    def test_four_hosts_each_with_two_evidence_files(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = scan_evidence_directory(evidence_dir)
        host_ids = sorted(host_id for host_id, _, _ in result)
        assert host_ids == sorted(self._HOSTS)
        for host_id, _, files in result:
            names = {p.name for p, _, _ in files}
            assert names == {f"{host_id}-memory.001", f"{host_id}.E01"}, (
                f"host {host_id} should have exactly memory.001 + .E01; "
                f"got {names}"
            )

    def test_memory_001_files_typed_as_memory(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = scan_evidence_directory(evidence_dir)
        memory_001 = [
            (p.name, t)
            for _, _, files in result
            for p, t, _ in files
            if p.name.endswith(".001")
        ]
        assert len(memory_001) == 4
        assert all(t == "memory" for _, t in memory_001)

    def test_disk_e01_files_typed_as_disk(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = scan_evidence_directory(evidence_dir)
        disk_e01 = [
            (p.name, t)
            for _, _, files in result
            for p, t, _ in files
            if p.name.lower().endswith(".e01")
        ]
        assert len(disk_e01) == 4
        assert all(t == "disk" for _, t in disk_e01)

    def test_mans_csv_txt_dump_baseline_img_all_skipped(
        self, tmp_path: Path
    ):
        evidence_dir = tmp_path / "evidence"
        self._seed(evidence_dir)
        result = scan_evidence_directory(evidence_dir)
        all_names = [
            p.name
            for _, _, files in result
            for p, _, _ in files
        ]
        # .mans (per-host)
        assert not any(n.endswith(".mans") for n in all_names)
        # precooked/ files (any extension under that dir)
        for skipped_ext in (".csv", ".dump", ".xlsx", ".body", ".ioc", ".txt"):
            assert not any(
                n.endswith(skipped_ext) for n in all_names
            ), f"a {skipped_ext} file leaked into the manifest"
        # baseline/*.img
        assert not any(
            n.endswith(".img") and "baseline" in n.lower()
            for n in all_names
        )
        # Total file count: 4 hosts × 2 files = 8.
        assert len(all_names) == 8


class TestFormatInventoryTable:
    def test_two_host_two_evidence_table(self):
        ef_a = EvidenceFile(
            evidence_id="a", file_path="/c/nfury-memory.raw",
            evidence_type="memory", os_guess="Windows 7 64-bit",
            file_size_bytes=14_000_000_000,
        )
        ef_b = EvidenceFile(
            evidence_id="b", file_path="/c/nfury-disk.E01",
            evidence_type="disk", os_guess="Windows 7 64-bit",
            file_size_bytes=8_700_000_000,
        )
        ef_c = EvidenceFile(
            evidence_id="c", file_path="/c/controller-memory.raw",
            evidence_type="memory", os_guess="Server 2008 R2",
            file_size_bytes=17_500_000_000,
        )
        hosts = [
            HostEvidence(
                host_id="nfury", host_label="nfury",
                evidence_files=[ef_a, ef_b],
            ),
            HostEvidence(
                host_id="controller", host_label="controller",
                evidence_files=[ef_c],
            ),
        ]
        table = format_inventory_table(hosts)
        assert "Host" in table and "Evidence" in table and "OS Guess" in table
        assert "nfury" in table and "controller" in table
        assert "nfury-memory.raw" in table
        assert "13.0 GB" in table or "13.1 GB" in table  # 14e9 bytes ≈ 13 GB

    def test_empty_hosts_yields_empty_string(self):
        assert format_inventory_table([]) == ""
