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
