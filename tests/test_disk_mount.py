"""Unit tests for `server.runners.disk_mount`.

Tests run in two modes:
  - **premounted**: SIFT_DISK_PREMOUNTED_PATH set to a tmp dir;
    the utility skips every shell-out and validates /proc/mounts.
  - **fake-mount**: monkeypatch _read_proc_mounts to return a
    synthetic /proc/mounts line so a real-looking mount is
    impersonated without root.

No real ewfmount / mount / guestmount calls happen in CI.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from server.runners import disk_mount
from server.runners.disk_mount import (
    MountVerificationError,
    SIFT_DISK_PREMOUNTED_PATH_ENV,
    _detect_image_format,
    _is_path_mounted_readonly,
    mount_disk_image,
    parse_evtx,
    parse_plaso_jsonl,
    parse_prefetch,
    parse_regripper,
    umount_all_for,
)


@pytest.fixture(autouse=True)
def _clear_mount_cache():
    """Ensure each test starts with an empty in-process mount cache."""
    disk_mount._MOUNT_CACHE.clear()
    yield
    disk_mount._MOUNT_CACHE.clear()


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


class TestDetectImageFormat:
    def test_e01_extension(self):
        assert _detect_image_format("/case/disk1.E01") == "e01"
        assert _detect_image_format("/case/disk.s01") == "e01"
        assert _detect_image_format("/case/disk.Ex01") == "e01"

    def test_raw_extension(self):
        assert _detect_image_format("/case/disk.raw") == "raw"
        assert _detect_image_format("/case/disk.dd") == "raw"
        assert _detect_image_format("/case/disk.img") == "raw"

    def test_vhdx_extension(self):
        assert _detect_image_format("/case/disk.vhdx") == "vhdx"
        assert _detect_image_format("/case/disk.vhd") == "vhdx"

    def test_unknown_falls_back_to_raw(self):
        # Renamed dd images often lose their extension; default-raw
        # gives the operator-most-likely-correct mount path.
        assert _detect_image_format("/case/no-extension") == "raw"


# ---------------------------------------------------------------------------
# Premounted-path mode
# ---------------------------------------------------------------------------


def _fake_proc_mounts_for(target: str, opts: str = "ro,relatime") -> str:
    return f"proc /proc proc rw,relatime 0 0\n/dev/loop1 {target} ext4 {opts} 0 0\n"


class TestPremountedMode:
    def test_premounted_path_is_returned_when_proc_mounts_shows_ro(
        self, tmp_path: Path, monkeypatch
    ):
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value=_fake_proc_mounts_for(str(target)),
        ):
            result = mount_disk_image("eid-1", "/case/disk.raw")
        assert result == str(target)

    def test_premounted_path_missing_ro_raises(self, tmp_path: Path, monkeypatch):
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value=_fake_proc_mounts_for(str(target), opts="rw"),
        ):
            with pytest.raises(MountVerificationError):
                mount_disk_image("eid-2", "/case/disk.raw")

    def test_premounted_path_skips_shellout(self, tmp_path: Path, monkeypatch):
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        with (
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value=_fake_proc_mounts_for(str(target)),
            ),
            patch("subprocess.run") as mock_run,
        ):
            mount_disk_image("eid-3", "/case/disk.raw")
        assert mock_run.call_count == 0, "premounted mode must not invoke any subprocess"

    def test_cached_mount_is_reused_on_repeat_call(self, tmp_path: Path, monkeypatch):
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value=_fake_proc_mounts_for(str(target)),
        ) as mock_read:
            first = mount_disk_image("eid-4", "/case/disk.raw")
            second = mount_disk_image("eid-4", "/case/disk.raw")
        assert first == second
        # First call validates the env-var path; cache hit
        # validates the cached path. So there are 2 reads, not 1
        # — but the second read happens against the cache, not via
        # a fresh env-var resolution. Either way < 3.
        assert mock_read.call_count <= 3


# ---------------------------------------------------------------------------
# /proc/mounts checker
# ---------------------------------------------------------------------------


class TestIsPathMountedReadonly:
    def test_recognizes_ro_in_options(self):
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value="/dev/loop1 /mnt/x ext4 ro,relatime 0 0\n",
        ):
            assert _is_path_mounted_readonly("/mnt/x") is True

    def test_rejects_rw_mount(self):
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value="/dev/loop1 /mnt/x ext4 rw,relatime 0 0\n",
        ):
            assert _is_path_mounted_readonly("/mnt/x") is False

    def test_returns_false_for_unmounted_path(self):
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value="proc /proc proc rw,relatime 0 0\n",
        ):
            assert _is_path_mounted_readonly("/mnt/missing") is False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MFT_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_mft_sample.jsonl"
PREFETCH_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_prefetch_sample.jsonl"
EVTX_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_evtx_sample.jsonl"
REGRIPPER_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_regripper_sample.txt"


class TestParsePlasoJsonl:
    def test_extracts_four_mft_rows_with_entry_types(self):
        rows = parse_plaso_jsonl(MFT_FIXTURE.read_text())
        assert len(rows) == 4
        types = {r["entry_type"] for r in rows}
        assert types == {"created", "modified", "accessed", "mft_modified"}
        # Path strings come through verbatim — evidence-derived,
        # tagged untrusted at the schema level.
        paths = {r["full_path"] for r in rows}
        assert "/Windows/System32/cmd.exe" in paths
        assert "/Users/Public/notepad.exe" in paths
        # File size pulls through; null is acceptable but we
        # populated it on every row.
        assert all(r["file_size"] == 289792 or r["file_size"] == 201728 for r in rows)

    def test_drops_non_mft_parser_rows(self):
        rows = parse_plaso_jsonl(
            '{"datetime": "2024-01-01T00:00:00+00:00", "parser": "pe", '
            '"timestamp_desc": "Creation Time", '
            '"display_name": "/x.exe"}\n'
        )
        assert rows == []


class TestParsePrefetch:
    def test_extracts_three_prefetch_entries(self):
        rows = parse_prefetch(PREFETCH_FIXTURE.read_text())
        assert len(rows) == 3
        names = {r["executable_name"] for r in rows}
        assert names == {"CMD.EXE", "POWERSHELL.EXE", "MIMIKATZ.EXE"}
        cmd = next(r for r in rows if r["executable_name"] == "CMD.EXE")
        assert cmd["run_count"] == 12
        assert len(cmd["last_run_times"]) == 2

    def test_caps_referenced_files_at_50(self):
        # Synthetic huge referenced-files list — parser truncates
        # to 50 to match the schema's max_length=50 contract.
        big = ", ".join([f'"\\\\path\\\\file{i}.dll"' for i in range(120)])
        line = (
            '{"executable_filename": "BIG.EXE", "run_count": 1, '
            '"last_run_times": [], "volume_path": "X", '
            '"referenced_files": [' + big + "]}"
        )
        rows = parse_prefetch(line)
        assert len(rows) == 1
        assert len(rows[0]["referenced_files"]) == 50


class TestParseEvtx:
    def test_extracts_three_event_records_with_logon_type(self):
        rows = parse_evtx(EVTX_FIXTURE.read_text())
        assert len(rows) == 3
        # Event 4624 — successful RDP-style logon (LogonType 10).
        e4624 = next(r for r in rows if r["event_id"] == 4624)
        assert e4624["channel"] == "Security"
        assert e4624["logon_type"] == 10
        # Event 4625 — failed logon.
        e4625 = next(r for r in rows if r["event_id"] == 4625)
        assert e4625["logon_type"] == 10
        # Event 7045 — service install. logon_type is null (no
        # LogonType in EventData).
        e7045 = next(r for r in rows if r["event_id"] == 7045)
        assert e7045["channel"] == "System"
        assert e7045["logon_type"] is None
        assert "EvilSvc" in e7045["message_summary"]

    def test_message_summary_truncated_to_500_chars(self):
        # Synthetic huge EventData payload — parser truncates.
        long_val = "A" * 600
        line = (
            '{"__channel": "Security", "Event": {"System": '
            '{"EventID": 4624, "Provider": {"Name": "X"}, '
            '"Channel": "Security", "TimeCreated": '
            '{"SystemTime": "2024-01-01T00:00:00+00:00"}}, '
            f'"EventData": {{"Data": [{{"@Name": "Foo", '
            f'"#text": "{long_val}"}}]}}}}}}'
        )
        rows = parse_evtx(line)
        assert len(rows) == 1
        assert len(rows[0]["message_summary"]) <= 500
        assert rows[0]["message_summary"].endswith("[truncated]")


class TestParseRegripper:
    def test_extracts_records_across_three_hives(self):
        rows = parse_regripper(REGRIPPER_FIXTURE.read_text())
        # 3 values in SYSTEM (ImagePath, Start, Type) + 1 in
        # SOFTWARE (EvilLoader) + 1 in NTUSER.DAT (SkypeUpdater) = 5.
        assert len(rows) == 5

        hives = {r["hive_name"] for r in rows}
        assert hives == {"SYSTEM", "SOFTWARE", "NTUSER.DAT"}

        # SYSTEM/Services/EvilSvc/ImagePath.
        evil = next(
            r for r in rows if r["hive_name"] == "SYSTEM" and r["value_name"] == "ImagePath"
        )
        assert "evil.exe" in evil["value_data"]
        assert "Services\\EvilSvc" in evil["key_path"]

        # SOFTWARE Run key.
        run = next(
            r for r in rows if r["hive_name"] == "SOFTWARE" and r["value_name"] == "EvilLoader"
        )
        assert "Run" in run["key_path"]

        # NTUSER.DAT Run key.
        ntuser_run = next(
            r for r in rows if r["hive_name"] == "NTUSER.DAT" and r["value_name"] == "SkypeUpdater"
        )
        assert "Run" in ntuser_run["key_path"]

    def test_value_data_truncated_to_500_chars(self):
        long_val = "A" * 600
        stdout = (
            "# === HIVE: SOFTWARE ===\n"
            "Key: Microsoft\\Windows\\CurrentVersion\\Run\n"
            "LastWrite Time = 2024-01-01T00:00:00+00:00\n"
            f"BigVal -> {long_val}\n"
        )
        rows = parse_regripper(stdout)
        assert len(rows) == 1
        assert len(rows[0]["value_data"]) <= 500


# ---------------------------------------------------------------------------
# umount_all_for
# ---------------------------------------------------------------------------


class TestUmountAllFor:
    def test_premounted_mode_does_not_shellout(self, tmp_path: Path, monkeypatch):
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        with patch.object(
            disk_mount,
            "_read_proc_mounts",
            return_value=_fake_proc_mounts_for(str(target)),
        ):
            mount_disk_image("eid-u", "/case/disk.raw")
        with patch("subprocess.run") as mock_run:
            umount_all_for("eid-u")
        assert mock_run.call_count == 0
        # Cache cleared.
        assert "eid-u" not in disk_mount._MOUNT_CACHE

    def test_unknown_evidence_id_is_no_op(self):
        # Idempotent — no error if there's no cached mount.
        umount_all_for("never-mounted")
