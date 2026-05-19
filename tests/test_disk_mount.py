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

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from server.runners import disk_mount
from server.runners.disk_mount import (
    MountError,
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
    """Ensure each test starts with an empty in-process mount cache.

    The fallback-chain tests also stash entries in
    ``_EWF_DIR_CACHE`` / ``_GUESTMOUNT_CACHE``; clear those too
    so the atexit handler does not chase tmp dirs from a prior
    test on shutdown.
    """
    disk_mount._MOUNT_CACHE.clear()
    disk_mount._EWF_DIR_CACHE.clear()
    disk_mount._GUESTMOUNT_CACHE.clear()
    yield
    disk_mount._MOUNT_CACHE.clear()
    disk_mount._EWF_DIR_CACHE.clear()
    disk_mount._GUESTMOUNT_CACHE.clear()


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
EVTX_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "disk_evtx_sample.xml"
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

    def test_parses_pytsk3_canonical_rows(self):
        # Since 2026-05-19 the runner emits canonical rows directly
        # (run_mft_timeline_pytsk3). parse_plaso_jsonl detects the
        # pytsk3 shape by the presence of the ``entry_type`` field
        # and short-circuits — no plaso field mapping needed.
        rows = parse_plaso_jsonl(
            '{"timestamp": "2024-01-01T00:00:00+00:00", '
            '"full_path": "/x.exe", "entry_type": "created", '
            '"file_size": 1024}\n'
            '{"timestamp": "2024-01-01T00:01:00+00:00", '
            '"full_path": "/dir", "entry_type": "modified", '
            '"file_size": null}'
        )
        assert len(rows) == 2
        assert rows[0]["entry_type"] == "created"
        assert rows[0]["file_size"] == 1024
        assert rows[1]["entry_type"] == "modified"
        assert rows[1]["file_size"] is None

    def test_plaso_legacy_shape_still_parses(self):
        # Cached extractions written under the pre-pytsk3 runner are
        # in the plaso json_line shape; parse_plaso_jsonl still maps
        # the legacy fields so old extractions remain readable.
        rows = parse_plaso_jsonl(
            '{"datetime": "2024-01-01T00:00:00+00:00", "parser": "mft", '
            '"timestamp_desc": "Creation Time", '
            '"display_name": "/legacy.exe", "file_size": 42}\n'
        )
        assert len(rows) == 1
        assert rows[0]["entry_type"] == "created"
        assert rows[0]["full_path"] == "/legacy.exe"


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
        # SIFT 2026.1's python-evtx 0.8.1 emits XML; the parser splits
        # on the runner's per-channel marker and parses each chunk.
        long_val = "A" * 600
        xml = (
            "<!-- __channel__:Security -->\n"
            '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'
            "<Events>\n"
            '<Event><System><Provider Name="X"></Provider>\n'
            "<EventID>4624</EventID>\n"
            '<TimeCreated SystemTime="2024-01-01T00:00:00+00:00"></TimeCreated>\n'
            "<Channel>Security</Channel>\n"
            "</System>\n"
            "<EventData>\n"
            f'<Data Name="Foo">{long_val}</Data>\n'
            "</EventData>\n"
            "</Event>\n"
            "</Events>"
        )
        rows = parse_evtx(xml)
        assert len(rows) == 1
        assert len(rows[0]["message_summary"]) <= 500
        assert rows[0]["message_summary"].endswith("[truncated]")

    def test_no_channel_marker_falls_back_to_untagged_chunk(self):
        # Tolerate the case where the runner couldn't tag a channel —
        # parse_evtx should still ingest the events with an empty
        # channel string rather than dropping everything.
        xml = (
            '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'
            "<Events>\n"
            '<Event><System><Provider Name="X"></Provider>\n'
            "<EventID>9999</EventID>\n"
            '<TimeCreated SystemTime="2024-01-01T00:00:00+00:00"></TimeCreated>\n'
            "</System></Event>\n"
            "</Events>"
        )
        rows = parse_evtx(xml)
        assert len(rows) == 1
        assert rows[0]["event_id"] == 9999

    def test_malformed_event_inside_chunk_is_skipped(self):
        # One garbage <Event> block should not poison the whole chunk —
        # the parser falls back to per-event regex parsing.
        xml = (
            "<!-- __channel__:Security -->\n"
            "<Events>\n"
            "<Event><System><EventID>NOT_A_NUMBER</EventID></System></Event>\n"
            '<Event><System><Provider Name="X"></Provider>\n'
            "<EventID>4624</EventID>\n"
            '<TimeCreated SystemTime="2024-01-01T00:00:00+00:00"></TimeCreated>\n'
            "</System></Event>\n"
            "</Events>"
        )
        rows = parse_evtx(xml)
        # Garbage event skipped; valid event retained.
        assert len(rows) == 1
        assert rows[0]["event_id"] == 4624


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


# ---------------------------------------------------------------------------
# Fallback-chain dispatch — no real subprocesses run; every shell-out
# is mocked. Verifies that each fallback fires in the right order and
# that the post-mount /proc/mounts validation rejects partial mounts.
# ---------------------------------------------------------------------------


def _proc_mounts_for(target: str) -> str:
    return f"proc /proc proc rw,relatime 0 0\n/dev/loop1 {target} ext4 ro,relatime 0 0\n"


def _fuse_proc_mounts_for(target: str) -> str:
    """A FUSE entry shaped like what guestmount writes to /proc/mounts."""
    return f"proc /proc proc rw,relatime 0 0\n/dev/fuse {target} fuse.guestmount ro,user_id=1000 0 0\n"


class TestFallbackChainDispatch:
    """Each fallback step is a separate subprocess call; the test
    decides which calls succeed and which fail so we can pin which
    branch of the fallback chain fired."""

    def test_e01_path_a_succeeds_with_sudo_mount(self, monkeypatch, tmp_path: Path):
        """Path A (ewfmount + loop-mount) succeeds under sudo on the
        first try (no guestmount fallback). ewfmount and mount are
        always invoked via ``sudo`` — the NOPASSWD sudoers entry at
        ``/etc/sudoers.d/sift-guard`` makes the call non-interactive
        and the previous direct-first/sudo-on-failure two-step is
        gone."""
        mount_base = tmp_path / "sift-mounts"
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", mount_base)
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)
        expected_mount = mount_base / "eid-e01-"[:8]  # _allocate_mount_dir uses [:8]

        def fake_run(argv, *args, **kwargs):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run) as mock_run,
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value=_proc_mounts_for(str(expected_mount)),
            ),
        ):
            mount_path = mount_disk_image("eid-e01-a", "/case/disk.E01")

        # No guestmount call should appear in the argv list.
        argvs = [c.args[0] for c in mock_run.call_args_list]
        flat = [token for argv in argvs for token in argv]
        assert "guestmount" not in flat, "Path A succeeded; guestmount must not have fired"
        # Every Path-A call leads with "sudo" — never a bare ewfmount/mount.
        assert any(a[0] == "sudo" and a[1] == "ewfmount" for a in argvs), (
            f"expected sudo ewfmount, got argvs={argvs!r}"
        )
        assert any(a[0] == "sudo" and a[1] == "mount" for a in argvs), (
            f"expected sudo mount, got argvs={argvs!r}"
        )
        assert not any(
            (a[0] == "ewfmount" or a[0] == "mount") for a in argvs
        ), "ewfmount/mount must not be invoked without sudo"
        assert mount_path == str(expected_mount)

    def test_e01_falls_back_to_guestmount_when_sudo_ewfmount_fails(
        self, monkeypatch, tmp_path: Path
    ):
        """``sudo ewfmount`` fails (or ``sudo mount -o ro,loop``
        fails); Path A is unusable. Guestmount (Path B) is then
        attempted and succeeds. The previous direct-then-sudo
        two-step is gone — there's exactly one ewfmount attempt
        (sudo) before the fallback fires."""
        mount_base = tmp_path / "sift-mounts"
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", mount_base)
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)

        calls: list[list[str]] = []

        def fake_run(argv, *args, **kwargs):
            calls.append(list(argv))

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            program = argv[0] if argv[0] != "sudo" else argv[1]
            # ewfmount + mount under sudo both fail; guestmount
            # (run without sudo, libguestfs ships its own FUSE
            # helper) succeeds. Cleanup-path umount calls are
            # no-ops (check=False) and return success.
            if program in ("ewfmount", "mount") and not kwargs.get("check") is False:
                raise subprocess.CalledProcessError(returncode=1, cmd=argv)
            return _R()

        # Second mount dir (after the cleanup-and-retry) has the
        # same path because _allocate_mount_dir is deterministic
        # and the cleanup rmdir is a no-op if it doesn't exist.
        expected_mount = mount_base / "eid-e01-"[:8]

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run),
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value=_fuse_proc_mounts_for(str(expected_mount)),
            ),
        ):
            mount_disk_image("eid-e01-b", "/case/disk.E01")

        sudo_ewfmount_calls = [c for c in calls if c[:2] == ["sudo", "ewfmount"]]
        bare_ewfmount_calls = [c for c in calls if c[:1] == ["ewfmount"]]
        guestmount_calls = [c for c in calls if c[:1] == ["guestmount"]]

        assert sudo_ewfmount_calls, "Path A must invoke ewfmount under sudo"
        assert not bare_ewfmount_calls, (
            "ewfmount must never be invoked without sudo — the "
            "direct-then-sudo two-step was removed in favor of the "
            "always-sudo path backed by /etc/sudoers.d/sift-guard"
        )
        assert guestmount_calls, (
            "Path A failed; Path B (guestmount) must fire"
        )
        # Order: sudo ewfmount runs before guestmount.
        first_sudo_ewf = next(i for i, c in enumerate(calls) if c[:2] == ["sudo", "ewfmount"])
        first_guestmount = next(i for i, c in enumerate(calls) if c[:1] == ["guestmount"])
        assert first_sudo_ewf < first_guestmount

    def test_raw_falls_back_to_guestmount_when_sudo_loop_mount_fails(
        self, monkeypatch, tmp_path: Path
    ):
        """For raw images: ``sudo mount -o ro,loop`` fails, so
        guestmount is attempted. Only one mount attempt happens
        before the fallback; the direct-then-sudo retry was
        removed."""
        mount_base = tmp_path / "sift-mounts"
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", mount_base)
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)

        calls: list[list[str]] = []

        def fake_run(argv, *args, **kwargs):
            calls.append(list(argv))

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            program = argv[0] if argv[0] != "sudo" else argv[1]
            # The actual Path-A subprocess calls (via _run_subprocess,
            # check=True) raise CalledProcessError. Cleanup calls
            # (check=False) just return success.
            if program == "mount" and kwargs.get("check"):
                raise subprocess.CalledProcessError(returncode=1, cmd=argv)
            return _R()

        expected_mount = mount_base / "eid-raw-"[:8]

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run),
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value=_fuse_proc_mounts_for(str(expected_mount)),
            ),
        ):
            mount_disk_image("eid-raw-b", "/case/disk.raw")

        sudo_mount_calls = [c for c in calls if c[:2] == ["sudo", "mount"]]
        bare_mount_calls = [c for c in calls if c[:1] == ["mount"]]
        guestmount_calls = [c for c in calls if c[:1] == ["guestmount"]]

        assert sudo_mount_calls, "Path A must invoke mount under sudo"
        assert not bare_mount_calls, (
            "mount must never be invoked without sudo"
        )
        assert guestmount_calls, (
            "sudo mount -o ro,loop failed; guestmount must fire"
        )
        first_sudo_mount = next(
            i for i, c in enumerate(calls) if c[:2] == ["sudo", "mount"]
        )
        first_guestmount = next(
            i for i, c in enumerate(calls) if c[:1] == ["guestmount"]
        )
        assert first_sudo_mount < first_guestmount

    def test_vhdx_uses_guestmount_only(self, monkeypatch, tmp_path: Path):
        """VHDX has no Path A — guestmount is the first and only
        mount strategy (other than the orphan-cleanup pre-flight,
        which only fires when a stale mount actually exists at the
        predictable path)."""
        mount_base = tmp_path / "sift-mounts"
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", mount_base)
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)

        calls: list[list[str]] = []

        def fake_run(argv, *args, **kwargs):
            calls.append(list(argv))

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            return _R()

        expected_mount = mount_base / "eid-vhdx"[:8]

        # Two-stage proc_mounts mock: empty BEFORE the mount so the
        # orphan-cleanup pre-flight skips both paths, populated AFTER
        # so the post-mount readonly verification passes.
        proc_states = iter(
            [
                "",  # _clean_stale_mount_for: target check
                "",  # _clean_stale_mount_for: ewf check
            ]
        )

        def proc_mounts() -> str:
            return next(proc_states, _fuse_proc_mounts_for(str(expected_mount)))

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run),
            patch.object(disk_mount, "_read_proc_mounts", side_effect=proc_mounts),
        ):
            mount_disk_image("eid-vhdx", "/case/disk.vhdx")

        programs = [c[0] if c[0] != "sudo" else c[2] for c in calls]
        # Only one subprocess call expected — guestmount. No cleanup
        # calls because Path A wasn't attempted and the orphan-cleanup
        # pre-flight saw the predictable paths clean.
        assert programs == ["guestmount"]

    def test_all_strategies_fail_raises_mount_error(self, monkeypatch, tmp_path: Path):
        """When every tier of the fallback chain fails, the final
        ``MountError`` propagates. No half-built mount leaks."""
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", tmp_path / "sift-mounts")
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)

        def fake_run(argv, *args, **kwargs):
            # Only check=True calls raise; cleanup (check=False) is
            # tolerated as a no-op.
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(returncode=1, cmd=argv)

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            return _R()

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run),
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value="proc /proc proc rw,relatime 0 0\n",
            ),
        ):
            with pytest.raises(MountError):
                mount_disk_image("eid-all-fail", "/case/disk.E01")
        # Cache is empty — no stale entry that future calls could trip on.
        assert "eid-all-fail" not in disk_mount._MOUNT_CACHE

    def test_mount_dir_lives_under_predictable_base(self, monkeypatch, tmp_path: Path):
        """The mount dir lives under ``_MOUNT_BASE/<evidence_id_short>/``
        — predictable so the sudoers wildcard scopes cleanly. No
        random tempfile name."""
        mount_base = tmp_path / "sift-mounts"
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", mount_base)
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)

        def fake_run(argv, *args, **kwargs):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        expected_mount = mount_base / "abcdef01"

        with (
            patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run),
            patch.object(
                disk_mount,
                "_read_proc_mounts",
                return_value=_proc_mounts_for(str(expected_mount)),
            ),
        ):
            mount_path = mount_disk_image("abcdef0123456789", "/case/disk.raw")

        # Mount path starts with the predictable base; the suffix
        # is the first 8 chars of the evidence_id (no random tempfile suffix).
        assert mount_path == str(expected_mount)


class TestAtexitCleanup:
    def test_atexit_skips_premounted_mode(self, tmp_path: Path, monkeypatch):
        """In premounted mode the operator manages the mount; the
        atexit handler must not unmount it."""
        target = tmp_path / "mounted"
        target.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(target))
        disk_mount._MOUNT_CACHE["eid-x"] = str(target)
        with patch("subprocess.run") as mock_run:
            disk_mount._atexit_cleanup_all_mounts()
        assert mock_run.call_count == 0
        # Premounted entries are also left in the cache so any
        # post-shutdown introspection can see what the operator
        # had set up.
        assert "eid-x" in disk_mount._MOUNT_CACHE

    def test_atexit_clears_cache_and_attempts_unmount(self, tmp_path: Path, monkeypatch):
        """When not in premounted mode, atexit unmount-s every cached
        mount and empties the cache."""
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)
        target = tmp_path / "mounted"
        target.mkdir()
        disk_mount._MOUNT_CACHE["eid-y"] = str(target)
        with patch("server.runners.disk_mount.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            disk_mount._atexit_cleanup_all_mounts()
        assert mock_run.call_count >= 1
        assert "eid-y" not in disk_mount._MOUNT_CACHE


class TestOrphanMountCleanup:
    """The 2026-05-13 SRL-v2 audit found three orphan fuse mounts
    surviving across run boundaries
    (``/tmp/sift-guard-mounts/<short>-ewf``). Any subsequent run on
    the same predictable mount path hits ``rejected_mount_failed``
    because ``_allocate_mount_dir`` collides with the orphan.

    These tests pin the orphan-detection + force-unmount path so the
    fix doesn't regress."""

    def test_is_path_mounted_anywhere_detects_orphan(self, monkeypatch):
        fake_mounts = (
            "/dev/fuse /tmp/sift-guard-mounts/bed14651-ewf "
            "fuse rw,nosuid,nodev,relatime,user_id=0,group_id=0 0 0"
        )
        monkeypatch.setattr(disk_mount, "_read_proc_mounts", lambda: fake_mounts)
        assert disk_mount._is_path_mounted_anywhere(
            "/tmp/sift-guard-mounts/bed14651-ewf"
        )
        assert not disk_mount._is_path_mounted_anywhere(
            "/tmp/sift-guard-mounts/nope"
        )

    def test_clean_stale_mount_for_attempts_both_paths(
        self, tmp_path: Path, monkeypatch
    ):
        """_clean_stale_mount_for must check BOTH ``mount_dir`` and
        ``mount_dir + "-ewf"`` since the ewfmount fallback creates an
        intermediate fuse mount at the latter."""
        target = tmp_path / "bed14651"
        ewf = tmp_path / "bed14651-ewf"
        target.mkdir()
        ewf.mkdir()
        # Pretend BOTH paths stay mounted regardless of teardown
        # attempts — that way _force_unmount exhausts every fallback
        # and we can count the teardown attempts per path. The
        # important assertion is that we tried to clean both, not
        # that the cleanup succeeded.
        fake_mounts = (
            f"/dev/fuse {target} fuse rw 0 0\n"
            f"/dev/fuse {ewf} fuse rw 0 0\n"
        )
        monkeypatch.setattr(disk_mount, "_read_proc_mounts", lambda: fake_mounts)

        umount_calls: list[list[str]] = []

        def fake_run(argv, **kwargs):
            umount_calls.append(list(argv))
            return subprocess.CompletedProcess(
                argv, returncode=0, stdout="", stderr=""
            )

        with patch("server.runners.disk_mount.subprocess.run", side_effect=fake_run):
            disk_mount._clean_stale_mount_for("bed14651-1234", target)

        # _force_unmount tries fusermount, sudo fusermount, sudo umount
        # per path → at minimum some teardown call per path.
        target_attempts = [c for c in umount_calls if str(target) in c]
        ewf_attempts = [c for c in umount_calls if str(ewf) in c]
        assert target_attempts, f"no teardown attempts on {target}"
        assert ewf_attempts, f"no teardown attempts on {ewf}"

    def test_force_unmount_returns_true_when_clean(
        self, tmp_path: Path, monkeypatch
    ):
        # First check shows mounted; after fusermount, clean.
        states = iter(
            [
                f"/dev/fuse {tmp_path}/m fuse rw 0 0",
                "",
            ]
        )
        monkeypatch.setattr(
            disk_mount, "_read_proc_mounts", lambda: next(states, "")
        )
        with patch("server.runners.disk_mount.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            ok = disk_mount._force_unmount(tmp_path / "m")
        assert ok is True

    def test_cleanup_stale_mounts_globally_skips_known_mounts(
        self, tmp_path: Path, monkeypatch
    ):
        """An in-cache mount is owned by the current process; do not
        tear it down even though it lives under the sift-guard mount
        base."""
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)
        my_mount = "/tmp/sift-guard-mounts/abcdef12"
        orphan = "/tmp/sift-guard-mounts/dead0001-ewf"
        disk_mount._MOUNT_CACHE["my-eid"] = my_mount
        try:
            fake_mounts = (
                f"/dev/loop9 {my_mount} fuseblk ro 0 0\n"
                f"/dev/fuse {orphan} fuse rw 0 0\n"
            )
            states = iter(
                [
                    fake_mounts,  # initial enumeration
                    fake_mounts,  # check on orphan — mounted
                    "",  # after fusermount on orphan — clean
                ]
            )
            monkeypatch.setattr(
                disk_mount, "_read_proc_mounts", lambda: next(states, "")
            )
            with patch(
                "server.runners.disk_mount.subprocess.run"
            ) as mock_run:
                mock_run.return_value.returncode = 0
                result = disk_mount.cleanup_stale_mounts_globally()

            # The owned mount must not have been touched.
            for call in mock_run.call_args_list:
                args = call.args[0] if call.args else call.kwargs.get("args", [])
                assert my_mount not in args
            assert result["cleaned"] >= 1
        finally:
            disk_mount._MOUNT_CACHE.pop("my-eid", None)

    def test_cleanup_stale_mounts_globally_respects_premounted_mode(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(tmp_path))
        with patch("server.runners.disk_mount.subprocess.run") as mock_run:
            result = disk_mount.cleanup_stale_mounts_globally()
        # No subprocess calls in premounted mode.
        assert mock_run.call_count == 0
        assert result == {"cleaned": 0, "remaining": 0}


class TestFileBasedPremount:
    """File-based per-evidence-id premount override.

    Complements ``SIFT_DISK_PREMOUNTED_PATH`` (the env-var form,
    one path for every evidence) by letting the operator point
    each evidence_id at a different external mount via a hint file
    at ``/tmp/sift-guard-premounts/<evidence_id>``. Useful when
    multiple disks are pre-mounted by hand on different loop
    devices."""

    def test_file_hint_takes_effect_when_env_unset(
        self, tmp_path: Path, monkeypatch
    ):
        # Re-base the mount tree under tmp_path so we can stage the
        # hint file alongside.
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", tmp_path / "sift-guard-mounts")
        operator_mount = tmp_path / "operator-mount"
        operator_mount.mkdir()
        hint_dir = tmp_path / "sift-guard-premounts"
        hint_dir.mkdir()
        (hint_dir / "eid-abc").write_text(str(operator_mount) + "\n")

        # Stage proc_mounts so the post-check sees operator_mount as ro.
        monkeypatch.setattr(
            disk_mount,
            "_read_proc_mounts",
            lambda: f"/dev/loop9 {operator_mount} ext4 ro 0 0\n",
        )
        try:
            with patch("server.runners.disk_mount.subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                resolved = mount_disk_image("eid-abc", "/case/disk.E01")
            # The file-based override short-circuits before any
            # mount/ewfmount call.
            assert resolved == str(operator_mount)
            assert mock_run.call_count == 0
        finally:
            disk_mount._MOUNT_CACHE.pop("eid-abc", None)

    def test_env_var_wins_over_file_hint(
        self, tmp_path: Path, monkeypatch
    ):
        # If both are set, the env var (operator's session-level
        # override) takes precedence over the per-evidence file.
        env_mount = tmp_path / "env-mount"
        env_mount.mkdir()
        file_mount = tmp_path / "file-mount"
        file_mount.mkdir()
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(env_mount))
        monkeypatch.setattr(disk_mount, "_MOUNT_BASE", tmp_path / "sift-guard-mounts")
        hint_dir = tmp_path / "sift-guard-premounts"
        hint_dir.mkdir()
        (hint_dir / "eid-xyz").write_text(str(file_mount) + "\n")

        monkeypatch.setattr(
            disk_mount,
            "_read_proc_mounts",
            lambda: f"/dev/loop9 {env_mount} ext4 ro 0 0\n",
        )
        try:
            resolved = mount_disk_image("eid-xyz", "/case/disk.E01")
            assert resolved == str(env_mount)
        finally:
            disk_mount._MOUNT_CACHE.pop("eid-xyz", None)


class TestPlasoTempdirTracking:
    """The 2026-05-13 SRL-v2 audit found ~210 MB of leaked
    ``/tmp/sift-plaso-*`` directories across three killed runs.
    ``_register_plaso_tempdir`` + ``_atexit_cleanup_all_mounts``'s
    new branch reaps these on shutdown."""

    def test_register_adds_to_set(self, tmp_path: Path):
        p = tmp_path / "sift-plaso-xyz"
        p.mkdir()
        try:
            disk_mount._register_plaso_tempdir(p)
            assert str(p) in disk_mount._PLASO_TEMP_DIRS
        finally:
            disk_mount._PLASO_TEMP_DIRS.discard(str(p))

    def test_atexit_reaps_plaso_tempdirs(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv(SIFT_DISK_PREMOUNTED_PATH_ENV, raising=False)
        p = tmp_path / "sift-plaso-zzz"
        p.mkdir()
        (p / "out.plaso").write_bytes(b"\x00" * 4096)
        disk_mount._register_plaso_tempdir(p)
        # Cache is empty so the mount-cleanup loop is a no-op; the
        # plaso reaper runs unconditionally.
        disk_mount._atexit_cleanup_all_mounts()
        assert not p.exists()
        assert str(p) not in disk_mount._PLASO_TEMP_DIRS

    def test_atexit_plaso_reap_runs_in_premounted_mode_too(
        self, tmp_path: Path, monkeypatch
    ):
        # Even in premounted mode (where the operator manages
        # external mounts), plaso work dirs are unconditionally
        # sift-guard-owned and must be reaped.
        monkeypatch.setenv(SIFT_DISK_PREMOUNTED_PATH_ENV, str(tmp_path))
        p = tmp_path / "sift-plaso-aaa"
        p.mkdir()
        disk_mount._register_plaso_tempdir(p)
        disk_mount._atexit_cleanup_all_mounts()
        assert not p.exists()
