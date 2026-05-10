"""Smoke tests for `sift_guard.preflight`.

Real `vol` invocation is mocked at the subprocess seam — the
preflight probe is a thin wrapper around two calls to
``windows.info.Info`` / ``linux.info.Info`` plus a regex-based
parser. We verify the four operational outcomes:

  - happy path: windows.info.Info returns 0 → success
  - linux fallback: windows fails (non-symbol), linux succeeds
  - missing symbols: stderr matches one of the symbol-failure
    patterns → remediation message points at the symbols-zip URL
  - vol not found: ``VolNotFoundError`` short-circuits with a
    helpful remediation
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from server.runners.local import VolNotFoundError
from sift_guard.preflight import preflight_check_image


_VALID_IMAGE = "/case/evidence/Rocba-Memory.raw"


def _run_result(returncode: int, stdout: str = "", stderr: str = ""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def test_windows_info_happy_path():
    win_stdout = (
        "Variable\tValue\n"
        "NtSystemRoot\tC:\\Windows\n"
        "NtProductType\tWinNt\n"
        "NTBuildLab\t19041.1.amd64fre.vb_release.191206-1406\n"
        "Major/Minor\t10/0\n"
    )
    with (
        patch("sift_guard.preflight.resolve_vol_bin", return_value="/usr/bin/vol"),
        patch("sift_guard.preflight.subprocess.run") as mock_run,
    ):
        mock_run.return_value = _run_result(0, stdout=win_stdout)
        result = preflight_check_image(_VALID_IMAGE)
    assert result.success is True
    assert result.os_family == "windows"
    assert result.os_version is not None
    assert "Windows" in result.os_version
    assert mock_run.call_count == 1  # linux probe never ran


def test_linux_fallback_when_windows_fails_for_non_symbol_reason():
    lin_stdout = "Linux version 5.15.0-91-generic (build-001) #101-Ubuntu SMP\n"
    with (
        patch("sift_guard.preflight.resolve_vol_bin", return_value="/usr/bin/vol"),
        patch("sift_guard.preflight.subprocess.run") as mock_run,
    ):
        mock_run.side_effect = [
            _run_result(2, stderr="No translation layer available"),
            _run_result(0, stdout=lin_stdout),
        ]
        result = preflight_check_image(_VALID_IMAGE)
    assert result.success is True
    assert result.os_family == "linux"
    assert result.os_version == "Linux 5.15.0-91-generic"
    assert mock_run.call_count == 2


def test_missing_symbols_emits_remediation():
    err = "ERROR: KdDebuggerDataBlock not found in the symbol table\n"
    with (
        patch("sift_guard.preflight.resolve_vol_bin", return_value="/usr/bin/vol"),
        patch("sift_guard.preflight.subprocess.run") as mock_run,
    ):
        mock_run.return_value = _run_result(1, stderr=err)
        result = preflight_check_image(_VALID_IMAGE)
    assert result.success is False
    assert result.missing_symbols is True
    assert result.os_family == "windows"
    assert result.remediation is not None
    assert "symbol" in result.remediation.lower()
    assert "downloads.volatilityfoundation.org" in result.remediation


def test_vol_not_found_short_circuits():
    with patch(
        "sift_guard.preflight.resolve_vol_bin",
        side_effect=VolNotFoundError("vol not found on PATH"),
    ):
        result = preflight_check_image(_VALID_IMAGE)
    assert result.success is False
    assert result.os_family == "unknown"
    assert result.error_message == "vol not found on PATH"
    assert result.remediation is not None
    assert "Volatility" in result.remediation


def test_subprocess_timeout_falls_through_to_unknown():
    with (
        patch("sift_guard.preflight.resolve_vol_bin", return_value="/usr/bin/vol"),
        patch(
            "sift_guard.preflight.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="vol", timeout=1),
        ),
    ):
        result = preflight_check_image(_VALID_IMAGE, timeout_seconds=1)
    assert result.success is False
    assert result.os_family == "unknown"
