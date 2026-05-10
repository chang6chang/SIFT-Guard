"""Pre-analysis OS / symbol availability probe for memory images.

Goal: catch missing Volatility symbol packs *before* dispatching the
analyst subagents. A missing Windows-build symbol pack causes every
plugin to fail with the same opaque ``KdDebuggerDataBlock not found``
error; surfacing the diagnostic up-front saves an entire run's worth
of token cost.

The probe runs ``vol -f <image> windows.info.Info`` first; if that
returns a non-zero exit and stderr matches one of the known
no-symbols / wrong-OS patterns, it falls back to
``linux.info.Info``. Either way we capture and parse the OS string
so the CLI can render it on the inventory table.

This module is part of ``sift-guard`` (the user-facing CLI), not the
MCP server. The agent never calls it directly — the orchestrator's
analyst-dispatch path uses ``vol_pslist`` and friends, which do
their own OS detection on first call. This is a pre-flight courtesy.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from server.runners.local import VolNotFoundError, resolve_vol_bin


@dataclass
class OsDetectionResult:
    """Outcome of a single image's OS probe.

    `os_family` is ``"windows"`` / ``"linux"`` / ``"unknown"``;
    `os_version` is the human-readable Volatility-reported string
    (``"Windows 10 x64"``, ``"Linux 5.15.0"``, etc.) when probe
    succeeded.

    `success=False` with `missing_symbols=True` is the actionable
    case: the operator needs to install a symbol pack. The
    `remediation` field carries a one-line fix the CLI prints.
    """

    image_path: str
    success: bool
    os_family: str
    os_version: str | None
    missing_symbols: bool
    error_message: str | None
    remediation: str | None


# Known stderr substrings indicating a symbol-pack mismatch. Vol3
# raises one of these from various plugins when the matching .json.xz
# pack is absent from the symbols dir.
_SYMBOL_FAILURE_PATTERNS: tuple[str, ...] = (
    "KdDebuggerDataBlock",
    "Unable to find a Symbol Table",
    "no suitable kernel offset",
    "KASLR offset",
    "KdVersionBlock",
    "could not be found",
    "Cannot find symbol",
)

# Vol3's stdout for windows.info.Info has a "NTBuildLab" or "Major/Minor"
# pair we can pull a friendly name out of. Same for linux.info.Info.
_WINDOWS_VERSION_RE = re.compile(
    r"(?:NtBuildLab|NTBuildLab)\s*[:\s]+(?P<version>[\w._\-]+)"
)
_WINDOWS_OS_PRODUCT_RE = re.compile(r"(?:NtProductType|ProductType)\s*[:\s]+(\w+)")
_LINUX_KERNEL_RE = re.compile(r"Linux version\s+([\w.\-+]+)")


def _run_vol_info_plugin(
    vol_bin: str, image_path: str, plugin: str, timeout_seconds: int
) -> tuple[bool, str, str]:
    """Return ``(returncode_zero, stdout, stderr)`` for one info probe.

    Uses ``-r pretty`` so the human-readable text is what we parse.
    Vol3's JSON renderer would also work here but the pretty output
    is what every existing how-to documents.
    """
    argv = [vol_bin, "-f", image_path, plugin]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "", "vol invocation timed out"
    except OSError as exc:
        return False, "", f"vol invocation failed to start: {exc}"
    return result.returncode == 0, result.stdout or "", result.stderr or ""


def _stderr_matches_symbol_failure(stderr: str) -> bool:
    return any(pattern in stderr for pattern in _SYMBOL_FAILURE_PATTERNS)


def _build_remediation(image_path: str, stderr: str) -> str:
    """Compose a one-line remediation message for the operator."""
    name = Path(image_path).name
    return (
        f"Missing Volatility symbols for {name}. Install a matching "
        "symbol pack: download "
        "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip "
        "(or linux.zip) and unzip into the directory pointed at by "
        "VOLATILITY3_SYMBOL_DIRS or volatility3/symbols/."
    )


def _parse_windows_version(stdout: str) -> str | None:
    m = _WINDOWS_VERSION_RE.search(stdout)
    if m:
        version = m.group("version")
        product_match = _WINDOWS_OS_PRODUCT_RE.search(stdout)
        if product_match:
            return f"Windows ({product_match.group(1)}) {version}"
        return f"Windows {version}"
    if "Windows" in stdout:
        return "Windows (version not parsed)"
    return None


def _parse_linux_version(stdout: str) -> str | None:
    m = _LINUX_KERNEL_RE.search(stdout)
    if m:
        return f"Linux {m.group(1)}"
    if "Linux" in stdout:
        return "Linux (version not parsed)"
    return None


def preflight_check_image(
    image_path: str | Path,
    *,
    timeout_seconds: int = 600,
) -> OsDetectionResult:
    """Probe a memory image's OS and symbol availability.

    Returns an `OsDetectionResult`; never raises. The CLI surfaces
    the error/remediation strings to the operator and decides whether
    to skip the image or abort the run.
    """
    image_path = str(image_path)
    try:
        vol_bin = resolve_vol_bin()
    except VolNotFoundError as exc:
        return OsDetectionResult(
            image_path=image_path,
            success=False,
            os_family="unknown",
            os_version=None,
            missing_symbols=False,
            error_message=str(exc),
            remediation="Install Volatility 3 (`pip install volatility3`) or set SIFT_VOL_PATH",
        )

    win_ok, win_stdout, win_stderr = _run_vol_info_plugin(
        vol_bin, image_path, "windows.info.Info", timeout_seconds
    )
    if win_ok:
        version = _parse_windows_version(win_stdout)
        return OsDetectionResult(
            image_path=image_path,
            success=True,
            os_family="windows",
            os_version=version,
            missing_symbols=False,
            error_message=None,
            remediation=None,
        )

    if _stderr_matches_symbol_failure(win_stderr):
        return OsDetectionResult(
            image_path=image_path,
            success=False,
            os_family="windows",
            os_version=None,
            missing_symbols=True,
            error_message=win_stderr.strip().splitlines()[-1] if win_stderr.strip() else None,
            remediation=_build_remediation(image_path, win_stderr),
        )

    # windows.info.Info failed for non-symbol reasons → likely Linux.
    lin_ok, lin_stdout, lin_stderr = _run_vol_info_plugin(
        vol_bin, image_path, "linux.info.Info", timeout_seconds
    )
    if lin_ok:
        version = _parse_linux_version(lin_stdout)
        return OsDetectionResult(
            image_path=image_path,
            success=True,
            os_family="linux",
            os_version=version,
            missing_symbols=False,
            error_message=None,
            remediation=None,
        )

    if _stderr_matches_symbol_failure(lin_stderr):
        return OsDetectionResult(
            image_path=image_path,
            success=False,
            os_family="linux",
            os_version=None,
            missing_symbols=True,
            error_message=lin_stderr.strip().splitlines()[-1] if lin_stderr.strip() else None,
            remediation=_build_remediation(image_path, lin_stderr),
        )

    last_stderr = lin_stderr or win_stderr
    return OsDetectionResult(
        image_path=image_path,
        success=False,
        os_family="unknown",
        os_version=None,
        missing_symbols=False,
        error_message=last_stderr.strip().splitlines()[-1] if last_stderr.strip() else None,
        remediation=(
            "vol could not identify the image. Verify the file is a "
            "memory image (LiME / raw / vmem) and that the matching "
            "Volatility symbol packs are installed."
        ),
    )


__all__ = ["OsDetectionResult", "preflight_check_image"]
