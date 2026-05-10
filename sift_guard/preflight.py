"""Local Volatility OS / symbol-pack pre-flight probe.

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

`vol` is invoked via ``subprocess.run`` against an absolute path on
the local host. Auto-detection order:

  1. ``SIFT_VOL_PATH`` env var (explicit override)
  2. ``shutil.which("vol")``
  3. ``shutil.which("vol.py")``

This is independent of the orchestrator's transport: even if the
loop dispatches Volatility calls to a SIFT VM over SSH (the main
branch's default), the pre-flight is a local courtesy and does not
need to share the runner module.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


SIFT_VOL_PATH_ENV = "SIFT_VOL_PATH"


class VolNotFoundError(RuntimeError):
    """Raised when ``vol`` cannot be located on PATH and no
    ``SIFT_VOL_PATH`` override is set. Sanitized message — safe to
    surface to operators."""


def resolve_vol_bin() -> str:
    """Locate the local ``vol`` binary.

    Resolution order:
      1. ``SIFT_VOL_PATH`` env var (explicit override)
      2. ``shutil.which("vol")``
      3. ``shutil.which("vol.py")``
    """
    override = os.environ.get(SIFT_VOL_PATH_ENV)
    if override:
        path = Path(override)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise VolNotFoundError(
            f"SIFT_VOL_PATH={override!r} is not an executable file"
        )
    for candidate in ("vol", "vol.py"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise VolNotFoundError(
        "vol not found on PATH; install Volatility 3 or set SIFT_VOL_PATH"
    )


@dataclass
class OsDetectionResult:
    """Outcome of a single image's OS probe."""

    image_path: str
    success: bool
    os_family: str
    os_version: str | None
    missing_symbols: bool
    error_message: str | None
    remediation: str | None


_SYMBOL_FAILURE_PATTERNS: tuple[str, ...] = (
    "KdDebuggerDataBlock",
    "Unable to find a Symbol Table",
    "no suitable kernel offset",
    "KASLR offset",
    "KdVersionBlock",
    "could not be found",
    "Cannot find symbol",
)

_WINDOWS_VERSION_RE = re.compile(
    r"(?:NtBuildLab|NTBuildLab)\s*[:\s]+(?P<version>[\w._\-]+)"
)
_WINDOWS_OS_PRODUCT_RE = re.compile(r"(?:NtProductType|ProductType)\s*[:\s]+(\w+)")
_LINUX_KERNEL_RE = re.compile(r"Linux version\s+([\w.\-+]+)")


def _run_vol_info_plugin(
    vol_bin: str, image_path: str, plugin: str, timeout_seconds: int
) -> tuple[bool, str, str]:
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


def _build_remediation(image_path: str) -> str:
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
    the error / remediation strings to the operator and decides
    whether to skip the image or abort the run.
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
            remediation=_build_remediation(image_path),
        )

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
            remediation=_build_remediation(image_path),
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


__all__ = [
    "OsDetectionResult",
    "VolNotFoundError",
    "preflight_check_image",
    "resolve_vol_bin",
]
