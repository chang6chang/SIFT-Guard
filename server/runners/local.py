"""Local Volatility 3 runner — the default transport in enterprise mode.

The MCP server runs on the same host where the evidence lives, so
`vol` is invoked directly via ``subprocess.run`` against an absolute
path. No SSH, no path translation, no host/VM split.

The companion module ``server.runners.ssh_remote`` provides an
alternative SSH-based runner for split-VM dev setups; both modules
expose the same ``run_vol_plugin`` / ``get_vol_version`` /
``parse_*`` surface so callers can swap transports without changing
their pipeline.

Auto-detection
--------------

The ``vol`` binary is resolved in this order:

  1. ``SIFT_VOL_PATH`` env var (explicit override)
  2. ``shutil.which("vol")``
  3. ``shutil.which("vol.py")``

If none of the above resolves, ``run_vol_plugin`` raises a
``VolNotFoundError`` with a clear remediation message — the
top-level CLI catches this and prints an installation hint.

Volatility 3's CLI has no ``--version`` flag (verified empirically
against the SIFT 2026.1 build). The version lives in
``volatility3.framework.constants.PACKAGE_VERSION`` and is read by
running the same Python interpreter that ``vol``'s shebang line
points at. ``SIFT_VOL_PYTHON`` overrides the auto-detection.

Per Hard Rule "no execute_shell": this module is internal to the
server process, NOT an MCP tool. The MCP tool layer wraps
``run_vol_plugin`` and exposes only typed, plugin-specific functions
(e.g. ``vol_pslist``) — the agent never names a plugin via
free-form input. The regex on ``plugin_name`` here is
defense-in-depth, not the primary boundary.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


SIFT_VOL_PATH_ENV = "SIFT_VOL_PATH"
SIFT_VOL_PYTHON_ENV = "SIFT_VOL_PYTHON"


_PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9]*$")

_VERSION_PROBE_SCRIPT = (
    "from volatility3.framework import constants; print(constants.PACKAGE_VERSION)"
)


class VolNotFoundError(RuntimeError):
    """Raised when ``vol`` cannot be located on PATH and no
    ``SIFT_VOL_PATH`` override is set.

    Sanitized: the message is generic so the rejection is safe to
    surface up the MCP tool layer without leaking host paths.
    """


def resolve_vol_bin() -> str:
    """Locate the local ``vol`` binary.

    Resolution order:
      1. ``SIFT_VOL_PATH`` env var (explicit override)
      2. ``shutil.which("vol")``
      3. ``shutil.which("vol.py")``

    Returns the absolute path to the resolved binary. Raises
    ``VolNotFoundError`` if none of the candidates resolves to an
    executable file.
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


def _resolve_vol_python(vol_bin: str) -> str:
    """Locate the Python interpreter that imports ``volatility3``.

    Order:
      1. ``SIFT_VOL_PYTHON`` env var (explicit override)
      2. The interpreter named in ``vol``'s shebang line, when that
         shebang is a regular ``#!/path/to/python`` form.
      3. ``sys.executable`` (the interpreter running the MCP server).

    The third fallback only succeeds when ``volatility3`` is
    importable from the server's own venv — usually true in the
    "all on one host" enterprise topology this runner is built for.
    """
    override = os.environ.get(SIFT_VOL_PYTHON_ENV)
    if override:
        return override
    try:
        with open(vol_bin, "rb") as f:
            head = f.read(256)
    except OSError:
        return sys.executable
    if not head.startswith(b"#!"):
        return sys.executable
    line = head.split(b"\n", 1)[0][2:].decode("utf-8", errors="replace").strip()
    parts = line.split()
    if not parts:
        return sys.executable
    interp = parts[0]
    if interp.endswith("env") and len(parts) >= 2:
        return parts[1]
    return interp


def get_vol_version(timeout_seconds: int = 10) -> str:
    """Capture the Volatility 3 ``PACKAGE_VERSION`` constant.

    Volatility 3's CLI has no ``--version`` / ``-V`` flag. We run
    the interpreter that imports ``volatility3`` and read
    ``constants.PACKAGE_VERSION``. Returns the bare version string
    (e.g. ``"2.27.0"``).

    Audit-friendly: every fresh tool call writes the captured
    version into the resulting extraction record, so the on-disk
    artifacts are reproducibly tagged with the Volatility version
    that produced them.
    """
    vol_bin = resolve_vol_bin()
    vol_python = _resolve_vol_python(vol_bin)
    result = subprocess.run(
        [vol_python, "-c", _VERSION_PROBE_SCRIPT],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
    )
    return result.stdout.strip()


def run_vol_plugin(
    plugin_name: str,
    image_path: str,
    timeout_seconds: int = 300,
) -> tuple[str, str, float]:
    """Run a Volatility 3 plugin locally against the given image path.

    Args:
        plugin_name: Volatility plugin identifier, e.g.
            ``windows.pslist.PsList``. Must match the
            three-segment ``lower.lower.PascalCase`` pattern. The
            regex rejects every shell metacharacter — see the
            security note below.
        image_path: absolute path to the memory image. The caller
            (a tier-1 MCP tool wrapper) has already validated the
            path is the registered evidence's ``absolute_path`` and
            confined under ``<case_dir>/evidence/``; this runner
            does no further path validation.
        timeout_seconds: subprocess timeout. Default 300s; tier-1
            wrappers override for slower plugins.

    Returns:
        ``(stdout, command_string, runtime_seconds)``.

    Raises:
        ValueError: ``plugin_name`` fails the regex.
        VolNotFoundError: ``vol`` could not be located.
        subprocess.CalledProcessError: ``vol`` returned non-zero.
        subprocess.TimeoutExpired: the run exceeded
            ``timeout_seconds``.

    Security: ``plugin_name`` is regex-validated to a Volatility
    plugin path with no shell metacharacters. The command is
    constructed as a list (not a string) and passed to
    ``subprocess.run`` with ``shell=False`` so there is no shell
    interpolation risk. The ``command_string`` returned for audit
    purposes is ``shlex.join`` of the same arg list — purely
    cosmetic, never re-executed.
    """
    if not _PLUGIN_NAME_RE.match(plugin_name):
        # Sanitized: never echo the offending input back. Caller
        # (the MCP tool wrapper) is the one whose error string the
        # agent sees.
        raise ValueError("plugin_name failed validation")

    vol_bin = resolve_vol_bin()
    argv = [vol_bin, "-f", image_path, "-r", "json", plugin_name]

    start = time.monotonic()
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
    )
    elapsed = time.monotonic() - start

    return result.stdout, shlex.join(argv), elapsed


# ---------------------------------------------------------------------------
# Volatility 3 → snake_case parsers. These are pure functions, so the
# SSH runner module re-exports them rather than duplicating the
# field-name maps. ``server.runners.ssh_remote`` does
# ``from server.runners.local import parse_volatility_json, ...``.
# ---------------------------------------------------------------------------


_EPROCESS_FIELD_MAP = {
    "PID": "pid",
    "PPID": "ppid",
    "ImageFileName": "image_file_name",
    "Offset(V)": "offset_v",
    "Threads": "threads",
    "Handles": "handles",
    "SessionId": "session_id",
    "Wow64": "wow64",
    "CreateTime": "create_time",
    "ExitTime": "exit_time",
}


def parse_volatility_json(stdout: str) -> list[dict]:
    """Parse a Volatility 3 EPROCESS-row JSON output into snake_case dicts.

    Used by both ``windows.pslist.PsList`` and
    ``windows.psscan.PsScan``; their JSON shape is empirically
    identical (Vol 3 2.27.0). Drops ``File output``, ``__children``,
    and any other unknown keys (forward-compat against future
    Volatility releases adding fields).
    """
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")

    rows: list[dict] = []
    for row in raw:
        mapped: dict = {}
        for vol_key, schema_key in _EPROCESS_FIELD_MAP.items():
            if vol_key in row:
                mapped[schema_key] = row[vol_key]
        rows.append(mapped)
    return rows


_PSTREE_FIELD_MAP = {
    **_EPROCESS_FIELD_MAP,
    "Audit": "audit",
    "Cmd": "cmd",
    "Path": "path",
}


def _map_pstree_node(node: dict) -> dict:
    """Map one pstree JSON node to ProcessTreeRecord-shaped kwargs.

    Recurses into ``__children`` so the caller receives a single
    dict suitable for ``ProcessTreeRecord(**d)`` construction.
    """
    mapped: dict = {}
    for vol_key, schema_key in _PSTREE_FIELD_MAP.items():
        if vol_key in node:
            mapped[schema_key] = node[vol_key]
    children_raw = node.get("__children") or []
    mapped["children"] = [_map_pstree_node(c) for c in children_raw]
    return mapped


def parse_pstree_json(stdout: str) -> list[dict]:
    """Parse Volatility 3 pstree JSON output into the recursive
    snake_case shape the schema expects."""
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")
    return [_map_pstree_node(node) for node in raw]


_NETSCAN_FIELD_MAP = {
    "Proto": "proto",
    "LocalAddr": "local_addr",
    "LocalPort": "local_port",
    "ForeignAddr": "foreign_addr",
    "ForeignPort": "foreign_port",
    "State": "state",
    "PID": "pid",
    "Owner": "owner",
    "Offset": "offset",
    "Created": "created",
}


def parse_netscan_json(stdout: str) -> list[dict]:
    """Parse Volatility 3 netscan JSON output into snake_case dicts."""
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")

    rows: list[dict] = []
    for row in raw:
        mapped: dict = {}
        for vol_key, schema_key in _NETSCAN_FIELD_MAP.items():
            if vol_key in row:
                mapped[schema_key] = row[vol_key]
        rows.append(mapped)
    return rows


_CMDLINE_FIELD_MAP = {
    "PID": "pid",
    "Process": "process_name",
    "Args": "cmdline",
}


def parse_cmdline_json(stdout: str) -> list[dict]:
    """Parse Volatility 3 cmdline JSON output into snake_case dicts."""
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")

    rows: list[dict] = []
    for row in raw:
        mapped: dict = {}
        for vol_key, schema_key in _CMDLINE_FIELD_MAP.items():
            if vol_key in row:
                mapped[schema_key] = row[vol_key]
        rows.append(mapped)
    return rows


_MALFIND_FIELD_MAP = {
    "PID": "pid",
    "Process": "process_name",
    "Start VPN": "vad_start",
    "Tag": "vad_tag",
    "Protection": "protection",
    "Hexdump": "hex_dump",
    "Disasm": "disassembly",
}


def parse_malfind_json(stdout: str) -> list[dict]:
    """Parse Volatility 3 malfind JSON output into snake_case dicts."""
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")

    rows: list[dict] = []
    for row in raw:
        mapped: dict = {}
        for vol_key, schema_key in _MALFIND_FIELD_MAP.items():
            if vol_key in row:
                mapped[schema_key] = row[vol_key]
        rows.append(mapped)
    return rows


__all__ = [
    "SIFT_VOL_PATH_ENV",
    "SIFT_VOL_PYTHON_ENV",
    "VolNotFoundError",
    "get_vol_version",
    "parse_cmdline_json",
    "parse_malfind_json",
    "parse_netscan_json",
    "parse_pstree_json",
    "parse_volatility_json",
    "resolve_vol_bin",
    "run_vol_plugin",
]
