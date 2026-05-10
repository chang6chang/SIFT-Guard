"""SSH-based Volatility 3 runner — alternative transport for split-VM setups.

This is the legacy dev/CI path: the MCP server runs on one host (often
a WSL2 / macOS / Linux developer machine) and Volatility runs inside a
SIFT VM at host:2222 → guest:22. ``run_vol_plugin`` shells out to
``ssh ... vol -f <image> -r json <plugin>``.

In enterprise mode (SIFT-Guard installed on the SIFT VM itself,
analyzing local evidence) prefer ``server.runners.local`` — there is
no host/VM split, no path translation, and no SSH dependency.

Per Hard Rule "no execute_shell": this module is internal to the
server process, NOT an MCP tool. The MCP tool layer wraps
``run_vol_plugin`` and exposes only typed, plugin-specific functions
(e.g. ``vol_pslist``) — the agent never names a plugin via free-form
input. The regex on ``plugin_name`` here is defense-in-depth, not the
primary boundary.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time


# Re-export the snake_case parsers from the local runner. They are
# pure functions over Volatility 3's JSON output and identical
# regardless of whether ``vol`` ran locally or over SSH.
from server.runners.local import (  # noqa: F401 — re-exported
    parse_cmdline_json,
    parse_malfind_json,
    parse_netscan_json,
    parse_pstree_json,
    parse_volatility_json,
)


SIFT_VM_USER = os.environ.get("SIFT_VM_USER", "sansforensics")
SIFT_VM_SSH_PORT = os.environ.get("SIFT_VM_SSH_PORT", "2222")
SIFT_VM_VOL_BIN = os.environ.get("SIFT_VM_VOL_BIN", "vol")
SIFT_VM_EVIDENCE_PREFIX = os.environ.get("SIFT_VM_EVIDENCE_PREFIX", "/mnt/rocba")
# Volatility 3's CLI has no --version flag; the version lives in
# ``volatility3.framework.constants.PACKAGE_VERSION`` and is read by
# running the VM's vol-venv Python interpreter. SIFT layout:
# ``/usr/local/bin/vol`` → ``/opt/volatility3/bin/vol``.
SIFT_VM_VOL_PYTHON = os.environ.get("SIFT_VM_VOL_PYTHON", "/opt/volatility3/bin/python3")


def _detect_default_gateway() -> str:
    """Return the WSL2 default-route gateway.

    VirtualBox port-forwards the SIFT VM to host:2222. On WSL2 the
    default route's gateway is the Windows host that VirtualBox runs
    on, so reaching it lets SSH land in the guest.
    """
    try:
        result = subprocess.run(
            ["sh", "-c", "ip route show | grep -i default | awk '{print $3}'"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError,
    ) as exc:
        raise RuntimeError(
            "Could not detect SIFT_VM_HOST: set the SIFT_VM_HOST env var or fix your default route"
        ) from exc
    host = result.stdout.strip()
    if not host:
        raise RuntimeError(
            "Could not detect SIFT_VM_HOST: set the SIFT_VM_HOST env var or fix your default route"
        )
    return host


SIFT_VM_HOST = os.environ.get("SIFT_VM_HOST") or _detect_default_gateway()


_PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9]*$")


_VERSION_PROBE_SCRIPT = (
    "from volatility3.framework import constants; print(constants.PACKAGE_VERSION)"
)


def get_vol_version(timeout_seconds: int = 10) -> str:
    """Capture the Volatility 3 PACKAGE_VERSION from the SIFT VM via SSH.

    Returns the bare version string (e.g. ``"2.27.0"``).
    """
    remote_cmd = f"{shlex.quote(SIFT_VM_VOL_PYTHON)} -c {shlex.quote(_VERSION_PROBE_SCRIPT)}"
    argv = [
        "ssh",
        "-p",
        SIFT_VM_SSH_PORT,
        f"{SIFT_VM_USER}@{SIFT_VM_HOST}",
        remote_cmd,
    ]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
    )
    return result.stdout.strip()


def run_vol_plugin(
    plugin_name: str,
    image_path_in_vm: str,
    timeout_seconds: int = 300,
) -> tuple[str, str, float]:
    """Run a Volatility 3 plugin over SSH against the SIFT VM.

    Args:
        plugin_name: Volatility plugin identifier, e.g.
            ``windows.pslist.PsList``. Must match the
            ``lower.lower.PascalCase`` regex.
        image_path_in_vm: absolute path to the memory image as
            visible from inside the VM. Must live under
            ``SIFT_VM_EVIDENCE_PREFIX``.
        timeout_seconds: subprocess timeout. Default 300s.

    Returns:
        ``(stdout, command_string, runtime_seconds)``.
    """
    if not _PLUGIN_NAME_RE.match(plugin_name):
        raise ValueError("plugin_name failed validation")

    prefix = SIFT_VM_EVIDENCE_PREFIX.rstrip("/")
    if image_path_in_vm != prefix and not image_path_in_vm.startswith(prefix + "/"):
        raise ValueError("image_path_in_vm is outside SIFT_VM_EVIDENCE_PREFIX")

    argv = [
        "ssh",
        "-p",
        SIFT_VM_SSH_PORT,
        f"{SIFT_VM_USER}@{SIFT_VM_HOST}",
        SIFT_VM_VOL_BIN,
        "-f",
        image_path_in_vm,
        "-r",
        "json",
        plugin_name,
    ]

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


__all__ = [
    "SIFT_VM_EVIDENCE_PREFIX",
    "SIFT_VM_HOST",
    "SIFT_VM_SSH_PORT",
    "SIFT_VM_USER",
    "SIFT_VM_VOL_BIN",
    "SIFT_VM_VOL_PYTHON",
    "get_vol_version",
    "parse_cmdline_json",
    "parse_malfind_json",
    "parse_netscan_json",
    "parse_pstree_json",
    "parse_volatility_json",
    "run_vol_plugin",
]
