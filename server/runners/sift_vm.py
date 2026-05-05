"""SSH-based Volatility 3 runner for the SIFT VM.

The MCP server runs in WSL2 on the host; Volatility 3 runs inside the
SIFT VM on a VirtualBox guest with a port-forward at host:2222 -> guest:22.
This module shells out to `ssh ... vol -f <image> -r json <plugin>` and
returns the captured stdout for downstream parsing.

Per Hard Rule "no execute_shell": this module is internal to the server
process, NOT an MCP tool. The MCP tool layer wraps `run_vol_plugin` and
exposes only typed, plugin-specific functions (e.g. memory_pslist) — the
agent never names a plugin via free-form input. The regex on plugin_name
here is defense-in-depth, not the primary boundary.

Per the 2026-05-05 decisions-log "dev-convenience SSH + sudo access"
entry: this SSH-based transport is the development setup. Before
submission it must be replaced with an in-VM MCP server transport so
operators are not asked to grant the agent shell access. That migration
should not require touching this module's callers — `run_vol_plugin`'s
signature is the seam.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time


SIFT_VM_USER = os.environ.get("SIFT_VM_USER", "sansforensics")
SIFT_VM_SSH_PORT = os.environ.get("SIFT_VM_SSH_PORT", "2222")
SIFT_VM_VOL_BIN = os.environ.get("SIFT_VM_VOL_BIN", "vol")
SIFT_VM_EVIDENCE_PREFIX = os.environ.get("SIFT_VM_EVIDENCE_PREFIX", "/mnt/rocba")
# Volatility 3's CLI has no --version flag (verified empirically against
# the SIFT 2026.1 build). The version lives in
# `volatility3.framework.constants.PACKAGE_VERSION`, which can only be
# read by running the vol venv's Python interpreter directly. Default
# matches the SIFT layout where `/usr/local/bin/vol` is a symlink to
# `/opt/volatility3/bin/vol`. Override via env if your install differs.
SIFT_VM_VOL_PYTHON = os.environ.get(
    "SIFT_VM_VOL_PYTHON", "/opt/volatility3/bin/python3"
)


def _detect_default_gateway() -> str:
    """Return the WSL2 default-route gateway.

    VirtualBox port-forwards from the SIFT VM to this host:2222. On WSL2
    the default route's gateway is the Windows host that VirtualBox runs
    on, so reaching it lets the SSH connection land in the guest.
    """
    try:
        result = subprocess.run(
            ["sh", "-c", "ip route show | grep -i default | awk '{print $3}'"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, OSError) as exc:
        raise RuntimeError(
            "Could not detect SIFT_VM_HOST: set the SIFT_VM_HOST env var "
            "or fix your default route"
        ) from exc
    host = result.stdout.strip()
    if not host:
        raise RuntimeError(
            "Could not detect SIFT_VM_HOST: set the SIFT_VM_HOST env var "
            "or fix your default route"
        )
    return host


SIFT_VM_HOST = os.environ.get("SIFT_VM_HOST") or _detect_default_gateway()


# Three dot-separated segments. The second segment is lowercase per the
# Volatility 3 plugin path convention (`windows.pslist.PsList`,
# `windows.netscan.NetScan`); only the leaf class name is PascalCase.
# This shape rejects shell metacharacters (`;`, `&`, `|`, `$`, `` ` ``,
# spaces, slashes) by construction — the regex's character classes
# never admit them.
_PLUGIN_NAME_RE = re.compile(
    r'^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9]*$'
)


_VERSION_PROBE_SCRIPT = (
    "from volatility3.framework import constants; "
    "print(constants.PACKAGE_VERSION)"
)


def get_vol_version(timeout_seconds: int = 10) -> str:
    """Capture the Volatility 3 PACKAGE_VERSION from the SIFT VM via SSH.

    Volatility 3's CLI has no ``--version`` / ``-V`` flag (verified
    empirically against the SIFT 2026.1 build); the version lives in
    ``volatility3.framework.constants.PACKAGE_VERSION``. We run the vol
    venv's Python interpreter (``SIFT_VM_VOL_PYTHON``) and read the
    constant.

    Returns the bare version string (e.g. ``"2.27.0"``) — what's
    actually captured from the source of truth, prefix-free. The
    audit log's ``tool_name`` supplies the rest of the context.

    The probe script contains a semicolon, so we hand SSH a single
    pre-quoted command string instead of an argv list — SSH joins the
    trailing argv with spaces and ships it to the remote shell, where
    an unquoted ``;`` would split the command. ``shlex.quote`` is
    defense-in-depth: every component is server-controlled, but
    quoting keeps the failure mode local if a future env override
    introduces a metacharacter.
    """
    remote_cmd = (
        f"{shlex.quote(SIFT_VM_VOL_PYTHON)} "
        f"-c {shlex.quote(_VERSION_PROBE_SCRIPT)}"
    )
    argv = [
        "ssh",
        "-p", SIFT_VM_SSH_PORT,
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
            ``windows.pslist.PsList``. Must match the plugin-name regex
            (three dot-separated segments, lowercase.module.PascalCase).
            The regex rejects every shell metacharacter — see security
            note below.
        image_path_in_vm: absolute path to the memory image as visible
            from inside the VM. Must be at, or below,
            ``SIFT_VM_EVIDENCE_PREFIX``. Otherwise raises ValueError.
        timeout_seconds: subprocess timeout. Default 300s. Volatility's
            first plugin run on a fresh image pays the symbol-resolution
            cost, which on Rocba is ~2-5 minutes.

    Returns:
        ``(stdout, command_string, runtime_seconds)``.

    Raises:
        ValueError: ``plugin_name`` fails the regex, or
            ``image_path_in_vm`` is outside the prefix.
        subprocess.CalledProcessError: ``vol`` returns nonzero.
        subprocess.TimeoutExpired: the run exceeds ``timeout_seconds``.

    Security: ``plugin_name`` is regex-validated to be a Volatility
    plugin path with no shell metacharacters. ``image_path_in_vm`` is
    prefix-checked against ``SIFT_VM_EVIDENCE_PREFIX``. The full SSH
    command is constructed as a list (not a string) and passed to
    ``subprocess.run`` with ``shell=False`` so there is no shell
    interpolation risk on the host. The ``command_string`` returned for
    audit purposes is ``shlex.join`` of the same arg list — purely
    cosmetic, never re-executed.
    """
    if not _PLUGIN_NAME_RE.match(plugin_name):
        # Sanitized: never echo the offending input back. Caller (the
        # MCP tool wrapper) is the one whose error string the agent
        # sees; keeping this internal message input-free means the tool
        # wrapper cannot accidentally leak by passing exc through.
        raise ValueError("plugin_name failed validation")

    prefix = SIFT_VM_EVIDENCE_PREFIX.rstrip("/")
    if image_path_in_vm != prefix and not image_path_in_vm.startswith(
        prefix + "/"
    ):
        raise ValueError("image_path_in_vm is outside SIFT_VM_EVIDENCE_PREFIX")

    argv = [
        "ssh",
        "-p", SIFT_VM_SSH_PORT,
        f"{SIFT_VM_USER}@{SIFT_VM_HOST}",
        SIFT_VM_VOL_BIN,
        "-f", image_path_in_vm,
        "-r", "json",
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


# Volatility 3 -> ProcessRecord field-name mapping. Volatility emits
# PascalCase plus quirks (`Offset(V)` with parens, `File output` with a
# space). Schema field names are snake_case. Listed explicitly so an
# unexpected new field in a future Volatility release silently drops
# out instead of poisoning the dict that `ProcessRecord(**d)` will
# consume — forward-compat with no version pin needed at the parser
# layer.
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

    Used by both ``windows.pslist.PsList`` and ``windows.psscan.PsScan``;
    their JSON shape is empirically identical (Vol 3 2.27.0 on Rocba —
    see PsscanResult docstring in server.schemas). Drops ``File output``,
    ``__children``, and any other unknown keys.

    Datetime strings are left as ISO strings — pydantic will parse them
    when the dict is fed to ``ProcessRecord(**d)``. Returns a list of
    dicts suitable for direct construction.

    Pstree's recursive shape is parsed by ``parse_pstree_json`` instead —
    its tree structure isn't a flat row list and it carries three extra
    fields (Audit, Cmd, Path) absent from pslist/psscan.
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


# Pstree adds three resolved-string fields beyond the EPROCESS basics:
# kernel-side image name (Audit), user-space path (Path), and command
# line (Cmd). Otherwise the per-node row shape is the same.
_PSTREE_FIELD_MAP = {
    **_EPROCESS_FIELD_MAP,
    "Audit": "audit",
    "Cmd": "cmd",
    "Path": "path",
}


def _map_pstree_node(node: dict) -> dict:
    """Map one pstree JSON node to ProcessTreeRecord-shaped kwargs.

    Recurses into ``__children`` so the caller receives a single dict
    suitable for ``ProcessTreeRecord(**d)`` construction. Unknown keys
    are dropped, matching the forward-compat stance in
    ``parse_volatility_json``.
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
    snake_case shape the schema expects.

    Pstree's top-level JSON is a list of root-or-orphan nodes; each
    node has ``__children`` recursively. This function preserves the
    tree (the validator's anchoring point) — flattening would erase
    parent-child relationships that the recursive schema captures.

    Returns a list of dicts. Each dict has the EPROCESS basics plus
    the three pstree-specific fields and a ``children`` list (possibly
    empty) of recursively-mapped child dicts.
    """
    raw = json.loads(stdout)
    if not isinstance(raw, list):
        raise ValueError("expected JSON array at top level")
    return [_map_pstree_node(node) for node in raw]


# Netscan emits a flat list, but its row shape is entirely different
# from EPROCESS — different keys, different semantics. Separate map
# rather than a parameterized parser: each plugin family's parser is
# small enough that a per-plugin function reads more cleanly than a
# meta-parser. If a fourth distinct shape lands, revisit.
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
    """Parse Volatility 3 netscan JSON output into snake_case dicts.

    Drops ``__children`` and any unknown keys (forward-compat). All
    four protocol families share the same field set on Vol 3 2.27.0,
    so a single mapping handles TCPv4 / TCPv6 / UDPv4 / UDPv6 — UDP
    records simply have ``State == ""`` and ``ForeignAddr == "*"``
    rather than a different field set, so no discriminated-union
    complexity at the schema layer.

    Datetime strings are left as ISO strings — pydantic parses them
    when the dict is fed to ``NetworkRecord(**d)``.
    """
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


__all__ = [
    "SIFT_VM_USER",
    "SIFT_VM_HOST",
    "SIFT_VM_SSH_PORT",
    "SIFT_VM_VOL_BIN",
    "SIFT_VM_VOL_PYTHON",
    "SIFT_VM_EVIDENCE_PREFIX",
    "get_vol_version",
    "parse_netscan_json",
    "parse_pstree_json",
    "parse_volatility_json",
    "run_vol_plugin",
]
