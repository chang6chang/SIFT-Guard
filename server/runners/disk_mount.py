"""Disk-image mount utility + subprocess runners for the four disk-side
tier-1 tools.

Mount utility (`mount_disk_image`) is internal to the server — it is
NOT exposed as an MCP tool. The disk tools call it on their first
invocation per (evidence_id, image format); subsequent calls reuse the
already-mounted path via the in-process mount cache.

Privilege model
---------------

`ewfmount` and `mount -o ro,loop` require either root, `CAP_SYS_ADMIN`,
or — for ewfmount specifically — membership in the `fuse` group (it is
FUSE-based). The MCP server runs as the invoking user. Three operating
modes are supported, in this resolution order:

  1. **Operator pre-mount (CI / dev / containers)** — set
     ``SIFT_DISK_PREMOUNTED_PATH=/mnt/sift_disk`` and the utility
     skips every shell-out, validates ``/proc/mounts`` shows the
     path is read-only, and returns it. The operator is responsible
     for the actual `ewfmount` / `mount -o ro,loop` step.

  2. **Real shell-out with fallback chain (default)** — when the
     env var is unset, the utility walks the per-format fallback
     chain below. Mount points live under
     ``/tmp/sift-guard-mounts/<evidence_id_short>/`` — predictable
     so the sudoers entry's wildcard (``umount
     /tmp/sift-guard-mounts/*``) scopes cleanly, and writable by
     the invoking user without elevation.

Per-format fallback chains
--------------------------

`.E01` / `.s01` / `.Ex01`:
  Path A (preferred): ``ewfmount <image> <ewf_dir>`` then
  ``mount -o ro,loop <ewf_dir>/ewf1 <mount>``. Each step tries the
  command directly first; on non-zero exit it retries via
  ``sudo -n`` (non-interactive — relies on the NOPASSWD sudoers
  entry installed by ``setup-sift-guard.sh``).

  Path B (fallback): ``guestmount --ro -a <image> -i <mount>``.
  libguestfs builds an in-process Linux VM that reads the E01
  directly via libewf; FUSE-mounted so no root required. Slower
  than Path A but the only option when ewfmount / mount-loop are
  both unavailable.

`.raw` / `.dd` / `.img`:
  Path A: ``mount -o ro,loop <image> <mount>`` — direct then
  ``sudo -n``.

  Path B: ``guestmount --ro -a <image> -i <mount>``.

`.vhdx` / `.vhd`:
  ``guestmount --ro -a <image> -i <mount>`` only. libguestfs
  natively reads VHDX/VHD; no Path A.

``/proc/mounts`` is re-validated after every successful mount: the
mount entry must include ``ro`` in its options. Any mismatch raises
``MountVerificationError`` and the partial mount is torn down. (For
guestmount the FUSE entry registers as ``fuse.guestmount`` with
``ro`` in its options when ``--ro`` was passed.)

Both modes are unit-test-friendly: tests set the env var to a
tmp_path the test pre-creates, plus monkeypatch
``_read_proc_mounts`` to make the path appear as a read-only mount
without root.

Per-tool runners
----------------

Four subprocess runner functions live in this module alongside the
mount utility because they all share the same "the mount has
already happened, here is the path; shell out to the SIFT-resident
tool" shape. Each returns ``(stdout, command_string,
runtime_seconds, tool_version)`` so the tier-1 wrapper can persist a
fully-provenanced result.

Verification notes (flagged for SIFT-2026.1 verification before the
first real disk-image run; see `docs/decisions-log.md` once
verified):

  - ``log2timeline.py --parsers mft`` is the plaso filter for the
    MFT-only parser. plaso ships ``mft`` as a stable parser
    identifier; verify by ``log2timeline.py --parsers list | grep
    mft`` on the SIFT VM.
  - ``psort.py -o json_line`` is plaso's documented JSON-line
    output format. Two-step pipeline (log2timeline → psort) is the
    actual plaso CLI shape; the user spec's single-step
    ``log2timeline.py -o json_line`` is incorrect — that flag
    belongs to psort. We run the two-step pipeline.
  - Prefetch parsing uses python-prefetch's programmatic
    ``prefetch.Prefetch`` class. Alternative on SIFT is ``pf2json``
    (CLI) — set ``SIFT_DISK_PREFETCH_CMD`` to override.
  - python-evtx ships ``evtx_dump.py`` for CLI XML dumping; we use
    its programmatic API to produce JSON-friendly per-record dicts.
  - RegRipper canonical CLI on SIFT is ``rip.pl -r <hive> -p
    <plugin>`` or ``-f <profile>``. The runner uses ``-f``
    profiles per-hive (``system``, ``software``, ``sam``, ``ntuser``).
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


SIFT_DISK_PREMOUNTED_PATH_ENV = "SIFT_DISK_PREMOUNTED_PATH"
SIFT_DISK_LOG2TIMELINE_BIN_ENV = "SIFT_DISK_LOG2TIMELINE_BIN"
SIFT_DISK_PSORT_BIN_ENV = "SIFT_DISK_PSORT_BIN"
SIFT_DISK_REGRIPPER_BIN_ENV = "SIFT_DISK_REGRIPPER_BIN"
SIFT_DISK_PREFETCH_CMD_ENV = "SIFT_DISK_PREFETCH_CMD"
SIFT_DISK_EVTX_DUMP_CMD_ENV = "SIFT_DISK_EVTX_DUMP_CMD"
SIFT_DISK_EWFMOUNT_BIN_ENV = "SIFT_DISK_EWFMOUNT_BIN"
SIFT_DISK_MOUNT_BIN_ENV = "SIFT_DISK_MOUNT_BIN"
SIFT_DISK_GUESTMOUNT_BIN_ENV = "SIFT_DISK_GUESTMOUNT_BIN"

# Defaults assume the SIFT 2026.1 image's `/usr/local/bin` PATH layout.
_DEFAULT_LOG2TIMELINE_BIN = "log2timeline.py"
_DEFAULT_PSORT_BIN = "psort.py"
_DEFAULT_REGRIPPER_BIN = "rip.pl"
_DEFAULT_EWFMOUNT_BIN = "ewfmount"
_DEFAULT_MOUNT_BIN = "mount"
_DEFAULT_GUESTMOUNT_BIN = "guestmount"
_DEFAULT_PREFETCH_CMD = "pf2json"
_DEFAULT_EVTX_DUMP_CMD = "evtx_dump.py"

# Per-hive RegRipper profile names. SIFT's RegRipper uses lowercase
# profile filenames in `/usr/share/regripper/plugins/`.
_REGRIPPER_PROFILE_FOR_HIVE: dict[str, str] = {
    "SYSTEM": "system",
    "SOFTWARE": "software",
    "SAM": "sam",
    "NTUSER.DAT": "ntuser",
}

# Relative paths under the mount root for each artifact family. The
# disk tools resolve these against the mount path returned by
# `mount_disk_image`.
RELATIVE_PREFETCH_DIR = "Windows/Prefetch"
RELATIVE_EVTX_DIR = "Windows/System32/winevt/Logs"
RELATIVE_REGISTRY_HIVES: dict[str, str] = {
    "SYSTEM": "Windows/System32/config/SYSTEM",
    "SOFTWARE": "Windows/System32/config/SOFTWARE",
    "SAM": "Windows/System32/config/SAM",
}
# NTUSER.DAT is per-user; the parser enumerates every Users/<name>/
# NTUSER.DAT it finds rather than expecting a single canonical path.

# In-process mount cache. Single-process server contract — see
# `server.audit` for the same assumption. Maps evidence_id to the
# resolved mount path so subsequent tool calls reuse the mount.
_MOUNT_CACHE: dict[str, str] = {}

# Cache of intermediate ewfmount FUSE dirs keyed by evidence_id, so
# the atexit teardown can fusermount them in reverse order of the
# loop-mount they back. ewf_dir is unmounted via `fusermount -u`.
_EWF_DIR_CACHE: dict[str, str] = {}

# Cache of guestmount FUSE mounts keyed by evidence_id, so the
# atexit teardown can `guestunmount` them. Tracked separately from
# `_MOUNT_CACHE` because guestmount + loop-mount tear down through
# different commands.
_GUESTMOUNT_CACHE: dict[str, str] = {}

# Track plaso work directories so they get reaped on shutdown.
# log2timeline.py writes ``out.plaso`` + ``out.jsonl`` into one of
# these; a partially-completed pass leaves the dir behind, and the
# 2026-05-13 SRL-v2 cleanup audit found ~210 MB of these accreted
# across three killed runs. The runner adds to this set in
# ``run_log2timeline_mft`` and the atexit hook clears it.
_PLASO_TEMP_DIRS: set[str] = set()

# Predictable mount base. Sudoers wildcards (`umount
# /tmp/sift-guard-mounts/*`) can scope cleanly against this; the
# directory lives under /tmp/ so the invoking user always has write
# permission without sudo.
_MOUNT_BASE = Path("/tmp/sift-guard-mounts")


class MountError(RuntimeError):
    """Mount setup or teardown failed.

    Sanitized: the message NEVER echoes the agent-supplied
    evidence_id or the absolute_path back. Operators see the
    rejection in the audit log; the agent sees a generic message.
    """


class MountVerificationError(MountError):
    """`/proc/mounts` post-condition check failed.

    Either the mount is missing entirely or its options do not
    include `ro`. Distinct subclass so test assertions can pin the
    exact failure mode.
    """


def _read_proc_mounts() -> str:
    """Return the contents of `/proc/mounts`.

    Wrapped so tests can monkeypatch it without faking subprocess.
    """
    return Path("/proc/mounts").read_text(encoding="utf-8")


def _is_path_mounted_readonly(mount_path: str) -> bool:
    """True iff `/proc/mounts` lists `mount_path` as a read-only mount.

    `/proc/mounts` lines look like:
      `/dev/loop1 /mnt/sift_disk ext4 ro,relatime 0 0`
    The second whitespace-separated field is the mount target; the
    fourth is a comma-separated options list. `ro` must be present
    in that options list.
    """
    target = mount_path.rstrip("/")
    for raw in _read_proc_mounts().splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        if parts[1].rstrip("/") != target:
            continue
        opts = parts[3].split(",")
        return "ro" in opts
    return False


def _detect_image_format(absolute_path: str) -> str:
    """Detect disk-image format by extension.

    Returns one of: ``e01``, ``raw``, ``vhdx``. Magic-byte detection
    happens at `register_evidence` time and stamps the artifact_class;
    here we just need to choose the right mount tool.
    """
    lower = absolute_path.lower()
    if lower.endswith((".e01", ".ex01", ".s01")):
        return "e01"
    if lower.endswith((".raw", ".dd", ".img")):
        return "raw"
    if lower.endswith((".vhdx", ".vhd")):
        return "vhdx"
    # Default to raw for unknown extensions — most likely a renamed
    # dd image. Operators with E01 / VHDX images should use the
    # canonical extensions.
    return "raw"


def _run_subprocess(argv: list[str], *, timeout_seconds: int = 60) -> tuple[str, str, float]:
    """Run a subprocess and return ``(stdout, command_string,
    runtime_seconds)``.

    Wraps the call in `shlex.join` for the audit-trail string. Never
    uses ``shell=True``. Failure modes (non-zero exit, timeout,
    OSError) all raise ``MountError`` with sanitized message — never
    echo `absolute_path` back at the agent.
    """
    start = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise MountError(f"subprocess {argv[0]!r} exited non-zero") from exc
    except subprocess.TimeoutExpired as exc:
        raise MountError(f"subprocess {argv[0]!r} timed out after {timeout_seconds}s") from exc
    except (OSError, FileNotFoundError) as exc:
        raise MountError(f"subprocess {argv[0]!r} could not be executed") from exc
    elapsed = time.monotonic() - start
    return result.stdout, shlex.join(argv), elapsed


def _allocate_mount_dir(evidence_id: str, suffix: str = "") -> Path:
    """Allocate a predictable mount directory under
    ``/tmp/sift-guard-mounts/<evidence_id_short>[<suffix>]/``.

    Predictable paths matter for the sudoers wildcard: an entry
    permitting ``umount /tmp/sift-guard-mounts/*`` scopes cleanly
    here, where ``tempfile.mkdtemp`` would produce
    randomly-suffixed names the sudoers rule could not anticipate.
    """
    _MOUNT_BASE.mkdir(parents=True, exist_ok=True)
    target = _MOUNT_BASE / f"{evidence_id[:8]}{suffix}"
    target.mkdir(parents=True, exist_ok=True)
    return target


def _is_path_mounted_anywhere(mount_path: str) -> bool:
    """True iff ``/proc/mounts`` has any entry for this path
    (read-only or read-write, fuse or block device).

    Distinct from ``_is_path_mounted_readonly`` which only matches
    ro entries: we use this for orphan detection where we don't yet
    know whether the existing mount is in a sane state, and don't
    care.
    """
    target = mount_path.rstrip("/")
    for raw in _read_proc_mounts().splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        if parts[1].rstrip("/") == target:
            return True
    return False


def _force_unmount(path: Path) -> bool:
    """Attempt to tear down whatever's mounted at ``path``.

    Tries ``fusermount -u`` first (works for ewfmount + guestmount
    fuse entries; user-mode), then ``sudo -n umount`` (loop-mounts;
    privileged via NOPASSWD sudoers wildcard). Returns True iff
    /proc/mounts shows ``path`` is no longer mounted at the end.

    Best-effort; swallows tool failures. The goal is to clear stale
    orphans from prior killed runs so a fresh mount can take the
    same predictable path. The 2026-05-13 SRL-v2 cleanup found
    three orphan fuse mounts (bed14651-ewf, 699521bf-ewf,
    093ec18c-ewf) blocking re-mount of the same evidence_id.
    """
    if not _is_path_mounted_anywhere(str(path)):
        return True

    # fusermount first — works without sudo for user-mode FUSE,
    # and the sudoers entry permits ``sudo -n fusermount -u
    # /tmp/sift-guard-mounts/*`` for root-owned ones.
    for argv in (
        ["fusermount", "-u", str(path)],
        ["sudo", "-n", "fusermount", "-u", str(path)],
        ["sudo", "-n", "umount", str(path)],
    ):
        try:
            subprocess.run(
                argv,
                capture_output=True,
                check=False,
                timeout=20,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if not _is_path_mounted_anywhere(str(path)):
            return True
    return False


def _clean_stale_mount_for(evidence_id: str, mount_dir: Path) -> None:
    """Tear down any orphan mount at the predictable paths for this
    evidence_id, before a fresh mount attempt.

    Two paths can hold orphans:
      * ``mount_dir`` — the final mount target (loop-mount target,
        or direct guestmount target).
      * ``mount_dir + "-ewf"`` — the ewfmount intermediate fuse
        mount used by the E01 fallback chain.

    A predecessor sift-guard run that died ungracefully (SIGKILL
    after timeout, ctrl-C during pre-extract, etc.) leaves those
    fuse mounts as root-owned orphans; subsequent runs collide on
    the predictable path. This function clears them so
    ``mount_disk_image`` can proceed.
    """
    ewf_intermediate = mount_dir.with_name(f"{mount_dir.name}-ewf")
    if _is_path_mounted_anywhere(str(mount_dir)):
        logger.info(
            "tearing down stale orphan mount at %s before remount", mount_dir
        )
        _force_unmount(mount_dir)
    if _is_path_mounted_anywhere(str(ewf_intermediate)):
        logger.info(
            "tearing down stale orphan ewfmount at %s before remount",
            ewf_intermediate,
        )
        _force_unmount(ewf_intermediate)


def cleanup_stale_mounts_globally() -> dict[str, int]:
    """Scan ``/tmp/sift-guard-mounts/`` and tear down every mount
    not held by the current process's in-memory caches.

    Returns ``{"cleaned": N, "remaining": M}`` so callers can decide
    whether to warn the operator. The 2026-05-13 SRL-v2 audit found
    three orphan fuse mounts surviving across run boundaries; this
    helper is what the pre-extract phase calls before kicking off
    plaso/regripper to ensure ``mount_disk_image`` won't hit the
    predictable-path collision.

    The function is safe to call multiple times — it only operates
    on paths that look like sift-guard mount points and never
    touches the operator's premounted-path env var.
    """
    if os.environ.get(SIFT_DISK_PREMOUNTED_PATH_ENV):
        # Operator-managed mount; do not touch.
        return {"cleaned": 0, "remaining": 0}

    known = set(_MOUNT_CACHE.values()) | set(_EWF_DIR_CACHE.values()) | set(_GUESTMOUNT_CACHE.values())
    cleaned = 0
    remaining = 0
    for raw in _read_proc_mounts().splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        path = parts[1].rstrip("/")
        if not path.startswith(str(_MOUNT_BASE) + "/"):
            continue
        if path in known:
            continue
        if _force_unmount(Path(path)):
            cleaned += 1
        else:
            remaining += 1
    return {"cleaned": cleaned, "remaining": remaining}


def _register_plaso_tempdir(path: Path) -> None:
    """Track a plaso work directory for the atexit reaper.

    Called by ``run_log2timeline_mft`` immediately after
    ``tempfile.mkdtemp(prefix="sift-plaso-")``. The atexit reaper
    walks ``_PLASO_TEMP_DIRS`` and ``rm -rf``s each, releasing
    the ~50-130 MB per pass that plaso would otherwise leave under
    /tmp on a killed run.
    """
    _PLASO_TEMP_DIRS.add(str(path))


def _try_ewfmount_then_loop(
    evidence_id: str, absolute_path: str, mount_dir: Path
) -> tuple[str, float]:
    """Path A for E01 images: ewfmount + loop-mount.

    Each step tries the command direct first, then ``sudo -n``.
    Mount dirs come from ``_allocate_mount_dir`` so the sudoers
    wildcard scopes cleanly. Records the intermediate ewf dir in
    ``_EWF_DIR_CACHE`` so atexit can ``fusermount -u`` it.

    Returns ``(command_string, runtime_seconds)`` — combined across
    the two-step pipeline.
    """
    ewfmount_bin = os.environ.get(SIFT_DISK_EWFMOUNT_BIN_ENV, _DEFAULT_EWFMOUNT_BIN)
    mount_bin = os.environ.get(SIFT_DISK_MOUNT_BIN_ENV, _DEFAULT_MOUNT_BIN)
    ewf_dir = _allocate_mount_dir(evidence_id, suffix="-ewf")

    _, ewf_cmd, ewf_elapsed = _run_subprocess(
        ["sudo", ewfmount_bin, absolute_path, str(ewf_dir)],
        timeout_seconds=120,
    )
    _EWF_DIR_CACHE[evidence_id] = str(ewf_dir)

    _, mount_cmd, mount_elapsed = _run_subprocess(
        ["sudo", mount_bin, "-o", "ro,loop", str(ewf_dir / "ewf1"), str(mount_dir)],
        timeout_seconds=60,
    )
    return f"{ewf_cmd} && {mount_cmd}", ewf_elapsed + mount_elapsed


def _try_loop_mount(absolute_path: str, mount_dir: Path) -> tuple[str, float]:
    """Loop-mount a raw image under sudo. The NOPASSWD sudoers entry
    at /etc/sudoers.d/sift-guard grants the mount/umount/ewfmount
    binaries without prompting; calling them direct first is a
    wasted exec on every disk dispatch."""
    mount_bin = os.environ.get(SIFT_DISK_MOUNT_BIN_ENV, _DEFAULT_MOUNT_BIN)
    _, command_string, elapsed = _run_subprocess(
        ["sudo", mount_bin, "-o", "ro,loop", absolute_path, str(mount_dir)],
        timeout_seconds=60,
    )
    return command_string, elapsed


def _try_guestmount(
    evidence_id: str, absolute_path: str, mount_dir: Path
) -> tuple[str, float]:
    """Final fallback: FUSE-based libguestfs mount.

    libguestfs spins up an in-process Linux VM, reads the image
    natively (E01, raw, VHDX, VMDK, QCOW2 — anything libguestfs
    recognizes), and exposes the filesystem via FUSE. No root and
    no fuse-group membership required (libguestfs ships its own
    FUSE-talking helper).

    Records the mount in ``_GUESTMOUNT_CACHE`` so atexit can call
    ``guestunmount`` rather than ``umount`` (the FUSE entry must
    be torn down via libguestfs' own helper).
    """
    guestmount_bin = os.environ.get(SIFT_DISK_GUESTMOUNT_BIN_ENV, _DEFAULT_GUESTMOUNT_BIN)
    _, command_string, elapsed = _run_subprocess(
        [guestmount_bin, "--ro", "-a", absolute_path, "-i", str(mount_dir)],
        timeout_seconds=180,
    )
    _GUESTMOUNT_CACHE[evidence_id] = str(mount_dir)
    return command_string, elapsed


def mount_disk_image(evidence_id: str, absolute_path: str) -> str:
    """Resolve a disk-image evidence_id to its mounted-root path.

    Resolution order:

      1. In-process cache (cheap re-validation against /proc/mounts).
      2. ``SIFT_DISK_PREMOUNTED_PATH`` env var, when set.
      3. Per-format fallback chain (see module docstring): ewfmount +
         loop for E01, loop for raw, guestmount as final fallback.

    Caches per-evidence_id to avoid double-mounting on repeat tool
    calls. The cache is in-process; a server restart starts fresh
    and re-mounts.

    Raises:
        MountError: every strategy in the fallback chain failed,
            or the image format is unsupported.
        MountVerificationError: post-mount /proc/mounts check did
            not show a read-only mount.

    Sanitized: messages never echo `absolute_path` or `evidence_id`
    back per the 2026-05-05 MCP error-message sanitization rule.
    """
    cached = _MOUNT_CACHE.get(evidence_id)
    if cached is not None:
        # Re-validate on cache hit — defensive against an external
        # `umount` race between calls. Cheap (one /proc/mounts read).
        if _is_path_mounted_readonly(cached):
            return cached
        # Cache stale; drop and re-mount.
        _MOUNT_CACHE.pop(evidence_id, None)

    premounted = os.environ.get(SIFT_DISK_PREMOUNTED_PATH_ENV)
    if not premounted:
        # File-based per-evidence-id override: operator writes the
        # mount path to ``/tmp/sift-guard-premounts/<evidence_id>``.
        # Complements the env-var form, which applies one path to
        # every evidence_id — the file form lets the operator point
        # each evidence at a different external mount (useful when
        # multiple disks are pre-mounted by hand under different
        # loop devices). The evidence_id is a validated UUID at the
        # MCP boundary so no path traversal is reachable here.
        hint_file = _MOUNT_BASE.parent / "sift-guard-premounts" / evidence_id
        if hint_file.exists():
            premounted = hint_file.read_text(encoding="utf-8").strip() or None
    if premounted:
        if not _is_path_mounted_readonly(premounted):
            raise MountVerificationError(
                "premounted path is not a read-only mount per /proc/mounts"
            )
        _MOUNT_CACHE[evidence_id] = premounted
        return premounted

    fmt = _detect_image_format(absolute_path)
    mount_dir = _allocate_mount_dir(evidence_id)
    # Pre-mount orphan cleanup: a previous run that died ungracefully
    # may have left fuse mounts at the predictable mount paths.
    # ``_allocate_mount_dir`` is deterministic on evidence_id_short,
    # so a collision is silent corruption: ewfmount / mount would
    # either fail with "already mounted" or succeed with a stale
    # backing file, masking the intended evidence. Clear orphans
    # first, then proceed. See 2026-05-13 SRL-v2 cleanup audit for
    # the empirical case.
    _clean_stale_mount_for(evidence_id, mount_dir)
    try:
        if fmt == "e01":
            try:
                _try_ewfmount_then_loop(evidence_id, absolute_path, mount_dir)
            except MountError:
                # Path A failed at one of its two subprocess steps.
                # Tear down whatever Path A managed to set up, then
                # try Path B (guestmount) on a fresh mount dir.
                _cleanup_partial_mount(evidence_id, mount_dir)
                mount_dir = _allocate_mount_dir(evidence_id)
                _try_guestmount(evidence_id, absolute_path, mount_dir)
        elif fmt == "raw":
            try:
                _try_loop_mount(absolute_path, mount_dir)
            except MountError:
                _cleanup_partial_mount(evidence_id, mount_dir)
                mount_dir = _allocate_mount_dir(evidence_id)
                _try_guestmount(evidence_id, absolute_path, mount_dir)
        elif fmt == "vhdx":
            _try_guestmount(evidence_id, absolute_path, mount_dir)
        else:
            raise MountError("unsupported disk-image format")

        if not _is_path_mounted_readonly(str(mount_dir)):
            raise MountVerificationError("post-mount /proc/mounts check did not show ro mount")
    except Exception:
        # Best-effort cleanup; if teardown itself fails, surface the
        # original error rather than the cleanup error.
        _cleanup_partial_mount(evidence_id, mount_dir)
        raise

    resolved = str(mount_dir)
    _MOUNT_CACHE[evidence_id] = resolved
    return resolved


def _cleanup_partial_mount(evidence_id: str, mount_dir: Path) -> None:
    """Best-effort teardown of a half-built mount.

    Used both on the failure path inside ``mount_disk_image`` and
    by the atexit cleanup. Tries the appropriate teardown command
    for whichever phase the mount reached: ``guestunmount`` for
    guestmount FUSE entries, ``fusermount -u`` for ewfmount FUSE
    entries, ``umount`` (direct then ``sudo -n``) for loop mounts.

    Failures are swallowed — the goal is cleanup, not loud
    reporting. The cache entries are popped regardless so a stale
    half-mount cannot poison future lookups.
    """
    # Guestmount FUSE entry, if one was registered.
    guestmount_path = _GUESTMOUNT_CACHE.pop(evidence_id, None)
    if guestmount_path:
        try:
            subprocess.run(
                ["guestunmount", guestmount_path],
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Loop-mounted target — umount under sudo (NOPASSWD).
    try:
        subprocess.run(
            ["sudo", "umount", str(mount_dir)],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass

    # ewfmount intermediate FUSE dir.
    ewf_dir = _EWF_DIR_CACHE.pop(evidence_id, None)
    if ewf_dir:
        try:
            subprocess.run(
                ["fusermount", "-u", ewf_dir],
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            Path(ewf_dir).rmdir()
        except OSError:
            pass

    try:
        mount_dir.rmdir()
    except OSError:
        pass


def _atexit_cleanup_all_mounts() -> None:
    """Tear down every cached mount + plaso work dir on shutdown.

    Iterates a snapshot of the mount cache (so we can mutate
    ``_MOUNT_CACHE`` inside the loop), runs ``_cleanup_partial_mount``
    against each, and finally removes the cache entries. Then reaps
    every ``/tmp/sift-plaso-*`` directory the runner registered via
    ``_register_plaso_tempdir`` — without this the temp dirs leak
    across runs (~50-130 MB per killed pass; the 2026-05-13 SRL-v2
    cleanup found ~210 MB accreted across three runs). Premounted
    mode skips the mount cleanup but still reaps plaso work dirs,
    since those are unconditionally owned by sift-guard.
    """
    if not os.environ.get(SIFT_DISK_PREMOUNTED_PATH_ENV):
        for evidence_id, mount_path in list(_MOUNT_CACHE.items()):
            try:
                _cleanup_partial_mount(evidence_id, Path(mount_path))
            except Exception:
                # Shutdown handlers swallow everything — the cache is
                # being thrown away regardless.
                pass
            _MOUNT_CACHE.pop(evidence_id, None)

    for tmp_path_str in list(_PLASO_TEMP_DIRS):
        try:
            shutil.rmtree(tmp_path_str, ignore_errors=True)
        except Exception:
            pass
        _PLASO_TEMP_DIRS.discard(tmp_path_str)


atexit.register(_atexit_cleanup_all_mounts)


def umount_all_for(evidence_id: str) -> None:
    """Best-effort teardown of any mount cached for `evidence_id`.

    Called by tests' tmp_path teardown and by an explicit
    operator-tooling path. Not invoked at MCP-tool boundaries —
    the mount is intentionally long-lived across the analyst's
    session so repeat calls hit the cache. Routes through
    ``_cleanup_partial_mount`` so guestmount + ewfmount + loop
    teardowns all run via the same code path as atexit.
    """
    mount_path = _MOUNT_CACHE.pop(evidence_id, None)
    if mount_path is None:
        # Even with no main mount entry, guestmount / ewfmount
        # intermediates may still be cached; teardown reaches into
        # both caches.
        if evidence_id in _GUESTMOUNT_CACHE or evidence_id in _EWF_DIR_CACHE:
            _cleanup_partial_mount(evidence_id, Path("/tmp/sift-guard-mounts/__nonexistent__"))
        return
    if os.environ.get(SIFT_DISK_PREMOUNTED_PATH_ENV):
        # Operator-managed mount; do not attempt to unmount.
        return
    _cleanup_partial_mount(evidence_id, Path(mount_path))


# ---------------------------------------------------------------------------
# Per-tool subprocess runners. Each returns ``(stdout, command_string,
# runtime_seconds, tool_version)`` so the tier-1 wrapper can persist a
# fully-provenanced result envelope.
# ---------------------------------------------------------------------------


def run_log2timeline_mft(
    mount_path: str, *, timeout_seconds: int = 1800
) -> tuple[str, str, float, str]:
    """Run plaso's two-step MFT-only timeline pipeline.

    Step 1: ``log2timeline.py --parsers mft --storage-file <plaso_file>
    <mount_path>`` writes a plaso storage file restricted to the MFT
    parser only.

    Step 2: ``psort.py -o json_line -w <jsonl> <plaso_file>`` converts
    the plaso file to JSON-line output.

    Returns the JSON-line contents as `stdout`, the joined two-step
    invocation as `command_string`, the cumulative runtime, and the
    plaso version captured from ``log2timeline.py --version``.

    Note: the user's spec used ``log2timeline.py -o json_line`` —
    that flag belongs to ``psort.py``, not ``log2timeline.py``. The
    actual plaso pipeline is two-step.
    """
    log2timeline_bin = os.environ.get(SIFT_DISK_LOG2TIMELINE_BIN_ENV, _DEFAULT_LOG2TIMELINE_BIN)
    psort_bin = os.environ.get(SIFT_DISK_PSORT_BIN_ENV, _DEFAULT_PSORT_BIN)
    plaso_workdir = Path(tempfile.mkdtemp(prefix="sift-plaso-"))
    _register_plaso_tempdir(plaso_workdir)
    plaso_storage = plaso_workdir / "out.plaso"
    jsonl_out = plaso_storage.with_suffix(".jsonl")

    try:
        version_stdout, _, _ = _run_subprocess([log2timeline_bin, "--version"], timeout_seconds=30)
        tool_version = version_stdout.strip().splitlines()[-1] if version_stdout else "plaso"

        _, l2t_cmd, l2t_elapsed = _run_subprocess(
            [
                log2timeline_bin,
                "--parsers",
                "mft",
                "--storage-file",
                str(plaso_storage),
                mount_path,
            ],
            timeout_seconds=timeout_seconds,
        )
        _, psort_cmd, psort_elapsed = _run_subprocess(
            [
                psort_bin,
                "-o",
                "json_line",
                "-w",
                str(jsonl_out),
                str(plaso_storage),
            ],
            timeout_seconds=timeout_seconds,
        )
        stdout = jsonl_out.read_text(encoding="utf-8")
    finally:
        for p in (plaso_storage, jsonl_out):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    command_string = f"{l2t_cmd} && {psort_cmd}"
    return stdout, command_string, l2t_elapsed + psort_elapsed, tool_version


def run_prefetch(mount_path: str, *, timeout_seconds: int = 300) -> tuple[str, str, float, str]:
    """Parse `Windows/Prefetch/*.pf` under the mount.

    Subprocess invocation: ``${SIFT_DISK_PREFETCH_CMD:-pf2json}
    <prefetch_dir>``. The runner expects JSON-line stdout (one
    object per .pf file). When no .pf files are present, returns
    empty stdout — the parser handles that as a zero-record
    extraction.
    """
    prefetch_cmd = os.environ.get(SIFT_DISK_PREFETCH_CMD_ENV, _DEFAULT_PREFETCH_CMD)
    prefetch_dir = Path(mount_path) / RELATIVE_PREFETCH_DIR
    if not prefetch_dir.exists():
        return "", f"{prefetch_cmd} {prefetch_dir}", 0.0, "missing"

    stdout, command_string, elapsed = _run_subprocess(
        [prefetch_cmd, str(prefetch_dir)],
        timeout_seconds=timeout_seconds,
    )
    return stdout, command_string, elapsed, prefetch_cmd


def run_evtx_dump(
    mount_path: str,
    channels: Iterable[str] = ("Security", "System"),
    *,
    timeout_seconds: int = 600,
) -> tuple[str, str, float, str]:
    """Dump the requested EVTX channels under the mount.

    Subprocess invocation per channel:
    ``${SIFT_DISK_EVTX_DUMP_CMD:-evtx_dump.py} -o json
    <Logs/<channel>.evtx>``. Concatenates JSON-line output across
    the requested channels with the channel name prepended on each
    line as a synthetic ``__channel`` field so the parser can split
    them out without re-reading file-paths.
    """
    cmd = os.environ.get(SIFT_DISK_EVTX_DUMP_CMD_ENV, _DEFAULT_EVTX_DUMP_CMD)
    log_dir = Path(mount_path) / RELATIVE_EVTX_DIR

    pieces: list[str] = []
    cmd_pieces: list[str] = []
    cumulative_elapsed = 0.0
    for channel in channels:
        log_path = log_dir / f"{channel}.evtx"
        if not log_path.exists():
            continue
        stdout, command_string, elapsed = _run_subprocess(
            [cmd, "-o", "json", str(log_path)],
            timeout_seconds=timeout_seconds,
        )
        cmd_pieces.append(command_string)
        cumulative_elapsed += elapsed
        # Tag each line with its source channel so the parser can
        # restore it without re-walking paths. JSON-line input only.
        for raw in stdout.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            obj["__channel"] = channel
            pieces.append(json.dumps(obj))

    combined_stdout = "\n".join(pieces)
    combined_command = " && ".join(cmd_pieces) if cmd_pieces else f"{cmd} (no logs)"
    return combined_stdout, combined_command, cumulative_elapsed, cmd


def run_regripper(mount_path: str, *, timeout_seconds: int = 600) -> tuple[str, str, float, str]:
    """Run RegRipper across SYSTEM / SOFTWARE / SAM / NTUSER.DAT.

    Subprocess invocation per hive:
    ``${SIFT_DISK_REGRIPPER_BIN:-rip.pl} -r <hive> -f <profile>``.
    Concatenates stdout across hives with a synthetic banner line
    (``# === HIVE: <name> ===``) before each block so the
    line-based parser can split them out without re-walking paths.

    Per-user NTUSER.DAT discovery: enumerates ``Users/*/NTUSER.DAT``
    under the mount and runs RegRipper once per user hive.
    """
    rip_bin = os.environ.get(SIFT_DISK_REGRIPPER_BIN_ENV, _DEFAULT_REGRIPPER_BIN)

    pieces: list[str] = []
    cmd_pieces: list[str] = []
    cumulative_elapsed = 0.0

    # System-wide hives.
    for hive_name in ("SYSTEM", "SOFTWARE", "SAM"):
        hive_path = Path(mount_path) / RELATIVE_REGISTRY_HIVES[hive_name]
        if not hive_path.exists():
            continue
        profile = _REGRIPPER_PROFILE_FOR_HIVE[hive_name]
        stdout, command_string, elapsed = _run_subprocess(
            [rip_bin, "-r", str(hive_path), "-f", profile],
            timeout_seconds=timeout_seconds,
        )
        pieces.append(f"# === HIVE: {hive_name} ===")
        pieces.append(stdout)
        cmd_pieces.append(command_string)
        cumulative_elapsed += elapsed

    # Per-user NTUSER.DAT hives.
    users_dir = Path(mount_path) / "Users"
    if users_dir.exists():
        for user_dir in sorted(users_dir.iterdir()):
            ntuser = user_dir / "NTUSER.DAT"
            if not ntuser.exists():
                continue
            stdout, command_string, elapsed = _run_subprocess(
                [rip_bin, "-r", str(ntuser), "-f", "ntuser"],
                timeout_seconds=timeout_seconds,
            )
            pieces.append(f"# === HIVE: NTUSER.DAT ({user_dir.name}) ===")
            pieces.append(stdout)
            cmd_pieces.append(command_string)
            cumulative_elapsed += elapsed

    combined_stdout = "\n".join(pieces)
    combined_command = " && ".join(cmd_pieces) if cmd_pieces else f"{rip_bin} (no hives)"
    return combined_stdout, combined_command, cumulative_elapsed, rip_bin


# ---------------------------------------------------------------------------
# Output parsers. Each takes the raw stdout produced by the matching
# runner and returns a list[dict] suitable for the schema's record_cls
# constructor. Per-record validation failures bubble to the wrapper
# layer, which audits them as `<tool>:record_validation_warning` lines.
# ---------------------------------------------------------------------------


def _truncate_to_500(text: str) -> str:
    """Truncate `text` to 500 characters with a `[truncated]` suffix.

    Pre-validation truncation per the EvtxRecord / RegistryRecord
    Field(max_length=500) constraints. Suffix is included in the
    500-char limit so the visible message is bounded.
    """
    if len(text) <= 500:
        return text
    suffix = "...[truncated]"
    keep = 500 - len(suffix)
    return text[:keep] + suffix


# Mapping of plaso `timestamp_desc` values to MftEntryType. Only the
# four MFT $STANDARD_INFORMATION timestamps are surfaced; anything
# else falls under the catch-all "modified" with a warning at the
# wrapper layer (a cleaner v2 might extend the Literal).
_PLASO_TIMESTAMP_DESC_MAP: dict[str, str] = {
    "Creation Time": "created",
    "Last Modification Time": "modified",
    "Last Access Time": "accessed",
    "MFT Entry Modification Time": "mft_modified",
}


def parse_plaso_jsonl(stdout: str) -> list[dict]:
    """Parse psort.py's json_line output to MftTimelineRecord-shaped dicts.

    Each line is a JSON object with plaso fields. We map the subset
    the schema cares about (datetime → timestamp, display_name →
    full_path, timestamp_desc → entry_type, file_size → file_size).

    Lines whose `parser` is not `mft` are filtered out — defense-in-
    depth against the runner being misconfigured. Lines whose
    timestamp_desc is not one of the four MFT timestamp categories
    are dropped (forward-compat with future plaso desc additions).
    """
    rows: list[dict] = []
    for raw in stdout.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if obj.get("parser") and obj.get("parser") != "mft":
            continue
        desc = obj.get("timestamp_desc", "")
        entry_type = _PLASO_TIMESTAMP_DESC_MAP.get(desc)
        if entry_type is None:
            continue
        rows.append(
            {
                "timestamp": obj.get("datetime"),
                "full_path": obj.get("display_name") or obj.get("filename") or "",
                "entry_type": entry_type,
                "file_size": obj.get("file_size"),
            }
        )
    return rows


def parse_prefetch(stdout: str) -> list[dict]:
    """Parse pf2json's JSON-line stdout to PrefetchRecord-shaped dicts.

    Each line is one .pf file's parsed metadata. Field mapping:
      executable_filename → executable_name
      run_count → run_count
      last_run_times → last_run_times (already a list of ISO strings)
      volume_path → volume_path
      referenced_files → referenced_files (capped at 50 entries here
      to match the schema's max_length=50)
    """
    rows: list[dict] = []
    for raw in stdout.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        refs = obj.get("referenced_files") or []
        if not isinstance(refs, list):
            refs = []
        rows.append(
            {
                "executable_name": obj.get("executable_filename")
                or obj.get("executable_name")
                or "",
                "run_count": int(obj.get("run_count") or 0),
                "last_run_times": obj.get("last_run_times") or [],
                "volume_path": obj.get("volume_path") or "",
                "referenced_files": refs[:50],
            }
        )
    return rows


def parse_evtx(stdout: str) -> list[dict]:
    """Parse `evtx_dump.py -o json` line-tagged stdout.

    Each line is a per-event JSON object. The runner pre-tags each
    line with `__channel: <name>` so we can populate the schema's
    `channel` field without re-walking file paths. EventData is
    flattened to a string for `message_summary` and truncated to
    500 chars.
    """
    rows: list[dict] = []
    for raw in stdout.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        system = (
            obj.get("Event", {}).get("System", {}) if isinstance(obj.get("Event"), dict) else {}
        )
        # Some evtx_dump variants flatten differently; fall back to
        # top-level keys when System.* is absent.
        event_id_raw = system.get("EventID") or obj.get("EventID") or obj.get("event_id") or 0
        if isinstance(event_id_raw, dict):
            event_id_raw = event_id_raw.get("#text", 0)
        try:
            event_id = int(event_id_raw)
        except (TypeError, ValueError):
            continue

        provider = system.get("Provider", {}) if isinstance(system.get("Provider"), dict) else {}
        source = provider.get("Name") or system.get("Provider") or obj.get("source") or ""
        channel = obj.get("__channel") or system.get("Channel") or obj.get("channel") or ""
        time_created_raw = (
            system.get("TimeCreated", {}).get("SystemTime")
            if isinstance(system.get("TimeCreated"), dict)
            else None
        ) or obj.get("timestamp")

        # Render EventData as a flat string for message_summary;
        # extract logon_type when present.
        event_data = (
            obj.get("Event", {}).get("EventData", {})
            if isinstance(obj.get("Event"), dict)
            else obj.get("EventData") or {}
        )
        if not isinstance(event_data, dict):
            event_data = {}
        # `Data` may be a list of {"@Name": "...", "#text": "..."}
        # entries on the rendered XML form, or a flat dict on
        # already-flattened producers.
        rendered: list[str] = []
        logon_type: int | None = None
        data = event_data.get("Data")
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict):
                    name = d.get("@Name") or d.get("Name") or ""
                    val = d.get("#text") or d.get("text") or d.get("value") or ""
                    rendered.append(f"{name}={val}")
                    if name == "LogonType":
                        try:
                            logon_type = int(val)
                        except (TypeError, ValueError):
                            pass
        elif isinstance(data, dict):
            for name, val in data.items():
                rendered.append(f"{name}={val}")
                if name == "LogonType":
                    try:
                        logon_type = int(val)
                    except (TypeError, ValueError):
                        pass

        message_summary = _truncate_to_500("; ".join(rendered) if rendered else str(event_data))

        rows.append(
            {
                "event_id": event_id,
                "timestamp": time_created_raw,
                "source": str(source),
                "channel": str(channel),
                "message_summary": message_summary,
                "logon_type": logon_type,
            }
        )
    return rows


# RegRipper banner line shape: ``# === HIVE: <name> ===`` (system
# hives) or ``# === HIVE: NTUSER.DAT (<user>) ===`` (per-user).
_REGRIPPER_HIVE_BANNER_PREFIX = "# === HIVE: "

# RegRipper plugin output convention: each plugin emits a `Key:`
# header followed by `LastWrite Time = <ISO>` and one or more
# `<value name> -> <value data>` or `<value name>: <value data>`
# pairs. Different plugins format differently; we parse the most
# common shapes and skip lines we can't structure.
_REGRIPPER_KEY_HEADER_RE = "Key:"
_REGRIPPER_LASTWRITE_RE = "LastWrite Time"


def parse_regripper(stdout: str) -> list[dict]:
    """Parse RegRipper's concatenated plugin output to RegistryRecord
    dicts.

    Best-effort line-based parser. Each `# === HIVE: ===` banner
    switches the active hive_name; subsequent `Key:` lines start a
    new key block; `<name> -> <value>` and `<name>: <value>` lines
    inside a key block produce one record each. Lines we cannot
    structure are silently skipped.

    `last_modified` is parsed from the `LastWrite Time = <ISO>`
    line associated with the active key. RegRipper plugins format
    timestamps differently across versions; when the format is not
    a recognizable ISO timestamp we leave `last_modified` as None
    (the schema accepts that).
    """
    from datetime import datetime, timezone

    rows: list[dict] = []
    active_hive: str | None = None
    active_key_path: str = ""
    active_last_modified: str | None = None

    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith(_REGRIPPER_HIVE_BANNER_PREFIX):
            # `# === HIVE: SYSTEM ===` or
            # `# === HIVE: NTUSER.DAT (alice) ===`
            inner = line[len(_REGRIPPER_HIVE_BANNER_PREFIX) :].rstrip(" =")
            # Strip per-user suffix (preserve hive name only).
            paren = inner.find(" (")
            hive_name = inner[:paren] if paren != -1 else inner
            active_hive = hive_name.strip()
            active_key_path = ""
            active_last_modified = None
            continue
        stripped = line.strip()
        if stripped.startswith(_REGRIPPER_KEY_HEADER_RE):
            active_key_path = stripped[len(_REGRIPPER_KEY_HEADER_RE) :].strip()
            active_last_modified = None
            continue
        if stripped.startswith(_REGRIPPER_LASTWRITE_RE):
            # `LastWrite Time = 2024-01-01T00:00:00Z` or
            # `LastWrite Time: Thu Jan  1 00:00:00 2024`
            eq_idx = stripped.find("=")
            colon_idx = stripped.find(":")
            sep = max(eq_idx, colon_idx)
            if sep > 0:
                active_last_modified = stripped[sep + 1 :].strip()
            continue
        # Value line: try `name -> data` first, then `name: data`.
        if active_hive is None or active_key_path == "":
            continue
        sep_idx = stripped.find(" -> ")
        if sep_idx > 0:
            value_name = stripped[:sep_idx].strip()
            value_data = stripped[sep_idx + 4 :].strip()
        else:
            sep_idx = stripped.find(": ")
            if sep_idx <= 0:
                continue
            value_name = stripped[:sep_idx].strip()
            value_data = stripped[sep_idx + 2 :].strip()
        # Reject obvious non-value lines (banner text, blank labels).
        if not value_name or value_name.startswith("#"):
            continue
        # Try to parse the timestamp; pydantic enforces UTC, so we
        # only pass through values we successfully parse to UTC.
        last_modified_iso: str | None = None
        if active_last_modified:
            try:
                parsed = datetime.fromisoformat(active_last_modified.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                last_modified_iso = parsed.isoformat()
            except (ValueError, TypeError):
                last_modified_iso = None
        rows.append(
            {
                "hive_name": active_hive,
                "key_path": active_key_path,
                "value_name": value_name,
                "value_data": _truncate_to_500(value_data),
                "last_modified": last_modified_iso,
            }
        )
    return rows


__all__ = [
    "MountError",
    "MountVerificationError",
    "RELATIVE_PREFETCH_DIR",
    "RELATIVE_EVTX_DIR",
    "RELATIVE_REGISTRY_HIVES",
    "SIFT_DISK_PREMOUNTED_PATH_ENV",
    "mount_disk_image",
    "parse_evtx",
    "parse_plaso_jsonl",
    "parse_prefetch",
    "parse_regripper",
    "run_evtx_dump",
    "run_log2timeline_mft",
    "run_prefetch",
    "run_regripper",
    "umount_all_for",
]
