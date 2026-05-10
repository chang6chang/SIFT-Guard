"""Directory scanner + grouping heuristic for `run-case` mode.

Three things this module does:

  1. **Scan** — walk a directory recursively for files whose
     extensions match the configured memory / disk / split-image
     / mixed sets. Stable order (sorted) so manifests are
     reproducible. Files under known-non-evidence directories
     (`baseline/`, `precooked/`) are skipped — DFIR cases
     conventionally place reference timelines, parsed CSVs, and
     pristine OS images there, none of which the loop should
     re-register as evidence.

  2. **Magic-byte detection** — read the first 16 bytes of each
     candidate and refine the type guess:
       - LiME header (4C 69 4D 45) → memory
       - E01 header (45 56 46 09 0D 0A FF 00) → disk
       - VHDX header (76 68 64 78 66 69 6C 65) → disk
     Magic-byte hits override the extension-only guess; nothing
     hits when the file is shorter than 16 bytes. Raw memory dumps
     (FTK Imager `.001` split images, dd output) have no
     distinguishing magic — the filename heuristic is what drives
     the type guess for those.

  3. **Group by host** — extract a host token from each filename
     (e.g. ``win7-64-nfury-10.3.58.6.raw`` → ``nfury``) and bucket
     files by that token. Files sharing a token belong to the same
     host. Files whose token cannot be inferred are each their own
     host, named after the filename stem.

Split-image (`.001`) heuristic
------------------------------

FTK Imager produces split images with sequential `.001` / `.002`
extensions. The first segment is what `register_evidence` picks
up; subsequent segments share the registration. Per the SRL-2015
dataset convention (used by the SANS "Find Evil!" hackathon),
memory split images carry "memory" in the filename
(`nfury-memory.001`) and disk split images do not. The scanner
applies that as a heuristic:

    extension == ".001" AND "memory" in filename.lower()  →  memory
    extension == ".001" AND "memory" NOT in filename      →  unknown

`unknown` here is the safe fallback — could be a split disk image,
could be something else entirely. Operators wanting to force the
type can pre-rename the file to include the role word, or edit
the manifest after `--scan-only`.

The scan + group output is then handed back to the caller, which
calls ``register_evidence`` for each `EvidenceFile`, builds a
`CaseManifest`, and writes it to disk via
``orchestrator.manifest.write_manifest``.

Per CLAUDE.md "Hard Rule" — `register_evidence` requires the file
be under `<case_dir>/evidence/`. The scanner does not enforce that
(it walks any directory the operator specifies); the registration
call is what catches a misplaced file with a sanitized rejection.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from orchestrator.manifest import EvidenceType, HostEvidence


logger = logging.getLogger(__name__)


# Extension → preliminary evidence-type guess. Magic bytes refine
# this, but a lot of files are extension-only by convention.
_MEMORY_EXTENSIONS: frozenset[str] = frozenset({".raw", ".mem", ".lime", ".vmem"})
_DISK_EXTENSIONS: frozenset[str] = frozenset(
    {".e01", ".dd", ".vhdx", ".vhd", ".img", ".vmdk", ".qcow2", ".vdi"}
)
# .aff4 can be either memory or disk (it's a container format).
# Treat as unknown so the operator must annotate post-scan, OR the
# magic-byte detector resolves it to one of the two.
_MIXED_EXTENSIONS: frozenset[str] = frozenset({".aff4"})
# FTK Imager split-image extensions. The first segment carries
# `.001`; subsequent segments are `.002`, `.003`, etc. The scanner
# only picks up `.001` — register_evidence's first-segment hash
# captures the entire image regardless of split count. Type
# detection for `.001` is filename-based (see module docstring's
# split-image heuristic section).
_SPLIT_IMAGE_EXTENSIONS: frozenset[str] = frozenset({".001"})

_ALL_SCANNED_EXTENSIONS: frozenset[str] = (
    _MEMORY_EXTENSIONS | _DISK_EXTENSIONS | _MIXED_EXTENSIONS | _SPLIT_IMAGE_EXTENSIONS
)

# Known non-evidence file extensions. These are explicitly skipped
# (with a debug log) when encountered. The set is informational —
# without an entry here, an unknown extension is silently skipped
# by the `_ALL_SCANNED_EXTENSIONS` membership check. Surfacing
# them here gives operators a documented "we considered it and
# decided it's not evidence" answer.
#
#   .mans  — Mandiant Memoryze session files (analysis state, not
#            an image)
#   .csv / .dump / .xlsx / .body / .ioc / .txt — common SRL-style
#            "precooked" parser output left next to evidence for
#            convenience; not images themselves
_KNOWN_NON_EVIDENCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".mans",
        ".csv",
        ".dump",
        ".xlsx",
        ".body",
        ".ioc",
        ".txt",
        # Archive / compressed-blob extensions that commonly land
        # next to a real evidence image (symbol packs, source-of-
        # acquisition zips). Listed here so the skip is greppable —
        # the membership check on _ALL_SCANNED_EXTENSIONS would
        # silently skip them too.
        ".zip",
        ".xz",
        ".gz",
        ".tar",
    }
)

# Directory components whose contents are conventionally NOT
# evidence — DFIR cases place reference timelines, parsed CSVs,
# and pristine baseline OS images here. The scanner skips any
# file whose path includes one of these components.
_NON_EVIDENCE_DIR_NAMES: frozenset[str] = frozenset({"baseline", "precooked"})


# Magic-byte signatures (read from the first 64 bytes of the file).
# VDI carries an ASCII "image_info" text in the first 64 bytes that
# starts with "<<< Oracle VM VirtualBox Disk Image >>>"; the actual
# 4-byte image_signature at offset 0x40 is the authoritative VDI
# discriminator, but the leading text is what every standard VDI
# we will encounter starts with, and is more portable across
# editions (Sun xVM, Innotek). We probe both.
_LIME_MAGIC = b"\x4c\x69\x4d\x45"  # b"LiME"
_E01_MAGIC = b"\x45\x56\x46\x09\x0d\x0a\xff\x00"  # EVF\t\r\n\xff\x00
_VHDX_MAGIC = b"\x76\x68\x64\x78\x66\x69\x6c\x65"  # b"vhdxfile"
_VMDK_MAGIC = b"KDMV"  # VMware sparse / streamOptimized header
_QCOW2_MAGIC = b"QFI\xfb"  # QEMU copy-on-write v2/v3 header
_VDI_TEXT_MAGIC = b"<<< Oracle VM VirtualBox Disk Image >>>"
_VDI_SIGNATURE = b"\x7f\x10\xda\xbe"  # at offset 0x40 (little-endian 0xbeda107f)
_VDI_SIGNATURE_OFFSET = 0x40

_MAGIC_PROBE_BYTES = 64


# Filename hostname-extraction heuristic. Common DFIR-case naming
# conventions we want to match:
#
#   win7-64-nfury-10.3.58.6.raw       → host_id "nfury"
#   nfury-memory.raw                   → host_id "nfury"
#   nfury-disk.E01                     → host_id "nfury"
#   controller-memory.raw              → host_id "controller"
#   controller_security.evtx           → host_id "controller"
#   IT-W10-PC1.E01                     → host_id "IT-W10-PC1"
#
# The heuristic strips:
#   - the file extension
#   - common evidence-role suffixes ("memory", "disk", "image", "ram")
#   - leading platform/architecture descriptors
#     ("win7", "win10", "win-64", "linux", "x64", etc.)
#   - a trailing IPv4-looking token
# What survives is the host token. Whitespace / underscore / dot
# are normalized to "-" so the token round-trips through the
# manifest's host_id pattern (alphanumerics + .-_).

_ROLE_TOKENS: frozenset[str] = frozenset(
    {
        "memory",
        "memdump",
        "memimage",
        "mem",
        "ram",
        "image",
        "disk",
        "drive",
        "hdd",
        "system",
        "cdrive",
        "pf",
        "prefetch",
        "registry",
        "reg",
        "evtx",
        "security",
        "application",
        "ntuser",
        "usrhive",
    }
)

_TRAILING_ROLE_RE = re.compile(
    r"[-_.](memory|memdump|memimage|mem|ram|image|disk|drive|hdd|"
    r"system|c-drive|cdrive|pf|prefetch|registry|reg|evtx|"
    r"security|application|ntuser|usrhive)\b",
    re.IGNORECASE,
)
_LEADING_PLATFORM_RE = re.compile(
    r"^(win-?xp|win-?vista|win-?7|win-?8|win-?10|win-?11|"
    r"windows-?\d*|server-?\d*r?\d*|w[2789]k\d*|"
    r"linux|ubuntu|debian|centos|redhat|rhel|"
    r"mac|macos|osx|"
    r"x86|x64|x32|amd64|arm64|i386|"
    r"32-?bit|64-?bit|32|64)\b",
    re.IGNORECASE,
)
_TRAILING_IP_RE = re.compile(r"[-_.](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


@dataclass
class _ScanCandidate:
    """One scanned file, before host-grouping. Internal to this
    module — the public API returns `(EvidenceFile, host_id,
    host_label)` triples or full `HostEvidence` blocks."""

    path: Path
    evidence_type: EvidenceType
    file_size_bytes: int
    host_id: str
    host_label: str


def _detect_evidence_type_by_extension(path: Path) -> EvidenceType:
    """Extension-first guess; refined by magic-byte detection.

    For `.001` split-image extensions the guess is filename-based:
    `"memory"` substring in the filename → memory; otherwise unknown.
    See the module docstring's split-image heuristic section for the
    rationale. Magic-byte detection cannot disambiguate raw memory
    dumps from split disk images by header alone, so the filename
    is the most reliable signal we have.
    """
    ext = path.suffix.lower()
    if ext in _MEMORY_EXTENSIONS:
        return "memory"
    if ext in _DISK_EXTENSIONS:
        return "disk"
    if ext in _SPLIT_IMAGE_EXTENSIONS:
        if "memory" in path.name.lower():
            return "memory"
        return "unknown"
    return "unknown"


def _is_under_non_evidence_dir(path: Path, evidence_root: Path) -> bool:
    """True iff any path component between `evidence_root` and `path`
    is a known non-evidence directory name (`baseline/`,
    `precooked/`).

    Resolves both sides so symlink games can't smuggle a file
    under a real `baseline/` into the scan output.
    """
    try:
        rel = path.resolve().relative_to(evidence_root.resolve())
    except ValueError:
        # Outside the scan root — let the caller handle it; this
        # check is not the path-confinement guard.
        return False
    return any(seg.lower() in _NON_EVIDENCE_DIR_NAMES for seg in rel.parts)


def _refine_evidence_type_by_magic(path: Path, ext_guess: EvidenceType) -> EvidenceType:
    """Read the first 16 bytes; bump the guess to a stronger
    classification when a magic-byte signature matches.

    Magic-byte hits are authoritative; we never override a
    magic-byte-confirmed type with the extension-only guess. When
    no magic matches, the extension-only guess stands.
    """
    try:
        with path.open("rb") as f:
            head = f.read(_MAGIC_PROBE_BYTES)
    except (OSError, FileNotFoundError):
        return ext_guess
    if head.startswith(_LIME_MAGIC):
        return "memory"
    if head.startswith(_E01_MAGIC):
        return "disk"
    if head.startswith(_VHDX_MAGIC):
        return "disk"
    if head.startswith(_VMDK_MAGIC):
        return "disk"
    if head.startswith(_QCOW2_MAGIC):
        return "disk"
    if head.startswith(_VDI_TEXT_MAGIC):
        return "disk"
    if (
        len(head) >= _VDI_SIGNATURE_OFFSET + 4
        and head[_VDI_SIGNATURE_OFFSET : _VDI_SIGNATURE_OFFSET + 4] == _VDI_SIGNATURE
    ):
        return "disk"
    return ext_guess


def _extract_host_token(stem: str) -> str | None:
    """Pull a host token out of a filename stem.

    The stem is the filename minus the extension. We strip
    leading-platform / trailing-role / trailing-IP segments and
    return whatever remains. If nothing remains (the filename was
    pure-role + pure-platform with no host token), return None and
    the caller falls back to the full stem as the host label.
    """
    candidate = stem
    # Strip trailing role segments (potentially several rounds, e.g.
    # `disk-image` would have both `disk` and `image` to peel).
    for _ in range(3):
        match = _TRAILING_ROLE_RE.search(candidate)
        if not match:
            break
        candidate = candidate[: match.start()]
    # Strip trailing IPv4-looking address.
    candidate = _TRAILING_IP_RE.sub("", candidate)
    # Strip leading platform descriptor (one round; multi-platform
    # prefixes like "win10-x64" we expect to be a single hyphenated
    # block we can re-walk).
    for _ in range(3):
        match = _LEADING_PLATFORM_RE.match(candidate)
        if not match:
            break
        candidate = candidate[match.end() :].lstrip("-_. ")
    candidate = candidate.strip(" -_.")
    if not candidate:
        return None
    # Pure-role detection: if every hyphenated segment that survives
    # is itself a known role token, the filename had no host info to
    # extract. Caller falls back to the filename stem as a singleton
    # bucket.
    segments = [seg for seg in re.split(r"[-_.]+", candidate) if seg]
    if segments and all(seg.lower() in _ROLE_TOKENS for seg in segments):
        return None
    # Normalize whitespace/underscore/dot to hyphen so the token
    # passes the manifest's host_id pattern.
    return re.sub(r"[\s._]+", "-", candidate)


def _scan_directory(
    evidence_dir: Path,
) -> list[tuple[Path, EvidenceType, int]]:
    """Walk `evidence_dir` recursively; return
    `[(path, evidence_type, size_bytes), ...]` sorted by path.

    Filtering rules, in order:
      1. Skip non-files (directories, symlinks-to-directories, etc.).
      2. Skip files under known non-evidence subdirectories
         (`baseline/`, `precooked/`).
      3. Log + skip files with known non-evidence extensions
         (`.mans`, `.csv`, `.dump`, `.xlsx`, `.body`, `.ioc`,
         `.txt`) — informational, since the membership check in
         step 4 would skip them silently anyway.
      4. Skip files whose extension is outside `_ALL_SCANNED_EXTENSIONS`.
    """
    results: list[tuple[Path, EvidenceType, int]] = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file():
            continue
        if _is_under_non_evidence_dir(path, evidence_dir):
            logger.debug(
                "skipping %s — under non-evidence directory",
                path.relative_to(evidence_dir),
            )
            continue
        ext = path.suffix.lower()
        if ext in _KNOWN_NON_EVIDENCE_EXTENSIONS:
            logger.debug(
                "skipping %s — known non-evidence extension %s",
                path.name,
                ext,
            )
            continue
        if ext not in _ALL_SCANNED_EXTENSIONS:
            continue
        ext_guess = _detect_evidence_type_by_extension(path)
        refined = _refine_evidence_type_by_magic(path, ext_guess)
        try:
            size = path.stat().st_size
        except OSError:
            logger.warning("could not stat %s; skipping", path.name)
            continue
        results.append((path, refined, size))
    return results


def _group_candidates(
    raw: list[tuple[Path, EvidenceType, int]],
) -> dict[str, list[_ScanCandidate]]:
    """Bucket the scan output by host_id.

    Filenames with no extractable host token become their own host,
    keyed by the filename stem (sanitized to the host_id pattern).
    Order within a bucket follows the original sort.
    """
    buckets: dict[str, list[_ScanCandidate]] = {}
    for path, evtype, size in raw:
        token = _extract_host_token(path.stem)
        if token is None:
            # Singleton bucket — sanitize the stem to the host_id
            # pattern and use it as both id and label.
            sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", path.stem)
            host_id = sanitized or "unnamed"
            host_label = path.stem
        else:
            host_id = token
            host_label = token
        candidate = _ScanCandidate(
            path=path,
            evidence_type=evtype,
            file_size_bytes=size,
            host_id=host_id,
            host_label=host_label,
        )
        buckets.setdefault(host_id, []).append(candidate)
    return buckets


def scan_evidence_directory(
    evidence_dir: Path | str,
) -> list[tuple[str, str, list[tuple[Path, EvidenceType, int]]]]:
    """High-level scan + group entry point.

    Returns a list of ``(host_id, host_label, files)`` triples,
    where `files` is the list of `(path, evidence_type, size)` per
    host. Sorted by host_id for determinism. The caller registers
    each file via `register_evidence` and then assembles the
    `CaseManifest` from the resulting evidence_ids.
    """
    evidence_dir = Path(evidence_dir).resolve()
    if not evidence_dir.exists():
        raise FileNotFoundError(f"evidence directory does not exist: {evidence_dir}")
    if not evidence_dir.is_dir():
        raise NotADirectoryError(f"evidence path is not a directory: {evidence_dir}")

    raw = _scan_directory(evidence_dir)
    buckets = _group_candidates(raw)

    out: list[tuple[str, str, list[tuple[Path, EvidenceType, int]]]] = []
    for host_id in sorted(buckets):
        candidates = buckets[host_id]
        host_label = candidates[0].host_label
        files = [(c.path, c.evidence_type, c.file_size_bytes) for c in candidates]
        out.append((host_id, host_label, files))
    return out


def format_inventory_table(
    hosts: Iterable[HostEvidence],
) -> str:
    """Pretty-printed two-line-header table summarizing the manifest.

    The exact format the user spec asks for; emitted to stdout by
    `run-case` before the loop kicks off.
    """
    rows: list[tuple[str, str, str, str, str]] = []
    rows.append(("Host", "Evidence", "Type", "Size", "OS Guess"))
    for host in hosts:
        for ef in host.evidence_files:
            rows.append(
                (
                    host.host_label,
                    Path(ef.file_path).name,
                    ef.evidence_type,
                    _format_size(ef.file_size_bytes),
                    ef.os_guess or "—",
                )
            )
    if len(rows) == 1:
        return ""
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = []
    for i, row in enumerate(rows):
        line = " | ".join(cell.ljust(widths[c]) for c, cell in enumerate(row))
        lines.append(line)
        if i == 0:
            lines.append("-+-".join("-" * w for w in widths))
    return "\n".join(lines)


def _format_size(n: int) -> str:
    """1.0 KB / 13.3 GB / 8.1 GB style."""
    units = ("B", "KB", "MB", "GB", "TB")
    val = float(n)
    idx = 0
    while val >= 1024.0 and idx < len(units) - 1:
        val /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(val)} {units[idx]}"
    return f"{val:.1f} {units[idx]}"


__all__ = [
    "format_inventory_table",
    "scan_evidence_directory",
]
