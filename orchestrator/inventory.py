"""Directory scanner + grouping heuristic for `run-case` mode.

Three things this module does:

  1. **Scan** — walk a directory recursively for files whose
     extensions match the configured memory / disk / mixed sets.
     Stable order (sorted) so manifests are reproducible.

  2. **Magic-byte detection** — read the first 16 bytes of each
     candidate and refine the type guess:
       - LiME header (4C 69 4D 45) → memory
       - E01 header (45 56 46 09 0D 0A FF 00) → disk
       - VHDX header (76 68 64 78 66 69 6C 65) → disk
     Magic-byte hits override the extension-only guess; nothing
     hits when the file is shorter than 16 bytes.

  3. **Group by host** — extract a host token from each filename
     (e.g. ``win7-64-nfury-10.3.58.6.raw`` → ``nfury``) and bucket
     files by that token. Files sharing a token belong to the same
     host. Files whose token cannot be inferred are each their own
     host, named after the filename stem.

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

from orchestrator.manifest import EvidenceFile, EvidenceType, HostEvidence


logger = logging.getLogger(__name__)


# Extension → preliminary evidence-type guess. Magic bytes refine
# this, but a lot of files are extension-only by convention.
_MEMORY_EXTENSIONS: frozenset[str] = frozenset(
    {".raw", ".mem", ".lime", ".vmem"}
)
_DISK_EXTENSIONS: frozenset[str] = frozenset(
    {".e01", ".dd", ".vhdx", ".img"}
)
# .aff4 can be either memory or disk (it's a container format).
# Treat as unknown so the operator must annotate post-scan, OR the
# magic-byte detector resolves it to one of the two.
_MIXED_EXTENSIONS: frozenset[str] = frozenset({".aff4"})

_ALL_SCANNED_EXTENSIONS: frozenset[str] = (
    _MEMORY_EXTENSIONS | _DISK_EXTENSIONS | _MIXED_EXTENSIONS
)


# Magic-byte signatures (read from the first 16 bytes of the file).
_LIME_MAGIC = b"\x4c\x69\x4d\x45"  # b"LiME"
_E01_MAGIC = b"\x45\x56\x46\x09\x0d\x0a\xff\x00"  # EVF\t\r\n\xff\x00
_VHDX_MAGIC = b"\x76\x68\x64\x78\x66\x69\x6c\x65"  # b"vhdxfile"

_MAGIC_PROBE_BYTES = 16


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
        "memory", "memdump", "memimage", "mem", "ram", "image",
        "disk", "drive", "hdd", "system", "cdrive", "pf",
        "prefetch", "registry", "reg", "evtx", "security",
        "application", "ntuser", "usrhive",
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
_TRAILING_IP_RE = re.compile(
    r"[-_.](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)


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
    """Extension-first guess; refined by magic-byte detection."""
    ext = path.suffix.lower()
    if ext in _MEMORY_EXTENSIONS:
        return "memory"
    if ext in _DISK_EXTENSIONS:
        return "disk"
    return "unknown"


def _refine_evidence_type_by_magic(
    path: Path, ext_guess: EvidenceType
) -> EvidenceType:
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
        candidate = candidate[match.end():].lstrip("-_. ")
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
    Entries with extensions outside the scanned set are skipped.
    """
    results: list[tuple[Path, EvidenceType, int]] = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _ALL_SCANNED_EXTENSIONS:
            continue
        ext_guess = _detect_evidence_type_by_extension(path)
        refined = _refine_evidence_type_by_magic(path, ext_guess)
        try:
            size = path.stat().st_size
        except OSError:
            logger.warning(
                "could not stat %s; skipping", path.name
            )
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
        raise FileNotFoundError(
            f"evidence directory does not exist: {evidence_dir}"
        )
    if not evidence_dir.is_dir():
        raise NotADirectoryError(
            f"evidence path is not a directory: {evidence_dir}"
        )

    raw = _scan_directory(evidence_dir)
    buckets = _group_candidates(raw)

    out: list[tuple[str, str, list[tuple[Path, EvidenceType, int]]]] = []
    for host_id in sorted(buckets):
        candidates = buckets[host_id]
        host_label = candidates[0].host_label
        files = [
            (c.path, c.evidence_type, c.file_size_bytes)
            for c in candidates
        ]
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
            rows.append((
                host.host_label,
                Path(ef.file_path).name,
                ef.evidence_type,
                _format_size(ef.file_size_bytes),
                ef.os_guess or "—",
            ))
    if len(rows) == 1:
        return ""
    widths = [
        max(len(row[i]) for row in rows) for i in range(len(rows[0]))
    ]
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
