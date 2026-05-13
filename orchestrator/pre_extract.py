"""Pre-extract tier-1 disk artifacts before the analyst dispatch.

Why this exists
---------------

The disk-side tier-1 tools (`disk_mft_timeline`, `disk_prefetch`,
`disk_evtx`, `disk_registry`) wrap plaso / log2timeline / RegRipper.
On a 13 GB E01 with `--parsers mft`, plaso commonly takes 30-60
minutes per pass. When these tools are called from inside an analyst
subagent session, the subagent's wall-clock timeout (currently 3600s
for ``disk_analyst``, see ``dispatch._DEFAULT_TIMEOUT_BY_ANALYST``)
runs alongside plaso — and on the 2026-05-13 SRL-v2 run, three of
four disk_analysts hit the wall while plaso was still mid-MFT,
leaving the audit chain with `disk_*:runner_failed` lines and zero
useful tier-1 output.

The architecture has a clean workaround: each tier-1 tool is
idempotent on ``(evidence_id, plugin_name)``. A successful
extraction lands in
``case-data/extractions/<evidence_id>/<plugin_name>.json`` and any
subsequent call short-circuits to the cache. So we can run the
expensive plaso/regripper work BEFORE the analyst dispatch, fully
populate the tier-1 cache, and dispatch the analyst with a
fast-cache-only workload. The disk_analyst's dispatch wall time
drops from 30-60 minutes to a few minutes (just tier-2 queries),
and the LLM session no longer sits idle burning its budget on the
plaso wait.

Two failure modes are deliberately tolerated:

* A single plugin's runner can fail (e.g., RegRipper hits a
  corrupted hive). We log the `runner_failed` audit-chain line —
  which already happens inside the tier-1 wrapper — and continue.
  The downstream analyst sees an `extraction_not_found` rejection
  for that plugin and either skips or pivots.
* The whole pre-extract phase can be disabled (CLI
  `--no-pre-extract`). The analyst dispatch will then drive the
  tier-1 tools the old way and pay the full plaso cost inside the
  session. This stays available as a fallback for operator
  debugging or for environments where plaso is itself broken.

Concurrency
-----------

We parallelize across `(evidence_id, plugin)` pairs with a
ThreadPoolExecutor. Each tier-1 tool spawns its own
plaso/regripper subprocess, so the threading layer is just I/O wait
coordination — the actual parallelism is bounded by CPU. Default
`max_workers=2` keeps a 4-host run from saturating a 4-core VM (each
plaso instance defaults to multi-process parallel parsing
internally; running 4 plaso × 3 internal workers = 12 cores fights).
Operators with bigger machines can bump it via
``--pre-extract-max-workers``.

Progress
--------

Emits ``pre_extract_phase_start`` / ``pre_extract_phase_done`` and
per-task ``pre_extract_start`` / ``pre_extract_done`` via the same
``on_progress`` callback the loop uses. ``sift_guard.display`` adds
matching event handlers that render `EXTRACT` lines next to the
existing `PREFLIGHT` / `ANALYZE` lines.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from orchestrator.manifest import CaseManifest, EvidenceFile, HostEvidence
from server.runners.disk_mount import cleanup_stale_mounts_globally
from server.tools.disk import (
    disk_evtx,
    disk_mft_timeline,
    disk_prefetch,
    disk_registry,
)


logger = logging.getLogger(__name__)


# Tier-1 disk plugins to pre-extract per disk evidence_id. The
# function reference here is the canonical entrypoint; the tool's
# audit-chain ``tool_name`` is the function's ``__name__``.
_DISK_TIER1_FUNCTIONS: tuple[tuple[str, Callable[[str, str], Any]], ...] = (
    ("disk_mft_timeline", disk_mft_timeline),
    ("disk_prefetch", disk_prefetch),
    ("disk_evtx", disk_evtx),
    ("disk_registry", disk_registry),
)


@dataclass
class PreExtractTaskResult:
    """One (evidence_id, plugin) task's outcome."""

    host_id: str
    host_label: str
    evidence_id: str
    plugin_tool_name: str
    duration_seconds: float
    succeeded: bool
    error_class: str | None = None
    error_message: str | None = None


@dataclass
class PreExtractResult:
    """Aggregate outcome of the pre-extract phase."""

    tasks: list[PreExtractTaskResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    @property
    def succeeded_count(self) -> int:
        return sum(1 for t in self.tasks if t.succeeded)

    @property
    def failed_count(self) -> int:
        return sum(1 for t in self.tasks if not t.succeeded)


def _disk_evidence_for(host: HostEvidence) -> list[EvidenceFile]:
    """Return the host's disk-typed evidence files (skip memory / unknown)."""
    return [ef for ef in host.evidence_files if ef.evidence_type == "disk"]


def has_disk_evidence(manifest: CaseManifest) -> bool:
    """True iff at least one host has at least one disk evidence file.

    The CLI uses this to decide whether to print the pre-extract
    banner / start the phase at all. For a memory-only case the
    pre-extract step is a no-op and we skip the banner.
    """
    return any(_disk_evidence_for(host) for host in manifest.hosts)


def pre_extract_disk_tier1(
    *,
    case_dir: Path,
    manifest: CaseManifest,
    max_workers: int = 2,
    on_progress: Callable[[str, dict[str, Any]], None] | None = None,
) -> PreExtractResult:
    """Pre-populate the tier-1 disk extraction cache for every
    disk-image in the manifest.

    Each ``(evidence_id, plugin)`` pair runs in its own
    ThreadPoolExecutor worker. The tier-1 wrapper's
    ``extraction_exists`` short-circuit means re-runs on the same
    case dir are near-instant — only the first pass on a fresh case
    dir pays the plaso/regripper cost.

    Failures are captured but do not abort the phase: the
    ``PreExtractResult.failed_count`` records them and the
    audit chain has the matching ``<tool>:runner_failed`` line. The
    downstream analyst dispatch sees those as
    ``extraction_not_found`` when it queries via tier-2.
    """
    tasks: list[tuple[str, str, str, Callable[[str, str], Any]]] = []
    for host in manifest.hosts:
        for ef in _disk_evidence_for(host):
            for tool_name, fn in _DISK_TIER1_FUNCTIONS:
                tasks.append((host.host_id, host.host_label, ef.evidence_id, tool_name, fn))  # type: ignore[arg-type]

    result = PreExtractResult()
    if not tasks:
        return result

    # Pre-flight cleanup: a prior sift-guard run that died ungracefully
    # may have left fuse mounts at the predictable
    # ``/tmp/sift-guard-mounts/<short>-ewf`` paths. The 2026-05-13
    # SRL-v2 audit found three of these surviving across run
    # boundaries — any one of them would cause
    # ``rejected_mount_failed`` on the first plaso call because
    # ``_allocate_mount_dir`` collides with the orphan. Clear before
    # starting so the tier-1 wrappers don't trip on someone else's
    # mess.
    orphan_summary = cleanup_stale_mounts_globally()
    if orphan_summary.get("cleaned"):
        logger.info(
            "pre-extract pre-flight: cleaned %d stale mount(s) from prior runs",
            orphan_summary["cleaned"],
        )

    _emit(
        on_progress,
        "pre_extract_phase_start",
        {
            "task_count": len(tasks),
            "host_count": len({t[0] for t in tasks}),
            "max_workers": max_workers,
            "stale_mounts_cleaned": orphan_summary.get("cleaned", 0),
        },
    )

    phase_started_at = time.monotonic()

    def _run_one(
        host_id: str,
        host_label: str,
        evidence_id: str,
        tool_name: str,
        fn: Callable[[str, str], Any],
    ) -> PreExtractTaskResult:
        _emit(
            on_progress,
            "pre_extract_start",
            {
                "host_id": host_id,
                "host_label": host_label,
                "evidence_id": evidence_id,
                "plugin_tool_name": tool_name,
            },
        )
        started = time.monotonic()
        succeeded = False
        error_class: str | None = None
        error_message: str | None = None
        try:
            fn(evidence_id, str(case_dir))
            succeeded = True
        except Exception as exc:  # noqa: BLE001 — best-effort phase
            error_class = type(exc).__name__
            error_message = str(exc)[:200]
            logger.warning(
                "pre-extract %s on %s (host=%s) failed: %s: %s",
                tool_name,
                evidence_id,
                host_id,
                error_class,
                error_message,
            )
        duration = time.monotonic() - started
        task = PreExtractTaskResult(
            host_id=host_id,
            host_label=host_label,
            evidence_id=evidence_id,
            plugin_tool_name=tool_name,
            duration_seconds=duration,
            succeeded=succeeded,
            error_class=error_class,
            error_message=error_message,
        )
        _emit(
            on_progress,
            "pre_extract_done",
            {
                "host_id": host_id,
                "host_label": host_label,
                "evidence_id": evidence_id,
                "plugin_tool_name": tool_name,
                "duration_seconds": duration,
                "succeeded": succeeded,
                "error_class": error_class,
            },
        )
        return task

    with ThreadPoolExecutor(
        max_workers=max(1, max_workers),
        thread_name_prefix="pre-extract",
    ) as pool:
        futures = [pool.submit(_run_one, *t) for t in tasks]
        for fut in as_completed(futures):
            result.tasks.append(fut.result())

    result.total_duration_seconds = time.monotonic() - phase_started_at
    _emit(
        on_progress,
        "pre_extract_phase_done",
        {
            "task_count": len(result.tasks),
            "succeeded": result.succeeded_count,
            "failed": result.failed_count,
            "total_duration_seconds": result.total_duration_seconds,
        },
    )
    return result


def _emit(
    on_progress: Callable[[str, dict[str, Any]], None] | None,
    event: str,
    payload: dict[str, Any],
) -> None:
    if on_progress is None:
        return
    try:
        on_progress(event, payload)
    except Exception:  # noqa: BLE001 — observer must not crash the phase
        logger.exception(
            "on_progress callback raised on pre-extract event %s; suppressing",
            event,
        )


__all__ = [
    "PreExtractResult",
    "PreExtractTaskResult",
    "has_disk_evidence",
    "pre_extract_disk_tier1",
]
