"""Tier-1 typed MCP tools for disk-side artifact families.

Four tools — ``disk_mft_timeline``, ``disk_prefetch``, ``disk_evtx``,
``disk_registry`` — wrap SIFT-resident parsers for MFT, Prefetch, EVTX,
and Registry-hive artifacts that live on a mounted Windows disk image.

Pipeline (mirrors the memory-side `server.tools.memory` pattern):

  1. Resolve `evidence_id` via CASE.yaml; reject if not registered.
  2. Validate `artifact_class is disk_image`.
  3. Cache check — if an extraction already exists for this
     (evidence_id, plugin_name) pair, return the recomputed summary
     with `cached=True` and audit `<tool>:cached`.
  4. Otherwise: call ``mount_disk_image`` (cached per evidence_id),
     run the matching SIFT subprocess via the runner module, parse
     the output into typed records, persist the typed result to
     `case-data/extractions/<evidence_id>/<plugin_name>.json`, write
     the .sha256 sidecar, append a chain line to
     `case-data/extractions.jsonl`, and audit `<tool>` with the
     summary as output.
  5. Return a small (≤10 KB) Summary model carrying an
     ``ExtractionRef`` plus distribution / shape signal — never the
     full record set.

Per-record validation failures are still audit-logged as
`<tool>:record_validation_warning` lines and the bad row is skipped
— same convention as the Volatility wrappers.

Privilege model: the disk-mount utility (`server.runners.disk_mount`)
honors ``SIFT_DISK_PREMOUNTED_PATH`` for dev / CI environments where
``ewfmount`` / ``mount -o ro,loop`` cannot be executed without root.
The agent never sees that env var; the resolver inside the mount
utility decides which path to take.

Per CLAUDE.md "Hard Rule" #3 — `register_evidence` resolves the
absolute path; the disk tools take only `evidence_id` and look the
absolute path up internally before handing it to ``mount_disk_image``.
The agent cannot construct a path through this surface.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel, ValidationError

from server.audit import append_audit_entry, peek_next_line_number
from server.extractions import (
    HashMismatchError,
    extraction_exists,
    load_extraction,
    write_extraction,
)
from server.runners.disk_mount import (
    MountError,
    mount_disk_image,
    parse_evtx,
    parse_plaso_jsonl,
    parse_prefetch,
    parse_regripper,
    run_evtx_dump,
    run_log2timeline_mft,
    run_prefetch,
    run_regripper,
)
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    EvtxRecord,
    EvtxResult,
    EvtxSummary,
    ExtractionRef,
    MftTimelineRecord,
    MftTimelineResult,
    MftTimelineSummary,
    PluginName,
    PrefetchRecord,
    PrefetchResult,
    PrefetchSummary,
    RegistryRecord,
    RegistryResult,
    RegistrySummary,
)


_MFT_PLUGIN: PluginName = "disk.mft.MftTimeline"
_PREFETCH_PLUGIN: PluginName = "disk.prefetch.Prefetch"
_EVTX_PLUGIN: PluginName = "disk.evtx.EventLog"
_REGISTRY_PLUGIN: PluginName = "disk.registry.Registry"

_MFT_TOOL_NAME = "disk_mft_timeline"
_PREFETCH_TOOL_NAME = "disk_prefetch"
_EVTX_TOOL_NAME = "disk_evtx"
_REGISTRY_TOOL_NAME = "disk_registry"

_CASE_FILENAME = "CASE.yaml"


# Known-interesting registry key-path prefixes for the persistence
# triage signal. The summary's `interesting_paths_distribution`
# bucket name maps onto these prefixes; everything else falls under
# `"other"`. Bounded set — adding a bucket requires extending this
# tuple AND the matching test in `tests/test_disk_registry.py`.
_INTERESTING_KEY_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("Run", "Microsoft\\Windows\\CurrentVersion\\Run"),
    ("RunOnce", "Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("Services", "ControlSet001\\Services"),
    ("Policies", "Microsoft\\Windows\\CurrentVersion\\Policies"),
)


class _ToolRecordWarning(BaseModel):
    """Audit payload for a disk-tool row that failed schema validation.

    Same shape as the memory-tool warning — embeds the tool name in
    the warning_type so a chain reader can grep distinctly.
    """

    warning_type: str
    record_index: int
    validation_error: str


class _RejectionReason(StrEnum):
    """Why a disk-tool call was rejected before serving a result."""

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    WRONG_ARTIFACT_CLASS = "wrong_artifact_class"
    MOUNT_FAILED = "mount_failed"
    HASH_MISMATCH = "hash_mismatch"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected disk-tool call."""

    reason: _RejectionReason
    evidence_id: str


def _resolve_evidence(evidence_id: str, case_dir: Path) -> EvidenceRecord | None:
    """Look up an evidence_id in CASE.yaml.

    Returns ``None`` instead of raising so the caller can audit-log
    the rejection before raising the sanitized exception. Mirrors
    the memory-tool resolver's contract.
    """
    case_yaml = case_dir / _CASE_FILENAME
    if not case_yaml.exists():
        return None
    with case_yaml.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    for entry in doc.get("evidence", []):
        if entry.get("evidence_id") == evidence_id:
            return EvidenceRecord.model_validate(entry)
    return None


def _log_tool_rejection(
    case_dir: Path,
    tool_name: str,
    reason: _RejectionReason,
    evidence_id: str,
) -> None:
    """Append one rejection line to the audit chain.

    Same byte-shape as the memory-tool rejection helper. Suffix is
    `<tool>:rejected_<reason>`.
    """
    rejection = _RejectionRecord(reason=reason, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{tool_name}:rejected_{reason.value}",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=rejection,
    )


def _log_hash_mismatch(
    case_dir: Path,
    tool_name: str,
    evidence_id: str,
) -> None:
    """Append a hash-mismatch line to the audit chain."""
    rejection = _RejectionRecord(reason=_RejectionReason.HASH_MISMATCH, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{tool_name}:hash_mismatch",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=rejection,
    )


def _resolve_and_mount(
    case_dir_path: Path, evidence_id: str, tool_name: str
) -> tuple[EvidenceRecord, str]:
    """Resolution + artifact-class + mount gate.

    Returns ``(EvidenceRecord, mount_path)`` on success. On any
    failure audits the rejection and raises a sanitized
    ``ValueError`` whose message does NOT echo the offending
    evidence_id back at the agent.
    """
    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        _log_tool_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.DISK_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        raise ValueError("evidence is not a disk image")

    try:
        mount_path = mount_disk_image(evidence_id, record.absolute_path)
    except MountError:
        _log_tool_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.MOUNT_FAILED,
            evidence_id,
        )
        raise ValueError("disk-image mount failed")

    return record, mount_path


# ---------------------------------------------------------------------------
# Summary computers — derive the tier-1 Summary from a list of
# record dicts. Same per-tool helper pattern as the memory module.
# ---------------------------------------------------------------------------


def _compute_mft_summary(ref: ExtractionRef, records: list[dict]) -> MftTimelineSummary:
    """Distribution + recency signal for MFT timeline rows."""
    type_counter: Counter[str] = Counter(r["entry_type"] for r in records)
    path_counter: Counter[str] = Counter(r["full_path"] for r in records)
    timestamps = [r["timestamp"] for r in records if r.get("timestamp")]
    # Records arriving from the in-memory flow have datetime objects;
    # records loaded from JSON have ISO strings. Normalize for the
    # min/max comparison without round-tripping through pydantic.
    parsed_ts: list[datetime] = []
    for t in timestamps:
        if isinstance(t, datetime):
            parsed_ts.append(t)
            continue
        try:
            parsed = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed_ts.append(parsed)
        except (ValueError, TypeError):
            continue
    earliest = min(parsed_ts) if parsed_ts else None
    latest = max(parsed_ts) if parsed_ts else None
    return MftTimelineSummary(
        extraction=ref,
        entry_type_distribution=dict(type_counter),
        earliest_timestamp=earliest,
        latest_timestamp=latest,
        top_paths=list(path_counter.most_common(10)),
        distinct_paths=len(path_counter),
    )


def _compute_prefetch_summary(ref: ExtractionRef, records: list[dict]) -> PrefetchSummary:
    """Distribution + recency signal for prefetch entries."""
    name_counter: Counter[str] = Counter(r["executable_name"] for r in records)
    run_count_by_name: dict[str, int] = {}
    earliest: datetime | None = None
    latest: datetime | None = None
    total_runs = 0
    for r in records:
        run_count = r.get("run_count") or 0
        total_runs += run_count
        run_count_by_name[r["executable_name"]] = (
            run_count_by_name.get(r["executable_name"], 0) + run_count
        )
        for raw_t in r.get("last_run_times") or []:
            try:
                if isinstance(raw_t, datetime):
                    parsed = raw_t
                else:
                    parsed = datetime.fromisoformat(str(raw_t).replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            if earliest is None or parsed < earliest:
                earliest = parsed
            if latest is None or parsed > latest:
                latest = parsed
    top = sorted(run_count_by_name.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return PrefetchSummary(
        extraction=ref,
        distinct_executables=len(name_counter),
        total_run_count=total_runs,
        top_executables=top,
        earliest_run_time=earliest,
        latest_run_time=latest,
    )


def _compute_evtx_summary(ref: ExtractionRef, records: list[dict]) -> EvtxSummary:
    """Distribution-only summary for Windows event records."""
    eid_counter: Counter[int] = Counter(r["event_id"] for r in records)
    channel_counter: Counter[str] = Counter(r["channel"] for r in records)
    parsed_ts: list[datetime] = []
    for r in records:
        t = r.get("timestamp")
        if isinstance(t, datetime):
            parsed_ts.append(t)
            continue
        try:
            parsed = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed_ts.append(parsed)
        except (ValueError, TypeError):
            continue
    earliest = min(parsed_ts) if parsed_ts else None
    latest = max(parsed_ts) if parsed_ts else None
    return EvtxSummary(
        extraction=ref,
        event_id_distribution=list(eid_counter.most_common(10)),
        channel_distribution=dict(channel_counter),
        earliest_timestamp=earliest,
        latest_timestamp=latest,
        distinct_event_ids=len(eid_counter),
    )


def _interesting_bucket_for(key_path: str) -> str:
    """Bucket a registry key path for the summary's
    `interesting_paths_distribution`.

    Returns one of the named prefixes (`Run`, `RunOnce`, `Services`,
    `Policies`) or `"other"`. Substring match is intentional: a key
    path can have varying ControlSet numbers (ControlSet001 vs
    ControlSet002 vs CurrentControlSet) so we match on the suffix
    after the changing prefix.
    """
    for bucket, prefix in _INTERESTING_KEY_PATH_PREFIXES:
        if prefix in key_path:
            return bucket
    return "other"


def _compute_registry_summary(ref: ExtractionRef, records: list[dict]) -> RegistrySummary:
    """Distribution summary for registry entries."""
    hive_counter: Counter[str] = Counter(r["hive_name"] for r in records)
    interesting_counter: Counter[str] = Counter(
        _interesting_bucket_for(r["key_path"]) for r in records
    )
    key_path_counter: Counter[str] = Counter(r["key_path"] for r in records)
    return RegistrySummary(
        extraction=ref,
        hive_distribution=dict(hive_counter),
        interesting_paths_distribution=dict(interesting_counter),
        distinct_key_paths=len(key_path_counter),
        top_key_paths=list(key_path_counter.most_common(10)),
    )


# ---------------------------------------------------------------------------
# Cached / fresh runners. Disk-side equivalents of the memory-side
# helpers; signatures differ because the disk runners return four
# values (stdout, command_string, runtime_seconds, tool_version)
# whereas the memory runners return three (no per-call tool_version
# capture — Volatility's PACKAGE_VERSION is captured separately by
# `get_vol_version`).
# ---------------------------------------------------------------------------


def _serve_cached(
    case_dir_path: Path,
    evidence_id: str,
    plugin_name: PluginName,
    tool_name: str,
    list_field_name: str,
    summary_fn: Callable[[ExtractionRef, list[dict]], BaseModel],
) -> BaseModel:
    """Cache-hit path. Same byte-shape as the memory module's
    `_serve_cached` — duplicated rather than cross-imported because
    the two tool families' import graphs are intentionally
    independent (changing the memory module's helper signature
    should not break disk tools)."""
    try:
        ref, parsed = load_extraction(case_dir_path, evidence_id, plugin_name)
    except HashMismatchError:
        _log_hash_mismatch(case_dir_path, tool_name, evidence_id)
        raise ValueError("cached extraction failed integrity verification")

    records = parsed.get(list_field_name, [])
    summary = summary_fn(ref, records)

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=f"{tool_name}:cached",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=summary,
    )
    return summary


def _serve_fresh(
    case_dir_path: Path,
    evidence_id: str,
    mount_path: str,
    plugin_name: PluginName,
    tool_name: str,
    list_field_name: str,
    runner: Callable[..., tuple[str, str, float, str]],
    parser: Callable[[str], list[dict]],
    record_cls: type[BaseModel],
    result_cls: type[BaseModel],
    summary_fn: Callable[[ExtractionRef, list[dict]], BaseModel],
) -> BaseModel:
    """Cache-miss path. Invokes the disk runner, validates each row,
    persists the typed result, recomputes the summary, audits the
    success line."""
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds, tool_version = runner(mount_path)
    raw_rows = parser(stdout)

    validated: list[BaseModel] = []
    warning_type = f"{tool_name}_record_validation_failed"
    for index, raw in enumerate(raw_rows):
        try:
            validated.append(record_cls(**raw))
        except ValidationError as exc:
            warning = _ToolRecordWarning(
                warning_type=warning_type,
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=f"{tool_name}:record_validation_warning",
                evidence_id=evidence_id,
                input_args={"record_index": index},
                output=warning,
            )

    result_kwargs = {
        list_field_name: validated,
        "evidence_id": evidence_id,
        "plugin_name": plugin_name,
        "tool_version": tool_version,
        "command_executed": command_string,
        "runtime_seconds": runtime_seconds,
        "invoked_at": invoked_at,
    }
    result = result_cls(**result_kwargs)

    audit_line = peek_next_line_number(case_dir_path)
    ref = write_extraction(
        case_dir=case_dir_path,
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        result=result,
        runtime_seconds=runtime_seconds,
        audit_line=audit_line,
    )

    record_dicts = [r.model_dump(mode="json") for r in validated]
    summary = summary_fn(ref, record_dicts)

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=tool_name,
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=summary,
    )
    return summary


# ---------------------------------------------------------------------------
# Public tier-1 entrypoints.
# ---------------------------------------------------------------------------


def disk_mft_timeline(evidence_id: str, case_dir: str = "case-data") -> MftTimelineSummary:
    """Run plaso's MFT-only timeline against a registered disk_image.

    Two-step pipeline (log2timeline.py + psort.py); see
    `server.runners.disk_mount.run_log2timeline_mft` for details.
    Returns a `MftTimelineSummary` with entry-type distribution,
    timestamp range, and a top-N list of paths by entry count.
    Specific timeline rows come from
    `query_records(plugin_name="disk.mft.MftTimeline", ...)`.
    """
    case_dir_path = Path(case_dir).resolve()
    _, mount_path = _resolve_and_mount(case_dir_path, evidence_id, _MFT_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], MftTimelineSummary] = _compute_mft_summary

    if extraction_exists(case_dir_path, evidence_id, _MFT_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _MFT_PLUGIN,
            _MFT_TOOL_NAME,
            "entries",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        mount_path,
        _MFT_PLUGIN,
        _MFT_TOOL_NAME,
        "entries",
        run_log2timeline_mft,
        parse_plaso_jsonl,
        MftTimelineRecord,
        MftTimelineResult,
        summary_fn,
    )


def disk_prefetch(evidence_id: str, case_dir: str = "case-data") -> PrefetchSummary:
    """Run a prefetch parser against `Windows/Prefetch/*.pf` on the
    registered disk_image. Returns a `PrefetchSummary` with
    distinct-executable count, total-run-count, top-N executables by
    run count, and a most-recent / earliest run-time pair. Specific
    prefetch entries come from
    `query_records(plugin_name="disk.prefetch.Prefetch", ...)`.
    """
    case_dir_path = Path(case_dir).resolve()
    _, mount_path = _resolve_and_mount(case_dir_path, evidence_id, _PREFETCH_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], PrefetchSummary] = _compute_prefetch_summary

    if extraction_exists(case_dir_path, evidence_id, _PREFETCH_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _PREFETCH_PLUGIN,
            _PREFETCH_TOOL_NAME,
            "entries",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        mount_path,
        _PREFETCH_PLUGIN,
        _PREFETCH_TOOL_NAME,
        "entries",
        run_prefetch,
        parse_prefetch,
        PrefetchRecord,
        PrefetchResult,
        summary_fn,
    )


def disk_evtx(evidence_id: str, case_dir: str = "case-data") -> EvtxSummary:
    """Run python-evtx against Security + System logs on the
    registered disk_image. Returns an `EvtxSummary` with event-id
    distribution (top 10), channel distribution, timestamp range,
    and distinct event-id count. Specific events come from
    `query_records(plugin_name="disk.evtx.EventLog", ...)`.

    `message_summary` is treated as untrusted evidence content per
    `PLUGIN_UNTRUSTED_RECORD_FIELDS`. The parser truncates each
    summary to 500 characters before validation.
    """
    case_dir_path = Path(case_dir).resolve()
    _, mount_path = _resolve_and_mount(case_dir_path, evidence_id, _EVTX_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], EvtxSummary] = _compute_evtx_summary

    if extraction_exists(case_dir_path, evidence_id, _EVTX_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _EVTX_PLUGIN,
            _EVTX_TOOL_NAME,
            "events",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        mount_path,
        _EVTX_PLUGIN,
        _EVTX_TOOL_NAME,
        "events",
        run_evtx_dump,
        parse_evtx,
        EvtxRecord,
        EvtxResult,
        summary_fn,
    )


def disk_registry(evidence_id: str, case_dir: str = "case-data") -> RegistrySummary:
    """Run RegRipper across SYSTEM / SOFTWARE / SAM / NTUSER.DAT
    hives on the registered disk_image. Returns a `RegistrySummary`
    with per-hive count, persistence-key bucket distribution
    (Run / RunOnce / Services / Policies / other), distinct key
    count, and a top-N list of key paths. Specific registry
    entries come from
    `query_records(plugin_name="disk.registry.Registry", ...)`.

    `value_data` is treated as untrusted evidence content per
    `PLUGIN_UNTRUSTED_RECORD_FIELDS`. The parser truncates each
    value to 500 characters before validation.
    """
    case_dir_path = Path(case_dir).resolve()
    _, mount_path = _resolve_and_mount(case_dir_path, evidence_id, _REGISTRY_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], RegistrySummary] = _compute_registry_summary

    if extraction_exists(case_dir_path, evidence_id, _REGISTRY_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _REGISTRY_PLUGIN,
            _REGISTRY_TOOL_NAME,
            "keys",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        mount_path,
        _REGISTRY_PLUGIN,
        _REGISTRY_TOOL_NAME,
        "keys",
        run_regripper,
        parse_regripper,
        RegistryRecord,
        RegistryResult,
        summary_fn,
    )


__all__ = [
    "disk_evtx",
    "disk_mft_timeline",
    "disk_prefetch",
    "disk_registry",
]
