"""Tier-1 typed MCP tools for the supported Volatility memory plugins.

Tier-1 tools (`vol_pslist`, `vol_psscan`, `vol_pstree`, `vol_netscan`,
`vol_cmdline`, `vol_malfind`) each compose the same pipeline:

  1. Resolve `evidence_id` via CASE.yaml; reject if not registered.
  2. Validate `artifact_class is memory_image`.
  3. Cache check — if an extraction already exists for this
     (evidence_id, plugin_name) pair, return a recomputed summary
     with `cached=True` and audit `<tool>:cached` (no Volatility
     run, no extractions.jsonl line).
  4. Otherwise, validate the registered absolute_path lives under
     `<case_dir>/evidence/`, capture the Volatility version, invoke
     the local subprocess runner against that path, parse the
     output, persist a typed result to `case-data/extractions/
     <evidence_id>/<plugin_name>.json`, write the .sha256 sidecar,
     append a chain line to `case-data/extractions.jsonl`, and
     audit `<tool>` with the summary as output.
  5. In both branches, return a small (≤10 KB) Summary model carrying
     an `ExtractionRef` plus distribution / shape signal — never the
     full record set. Tier-2 tools compose narrowed answers from the
     stored extractions.

Architectural rationale: the process_analyst v1 experiment
(2026-05-05) showed that the LLM tool-result token budget collapses
the "tool returns full data" pattern on a 19 GB Windows 10 image
(459 KB pslist, 800 KB pstree). Tier-1 returns a fixed-shape summary;
tier-2 reads from disk and projects.

Per-record validation failures are still audit-logged as
`vol_<tool>:record_validation_warning` lines and the bad row is
skipped — partial extractions are valuable, and the failure mode
goes in the audit chain rather than bubbling as an exception.

Architectural guarantee per CLAUDE.md "Ground truth isolation" rule 3:
the agent cannot construct a path and cannot name a plugin. Plugin
names are pinned in this module; the path comes from the evidence
registry. The runner's plugin_name regex is defense-in-depth.

Helpers (extracted as the four tier-1 tools collapsed onto a shared
cache-aware pipeline — the pre-refactor "rule of three" set has now
become a "rule of four with two sub-paths each", justifying a
slightly tighter shape):

  - ``_log_tool_rejection`` — audited rejection helper, parameterized
    on tool_name and reason
  - ``_log_hash_mismatch`` — special case of rejection for
    cache-integrity failures, emits a distinct ``:hash_mismatch``
    audit suffix per the cache contract
  - ``_resolve_and_validate`` — resolution + artifact-class +
    path-confinement gate shared across all tier-1 entrypoints
  - ``_serve_cached`` / ``_serve_fresh`` — shared cache-hit /
    cache-miss bodies; each public tool is now a thin dispatcher
  - ``_compute_*_summary`` — per-plugin summary computers; pslist
    and psscan share the body since their record schemas are aliased
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
from server.runners.local import (
    get_vol_version,
    parse_cmdline_json,
    parse_malfind_json,
    parse_netscan_json,
    parse_pstree_json,
    parse_volatility_json,
    run_vol_plugin,
)
from server.schemas import (
    ArtifactClass,
    CmdLineResult,
    CmdLineSummary,
    EvidenceRecord,
    ExtractionRef,
    MalfindRecord,
    MalfindResult,
    MalfindSummary,
    NetscanResult,
    NetscanSummary,
    NetworkRecord,
    PluginName,
    ProcessCmdLineRecord,
    ProcessRecord,
    ProcessScanRecord,
    ProcessTreeRecord,
    PslistResult,
    PslistSummary,
    PsscanResult,
    PsscanSummary,
    PstreeResult,
    PstreeSummary,
)


_PSLIST_PLUGIN: PluginName = "windows.pslist.PsList"
_PSSCAN_PLUGIN: PluginName = "windows.psscan.PsScan"
_PSTREE_PLUGIN: PluginName = "windows.pstree.PsTree"
_NETSCAN_PLUGIN: PluginName = "windows.netscan.NetScan"
_CMDLINE_PLUGIN: PluginName = "windows.cmdline.CmdLine"
_MALFIND_PLUGIN: PluginName = "windows.malfind.Malfind"
_CASE_FILENAME = "CASE.yaml"
_PSLIST_TOOL_NAME = "vol_pslist"
_PSSCAN_TOOL_NAME = "vol_psscan"
_PSTREE_TOOL_NAME = "vol_pstree"
_NETSCAN_TOOL_NAME = "vol_netscan"
_CMDLINE_TOOL_NAME = "vol_cmdline"
_MALFIND_TOOL_NAME = "vol_malfind"

# Pool-tag scanning walks the full memory layer rather than the active
# EPROCESS list, so psscan is materially slower than pslist. On Rocba
# (19 GB Windows 10 image, SIFT 2026.1 / Vol 3 2.27.0) one observed run
# was 6m36s; runner default is 300s so this tool overrides explicitly.
# 900s gives ~2× the observed runtime as headroom for slower disks or
# the cold-cache case where Volatility re-resolves PDB symbols.
_PSSCAN_TIMEOUT_SECONDS = 900

# Netscan also pool-scans, walks more pool families than psscan
# (TCP endpoint, TCP listener, UDP endpoint), and is empirically
# slower on Rocba: 8m57s observed. 1200s gives ~33% headroom over
# that. Vol 3 sometimes hits a slow path on heavily-fragmented
# heaps; the cushion is for that, not normal operation.
_NETSCAN_TIMEOUT_SECONDS = 1200


class _ToolRecordWarning(BaseModel):
    """Audit payload for a Volatility row that failed schema validation.

    `warning_type` is constructed as ``vol_<tool>_record_validation_failed``
    by the caller — embedding the tool name in the warning_type field
    keeps the failure greppable from the JSONL when multiple plugin
    tools have run against the same image.

    Persisted into the chain only via its `output_hash`. The full
    warning text is not written elsewhere in the prototype; recovery
    is bounded to "row at index N was skipped". If full recoverability
    becomes required, write the warning blob to extractions/ and
    reference the path here.
    """

    warning_type: str
    record_index: int
    validation_error: str


class _RejectionReason(StrEnum):
    """Why a memory-tool call was rejected before serving a result."""

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    WRONG_ARTIFACT_CLASS = "wrong_artifact_class"
    PATH_OUTSIDE_EVIDENCE_DIR = "path_outside_evidence_dir"
    # Cache-read tampering: stored .json bytes do not match the
    # extractions chain entry's recorded sha256, or the .sha256
    # sidecar disagrees with the chain. Audited under the
    # ``<tool>:hash_mismatch`` tool_name suffix per the week-5
    # cache contract.
    HASH_MISMATCH = "hash_mismatch"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected memory-tool call.

    Per the Phase B.3 follow-up: every rejection writes a chain line so
    rejection cannot become an unrecorded probe channel. The
    `evidence_id` is captured here (operator-visible via the audit log)
    but is never echoed in the sanitized exception the agent sees —
    that asymmetry is the whole point.
    """

    reason: _RejectionReason
    evidence_id: str


def _validate_path_under_evidence(absolute_path: str, evidence_root: Path) -> None:
    """Confirm `absolute_path` lives under `<case_dir>/evidence/`.

    `register_evidence` enforces this confinement at registration
    time, so a registered evidence_id should never resolve to a
    path outside the tree. The check here is defense-in-depth
    against a hand-edited CASE.yaml.

    Sanitized: the rejection message never echoes the offending
    path, per the 2026-05-05 MCP error-message sanitization rule.
    """
    evidence_root = evidence_root.resolve()
    candidate = Path(absolute_path).resolve()
    try:
        candidate.relative_to(evidence_root)
    except ValueError:
        raise ValueError("evidence path is not under the case evidence directory")


def _resolve_evidence(evidence_id: str, case_dir: Path) -> EvidenceRecord | None:
    """Look up an evidence_id in CASE.yaml.

    Returns ``None`` instead of raising so the caller can audit-log
    the rejection before raising the sanitized exception. Keeps the
    rejection-write path straight-line (no try/except for control
    flow) and makes the "every rejection writes a chain line" rule
    visible at the call site.
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

    The rejection's tool_name is ``<tool_name>:rejected_<reason>`` —
    greppable from the JSONL and unambiguous about which rejection
    path fired and which tool fired it. Used by all memory-tool
    wrappers; behavior is byte-identical to the per-tool helpers it
    replaces (same `_RejectionRecord` shape, same input_args, same
    tool_name string format).
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
    """Append a hash-mismatch line to the audit chain.

    Distinct suffix (`<tool>:hash_mismatch`, no ``:rejected_`` infix)
    from the regular rejection paths because hash mismatch is not an
    input-validation failure — the agent's input was valid; the
    cache itself is corrupted. The audit suffix difference is what an
    operator greps to find tampering events vs. agent-side probes.
    """
    rejection = _RejectionRecord(reason=_RejectionReason.HASH_MISMATCH, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{tool_name}:hash_mismatch",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=rejection,
    )


def _resolve_and_validate(
    case_dir_path: Path, evidence_id: str, tool_name: str
) -> tuple[EvidenceRecord, str]:
    """Resolution + artifact-class + path-confinement gate.

    Returns ``(EvidenceRecord, image_path)`` on success. On any
    failure audits the rejection and raises a sanitized
    ``ValueError`` whose message does NOT echo the offending
    evidence_id back at the agent. Three rejection paths share
    this body.

    `image_path` is the registered absolute_path — local to the
    host running the MCP server, since the local runner does not
    cross any host/VM boundary. The path-confinement check is
    defense-in-depth against hand-edited ``CASE.yaml``.
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

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        raise ValueError("evidence is not a memory image")

    evidence_root = case_dir_path / "evidence"
    try:
        _validate_path_under_evidence(record.absolute_path, evidence_root)
    except ValueError:
        _log_tool_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.PATH_OUTSIDE_EVIDENCE_DIR,
            evidence_id,
        )
        raise

    return record, record.absolute_path


# ---------------------------------------------------------------------------
# Summary computers — derive the tier-1 Summary from a list of record dicts.
# Pslist and psscan share a body because ProcessScanRecord is aliased to
# ProcessRecord; a separate helper for each keeps the public-tool dispatch
# obvious at the call site.
# ---------------------------------------------------------------------------


def _compute_process_summary(
    ref: ExtractionRef,
    records: list[dict],
    summary_cls: type[PslistSummary],
) -> PslistSummary:
    """Shared body for pslist and psscan summaries.

    `records` are dicts with snake_case keys (pydantic
    `model_dump(mode="json")` output, or `json.loads` on the stored
    extraction). Empty record list yields a zero-shaped summary with
    `pid_range=(0, 0)` — pydantic's PslistSummary accepts it because
    the int fields have ge=0 and pid_range is a free tuple.
    """
    pids = [r["pid"] for r in records]
    image_names = [r["image_file_name"] for r in records]
    name_counter = Counter(image_names)
    return summary_cls(
        extraction=ref,
        unique_image_names=len(set(image_names)),
        null_create_time_count=sum(1 for r in records if r.get("create_time") is None),
        with_exit_time_count=sum(1 for r in records if r.get("exit_time") is not None),
        distinct_ppids=len({r["ppid"] for r in records}),
        top_image_names=list(name_counter.most_common(10)),
        pid_range=(min(pids), max(pids)) if pids else (0, 0),
    )


def _compute_pstree_summary(ref: ExtractionRef, records: list[dict]) -> PstreeSummary:
    """Walk the recursive pstree to derive shape signal.

    Computes max_depth, depth_distribution, largest_subtree, and
    orphan_count from the recursive `children` field. All four are
    cheap (single pass over the tree); we walk twice — once for
    depth/largest-subtree, once for the all-pids set used by orphan
    detection — to keep the recursive helpers small.
    """
    top_level_root_count = len(records)

    distribution: dict[int, int] = {}
    max_depth = 0
    largest_pid = 0
    largest_count = 0
    all_pids: set[int] = set()

    def collect_pids(node: dict) -> None:
        all_pids.add(node["pid"])
        for child in node.get("children", []) or []:
            collect_pids(child)

    def walk(node: dict, depth: int) -> tuple[int, int]:
        distribution[depth] = distribution.get(depth, 0) + 1
        deepest = depth
        descendant_count = 0
        for child in node.get("children", []) or []:
            child_deepest, child_count = walk(child, depth + 1)
            deepest = max(deepest, child_deepest)
            descendant_count += 1 + child_count
        return deepest, descendant_count

    for root in records:
        collect_pids(root)

    for root in records:
        d, count = walk(root, 0)
        if d > max_depth:
            max_depth = d
        if count > largest_count:
            largest_count = count
            largest_pid = root["pid"]

    # Orphan: top-level whose ppid is not anywhere in the tree, AND
    # ppid != 0 (PID 4 / System has PPID 0 by convention; not an orphan).
    orphan_count = sum(1 for r in records if r["ppid"] != 0 and r["ppid"] not in all_pids)

    return PstreeSummary(
        extraction=ref,
        top_level_root_count=top_level_root_count,
        max_depth=max_depth,
        depth_distribution=distribution,
        largest_subtree=(largest_pid, largest_count),
        orphan_count=orphan_count,
    )


def _compute_cmdline_summary(ref: ExtractionRef, records: list[dict]) -> CmdLineSummary:
    """Distribution + gap signal for cmdline records.

    `null_cmdline_count` is the load-bearing field — it answers the
    "how much of the user-space parameters block actually paged in"
    question that pslist alone cannot answer (pslist has no cmdline
    field; pstree's `cmd` projection gives the same gap but as a
    side-channel of the tree).
    """
    pids = [r["pid"] for r in records]
    process_names = [r["process_name"] for r in records]
    name_counter = Counter(process_names)
    null_count = sum(1 for r in records if r.get("cmdline") is None)
    distinct_cmdlines = len({r["cmdline"] for r in records if r.get("cmdline") is not None})
    return CmdLineSummary(
        extraction=ref,
        unique_process_names=len(set(process_names)),
        null_cmdline_count=null_count,
        with_cmdline_count=len(records) - null_count,
        distinct_cmdlines=distinct_cmdlines,
        top_process_names=list(name_counter.most_common(10)),
        pid_range=(min(pids), max(pids)) if pids else (0, 0),
    )


def _compute_malfind_summary(ref: ExtractionRef, records: list[dict]) -> MalfindSummary:
    """Distribution-only summary for malfind detections.

    Per-protection breakdown is the most diagnostic field —
    `PAGE_EXECUTE_READWRITE` count > 0 is what surfaces shellcode
    candidates. `vad_tag_distribution` is bounded naturally
    (typically 1-3 tags); we keep the full dict rather than
    truncating.
    """
    pids = [r["pid"] for r in records]
    process_names = [r["process_name"] for r in records]
    name_counter = Counter(process_names)
    proto_counter: Counter[str] = Counter(r["protection"] for r in records)
    tag_counter: Counter[str] = Counter(r["vad_tag"] for r in records)
    return MalfindSummary(
        extraction=ref,
        unique_process_names=len(set(process_names)),
        detections_by_process=list(name_counter.most_common(10)),
        protection_distribution=dict(proto_counter),
        vad_tag_distribution=dict(tag_counter),
        pid_range=(min(pids), max(pids)) if pids else (0, 0),
    )


def _compute_netscan_summary(ref: ExtractionRef, records: list[dict]) -> NetscanSummary:
    """Distribution-only summary for netscan records."""
    proto_counter: Counter[str] = Counter(r["proto"] for r in records)
    tcp_state_counter: Counter[str] = Counter(
        r.get("state", "") for r in records if str(r.get("proto", "")).startswith("TCP")
    )
    null_owner_count = sum(1 for r in records if r.get("owner") is None)
    listening_count = sum(1 for r in records if r.get("state") == "LISTENING")
    established_count = sum(1 for r in records if r.get("state") == "ESTABLISHED")
    distinct_foreign = len(
        {r.get("foreign_addr") for r in records if r.get("foreign_addr") not in (None, "*", "")}
    )
    return NetscanSummary(
        extraction=ref,
        protocol_distribution=dict(proto_counter),
        tcp_state_distribution=dict(tcp_state_counter),
        null_owner_count=null_owner_count,
        listening_port_count=listening_count,
        established_count=established_count,
        distinct_foreign_addrs=distinct_foreign,
    )


# ---------------------------------------------------------------------------
# Cached / fresh path runners. Each public tool resolves first (so the
# CASE.yaml-not-registered probe is still audited), then either serves a
# cached extraction or invokes Volatility for the first time.
# ---------------------------------------------------------------------------


def _serve_cached(
    case_dir_path: Path,
    evidence_id: str,
    plugin_name: PluginName,
    tool_name: str,
    list_field_name: str,
    summary_fn: Callable[[ExtractionRef, list[dict]], BaseModel],
) -> BaseModel:
    """Cache-hit path. Loads the stored extraction, verifies hashes,
    recomputes the summary, audits ``<tool>:cached``."""
    try:
        ref, parsed = load_extraction(case_dir_path, evidence_id, plugin_name)
    except HashMismatchError:
        _log_hash_mismatch(case_dir_path, tool_name, evidence_id)
        # Sanitized: do not tell the agent which file diverged.
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
    image_path: str,
    plugin_name: PluginName,
    tool_name: str,
    list_field_name: str,
    parser: Callable[[str], list[dict]],
    record_cls: type[BaseModel],
    result_cls: type[BaseModel],
    summary_fn: Callable[[ExtractionRef, list[dict]], BaseModel],
    timeout_seconds: int | None = None,
) -> BaseModel:
    """Cache-miss path. Invokes Volatility, validates each row, persists
    the typed result, recomputes the summary, audits ``<tool>``.

    Per-record ValidationError lands as a
    `<tool>:record_validation_warning` line and the bad row is
    skipped. Pstree validates whole subtrees at once (recursive
    pydantic), so for that plugin the granularity is per-top-level —
    a single corrupt descendant skips its entire subtree.
    """
    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    if timeout_seconds is None:
        stdout, command_string, runtime_seconds = run_vol_plugin(plugin_name, image_path)
    else:
        stdout, command_string, runtime_seconds = run_vol_plugin(
            plugin_name, image_path, timeout_seconds=timeout_seconds
        )
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
        "volatility_version": volatility_version,
        "command_executed": command_string,
        "runtime_seconds": runtime_seconds,
        "invoked_at": invoked_at,
    }
    result = result_cls(**result_kwargs)

    # Peek the audit line where this fresh-call's success entry will
    # land. Must come AFTER the per-record validation warnings above
    # (which append to the chain). The peeked line is what the
    # extractions chain entry and the returned `ExtractionRef` will
    # carry as `audit_line`, so the analyst can reference it in
    # `record_finding`'s `EvidenceRef` without probing.
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
# Public tier-1 entrypoints. Each is a thin dispatcher over the shared
# resolve / cache-check / serve pipeline. Constants and per-plugin
# parameters are captured at the call site so each tool reads top-down
# without indirection.
# ---------------------------------------------------------------------------


def vol_pslist(evidence_id: str, case_dir: str = "case-data") -> PslistSummary:
    """Run windows.pslist.PsList against a registered memory_image.

    On cache hit: re-derives PslistSummary from the stored extraction
    (`cached=True`, `runtime_seconds=None`); audits ``vol_pslist:cached``.
    On cache miss: invokes Volatility, persists the full PslistResult to
    `case-data/extractions/<evidence_id>/windows.pslist.PsList.json`,
    audits ``vol_pslist`` with the summary as output, and writes one
    line to ``extractions.jsonl``.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _PSLIST_TOOL_NAME)

    def summary_fn(ref: ExtractionRef, records: list[dict]) -> PslistSummary:
        return _compute_process_summary(ref, records, PslistSummary)

    if extraction_exists(case_dir_path, evidence_id, _PSLIST_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _PSLIST_PLUGIN,
            _PSLIST_TOOL_NAME,
            "processes",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _PSLIST_PLUGIN,
        _PSLIST_TOOL_NAME,
        "processes",
        parse_volatility_json,
        ProcessRecord,
        PslistResult,
        summary_fn,
    )


def vol_psscan(evidence_id: str, case_dir: str = "case-data") -> PsscanSummary:
    """Run windows.psscan.PsScan against a registered memory_image.

    Same cache contract and persistence as `vol_pslist`. Pool-tag
    scanning surfaces processes pslist's active-list walk misses
    (terminated, hidden, unlinked); the cross-plugin diff is what
    `set_difference(plugin_a=psscan, plugin_b=pslist, key="pid",
    direction="a_minus_b")` exposes for the validator.

    Cost: 5–10 minutes per fresh call against a 19 GB Windows 10 image
    (Rocba: 6m36s observed). Runner timeout bumped to 900 s.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _PSSCAN_TOOL_NAME)

    def summary_fn(ref: ExtractionRef, records: list[dict]) -> PsscanSummary:
        return _compute_process_summary(ref, records, PsscanSummary)

    if extraction_exists(case_dir_path, evidence_id, _PSSCAN_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _PSSCAN_PLUGIN,
            _PSSCAN_TOOL_NAME,
            "processes",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _PSSCAN_PLUGIN,
        _PSSCAN_TOOL_NAME,
        "processes",
        parse_volatility_json,
        ProcessScanRecord,
        PsscanResult,
        summary_fn,
        timeout_seconds=_PSSCAN_TIMEOUT_SECONDS,
    )


def vol_pstree(evidence_id: str, case_dir: str = "case-data") -> PstreeSummary:
    """Run windows.pstree.PsTree against a registered memory_image.

    Same cache contract and persistence as `vol_pslist`. Returns a
    `PstreeSummary` with tree-shape signal (root count, max depth,
    depth distribution, largest subtree, orphan count); the recursive
    tree itself lives in the stored extraction. Tier-2's `subtree`
    tool reads it for masquerading and unusual-depth checks.

    Per-record validation note: pydantic validates whole subtrees when
    constructing a top-level ProcessTreeRecord — a malformed descendant
    skips the entire top-level subtree.

    Cost: 25–45 seconds per fresh call against a 19 GB Windows 10 image
    (Rocba: 29.5 s observed). Runner default timeout (300 s) is sufficient.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _PSTREE_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], PstreeSummary] = _compute_pstree_summary

    if extraction_exists(case_dir_path, evidence_id, _PSTREE_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _PSTREE_PLUGIN,
            _PSTREE_TOOL_NAME,
            "processes",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _PSTREE_PLUGIN,
        _PSTREE_TOOL_NAME,
        "processes",
        parse_pstree_json,
        ProcessTreeRecord,
        PstreeResult,
        summary_fn,
    )


def vol_netscan(evidence_id: str, case_dir: str = "case-data") -> NetscanSummary:
    """Run windows.netscan.NetScan against a registered memory_image.

    Same cache contract and persistence as `vol_pslist`. Returns a
    `NetscanSummary` with protocol / TCP-state distribution and a few
    top-level counts; specific endpoints come from
    `query_records(plugin="windows.netscan.NetScan", ...)`.

    Cost: 5–12 minutes per fresh call against a 19 GB Windows 10 image
    (Rocba: 8m57s observed). Runner timeout bumped to 1200 s.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _NETSCAN_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], NetscanSummary] = _compute_netscan_summary

    if extraction_exists(case_dir_path, evidence_id, _NETSCAN_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _NETSCAN_PLUGIN,
            _NETSCAN_TOOL_NAME,
            "connections",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _NETSCAN_PLUGIN,
        _NETSCAN_TOOL_NAME,
        "connections",
        parse_netscan_json,
        NetworkRecord,
        NetscanResult,
        summary_fn,
        timeout_seconds=_NETSCAN_TIMEOUT_SECONDS,
    )


def vol_cmdline(evidence_id: str, case_dir: str = "case-data") -> CmdLineSummary:
    """Run windows.cmdline.CmdLine against a registered memory_image.

    Same cache contract and persistence as `vol_pslist`. Surfaces the
    user-space command line for each process — fills the gap left by
    pslist/psscan, which expose the EPROCESS image name but not the
    `_RTL_USER_PROCESS_PARAMETERS.CommandLine` string. Most rows
    have null `cmdline` because the parameters block paged out
    before acquisition; the `null_cmdline_count` summary field
    quantifies that gap directly.

    Cost: comparable to vol_pstree (the two plugins read overlapping
    user-space pages); no override over the runner's 300 s default
    timeout.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _CMDLINE_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], CmdLineSummary] = _compute_cmdline_summary

    if extraction_exists(case_dir_path, evidence_id, _CMDLINE_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _CMDLINE_PLUGIN,
            _CMDLINE_TOOL_NAME,
            "processes",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _CMDLINE_PLUGIN,
        _CMDLINE_TOOL_NAME,
        "processes",
        parse_cmdline_json,
        ProcessCmdLineRecord,
        CmdLineResult,
        summary_fn,
    )


def vol_malfind(evidence_id: str, case_dir: str = "case-data") -> MalfindSummary:
    """Run windows.malfind.Malfind against a registered memory_image.

    Same cache contract and persistence as `vol_pslist`. Walks each
    process's VAD tree and flags regions whose page protection
    includes both write and execute (typically PAGE_EXECUTE_READWRITE)
    AND whose contents look like code rather than zero-fill — the
    classic shellcode signature.

    Per-record validation note: a single PID can produce multiple
    detections (one row per suspicious VAD region). The result
    envelope's list field is named `detections` rather than
    `processes` for that reason.

    Cost: bounded by the number of injected regions, not the total
    process count. Typically completes in seconds-to-minutes against
    a 19 GB Windows 10 image; no override over the runner's 300 s
    default.
    """
    case_dir_path = Path(case_dir).resolve()
    _, image_path = _resolve_and_validate(case_dir_path, evidence_id, _MALFIND_TOOL_NAME)

    summary_fn: Callable[[ExtractionRef, list[dict]], MalfindSummary] = _compute_malfind_summary

    if extraction_exists(case_dir_path, evidence_id, _MALFIND_PLUGIN):
        return _serve_cached(
            case_dir_path,
            evidence_id,
            _MALFIND_PLUGIN,
            _MALFIND_TOOL_NAME,
            "detections",
            summary_fn,
        )

    return _serve_fresh(
        case_dir_path,
        evidence_id,
        image_path,
        _MALFIND_PLUGIN,
        _MALFIND_TOOL_NAME,
        "detections",
        parse_malfind_json,
        MalfindRecord,
        MalfindResult,
        summary_fn,
    )


__all__ = [
    "vol_cmdline",
    "vol_malfind",
    "vol_netscan",
    "vol_pslist",
    "vol_psscan",
    "vol_pstree",
]
