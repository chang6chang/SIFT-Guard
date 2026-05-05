"""Typed MCP tools for the Volatility 3
`windows.{pslist,psscan,pstree,netscan}` plugins.

All four tools compose the same Phase B layers:
  - the agent supplies an `evidence_id`
  - the tool resolves it via case-data/CASE.yaml to an EvidenceRecord
  - validates `artifact_class is memory_image`
  - translates the host-side absolute_path to the VM-side path under
    SIFT_VM_EVIDENCE_PREFIX
  - captures the Volatility version (reproducibility metadata)
  - invokes the SSH-based runner with the pinned plugin name
  - parses the PascalCase JSON output
  - constructs typed records; per-row validation failures are audit-
    logged as warnings and the bad row (or bad subtree, for pstree) is
    skipped, so one corrupt record does not collapse the whole call
  - returns a typed result with full provenance

Architectural guarantee per CLAUDE.md "Ground truth isolation" rule 3:
the agent cannot construct a path and cannot name a plugin. Plugin
names are pinned in this module; the path comes from the evidence
registry. The runner's plugin_name regex is defense-in-depth.

Helpers shared across the three tools (extracted in week 4 — the
"rule of three" trigger):

  - ``_log_tool_rejection`` (was ``_log_rejection`` /
    ``_log_psscan_rejection``) parameterized on tool_name
  - ``_ToolRecordWarning`` (was ``_PslistRecordWarning`` /
    ``_PsscanRecordWarning``) carries `warning_type` as a constructor
    arg rather than a class default

Both extractions preserve audit-line bytes for callers that pass the
right strings — pydantic's `model_dump_json` serializes the same field
set in the same order regardless of whether `warning_type` was a class
default or an instance value.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError

from server.audit import append_audit_entry
from server.runners.sift_vm import (
    SIFT_VM_EVIDENCE_PREFIX,
    get_vol_version,
    parse_netscan_json,
    parse_pstree_json,
    parse_volatility_json,
    run_vol_plugin,
)
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    NetscanResult,
    NetworkRecord,
    ProcessRecord,
    ProcessScanRecord,
    ProcessTreeRecord,
    PslistResult,
    PsscanResult,
    PstreeResult,
)


_PSLIST_PLUGIN = "windows.pslist.PsList"
_PSSCAN_PLUGIN = "windows.psscan.PsScan"
_PSTREE_PLUGIN = "windows.pstree.PsTree"
_NETSCAN_PLUGIN = "windows.netscan.NetScan"
_CASE_FILENAME = "CASE.yaml"
_PSLIST_TOOL_NAME = "vol_pslist"
_PSSCAN_TOOL_NAME = "vol_psscan"
_PSTREE_TOOL_NAME = "vol_pstree"
_NETSCAN_TOOL_NAME = "vol_netscan"

# Pool-tag scanning walks the full memory layer rather than the active
# EPROCESS list, so psscan is materially slower than pslist. On Rocba
# (19 GB Windows 10 image, SIFT 2026.1 / Vol 3 2.27.0) one observed run
# was 6m36s; runner default is 300s so this tool overrides explicitly.
# 900s gives ~2x the observed runtime as headroom for slower disks or
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
    """Why a memory-tool call was rejected before the runner was invoked."""

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    WRONG_ARTIFACT_CLASS = "wrong_artifact_class"
    PATH_TRANSLATION_FAILED = "path_translation_failed"


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


def translate_to_vm_path(
    host_path: str, host_prefix: str, vm_prefix: str
) -> str:
    """Translate a host-side absolute path to its VM-side equivalent.

    Replaces ``host_prefix`` with ``vm_prefix`` and enforces a
    boundary: ``/foo/bar-other/file`` does NOT satisfy the prefix
    ``/foo/bar``. The next character after the matched prefix must be
    a separator (or the path exactly equals the prefix).

    Sanitized: refuses without echoing the offending path back, per
    the 2026-05-05 MCP error-message sanitization rule.
    """
    host_prefix = host_prefix.rstrip("/")
    vm_prefix = vm_prefix.rstrip("/")
    if host_path == host_prefix:
        return vm_prefix
    if not host_path.startswith(host_prefix + "/"):
        raise ValueError("evidence path is not under the expected host prefix")
    return vm_prefix + host_path[len(host_prefix):]


def _resolve_evidence(
    evidence_id: str, case_dir: Path
) -> EvidenceRecord | None:
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


def vol_pslist(evidence_id: str, case_dir: str = "case-data") -> PslistResult:
    """Run windows.pslist.PsList against a registered memory_image.

    Resolves ``evidence_id`` via CASE.yaml. Validates ``artifact_class``
    is ``memory_image``. Translates the host path to the VM path under
    ``SIFT_VM_EVIDENCE_PREFIX``. Captures the Volatility version,
    invokes the runner, parses the output, and returns a typed
    PslistResult. Per-record validation failures are audit-logged as
    warnings and the bad row is skipped — partial results are
    valuable and the failure mode goes in the audit chain rather than
    bubbling as an exception.
    """
    case_dir_path = Path(case_dir).resolve()

    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        # Audit BEFORE raising: rejection must not be an unrecorded
        # probe channel. Operator sees the evidence_id via the audit
        # log; agent sees only the sanitized exception.
        _log_tool_rejection(
            case_dir_path,
            _PSLIST_TOOL_NAME,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            _PSLIST_TOOL_NAME,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        # Sanitized: the actual artifact_class is internal state.
        raise ValueError("evidence is not a memory image")

    host_prefix = str(case_dir_path / "evidence")
    try:
        vm_path = translate_to_vm_path(
            record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX
        )
    except ValueError:
        # Triggered only if CASE.yaml's absolute_path is outside the
        # case_dir/evidence/ tree — should be impossible under normal
        # register_evidence flow, but we still record the probe.
        _log_tool_rejection(
            case_dir_path,
            _PSLIST_TOOL_NAME,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _PSLIST_PLUGIN, vm_path
    )
    raw_rows = parse_volatility_json(stdout)

    processes: list[ProcessRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            processes.append(ProcessRecord(**raw))
        except ValidationError as exc:
            warning = _ToolRecordWarning(
                warning_type="vol_pslist_record_validation_failed",
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=f"{_PSLIST_TOOL_NAME}:record_validation_warning",
                evidence_id=evidence_id,
                input_args={"record_index": index},
                output=warning,
            )

    result = PslistResult(
        evidence_id=evidence_id,
        plugin_name=_PSLIST_PLUGIN,
        volatility_version=volatility_version,
        processes=processes,
        command_executed=command_string,
        runtime_seconds=runtime_seconds,
        invoked_at=invoked_at,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_PSLIST_TOOL_NAME,
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=result,
    )

    return result


def vol_psscan(evidence_id: str, case_dir: str = "case-data") -> PsscanResult:
    """Run windows.psscan.PsScan against a registered memory_image.

    Pool-tag scans memory directly for `_EPROCESS` allocations rather
    than walking the active EPROCESS linked list. Surfaces processes
    `vol_pslist` cannot see by construction: terminated processes whose
    EPROCESS still lingers in the pool, processes hidden via DKOM (the
    EPROCESS unlinked from the active list while the pool tag stays
    intact), and processes the kernel has marked exited but not yet
    reaped. The set difference between psscan and pslist is the
    cross-plugin contradiction the week-6 validator will surface.

    Resolves ``evidence_id`` via CASE.yaml. Validates ``artifact_class``
    is ``memory_image``. Translates the host path to the VM path under
    ``SIFT_VM_EVIDENCE_PREFIX``. Captures the Volatility version,
    invokes the runner, parses the output, and returns a typed
    PsscanResult. Per-record validation failures are audit-logged as
    `vol_psscan:record_validation_warning` entries and the bad row is
    skipped — partial results are valuable.

    Cost: typically 5-10 minutes per call against a 19 GB Windows 10
    image (Rocba: 6m36s observed on the SIFT 2026.1 / Vol 3 2.27.0
    build, 2026-05-05). About 30-50× slower than ``vol_pslist`` because
    pool-tag scanning walks the full memory layer rather than the
    EPROCESS active list. Runner timeout is bumped to 900s; the LLM
    should not call this redundantly back-to-back.

    Field set: empirically identical to `vol_pslist` on Vol 3 2.27.0 —
    same 12-key EPROCESS row. Most psscan rows have non-null
    ``ExitTime`` (~90% on Rocba: 2001 of 2212), reflecting the
    plugin's ability to surface terminated processes pslist's
    linked-list walk has dropped.
    """
    case_dir_path = Path(case_dir).resolve()

    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        _log_tool_rejection(
            case_dir_path,
            _PSSCAN_TOOL_NAME,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            _PSSCAN_TOOL_NAME,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        raise ValueError("evidence is not a memory image")

    host_prefix = str(case_dir_path / "evidence")
    try:
        vm_path = translate_to_vm_path(
            record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX
        )
    except ValueError:
        _log_tool_rejection(
            case_dir_path,
            _PSSCAN_TOOL_NAME,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _PSSCAN_PLUGIN, vm_path, timeout_seconds=_PSSCAN_TIMEOUT_SECONDS
    )
    raw_rows = parse_volatility_json(stdout)

    processes: list[ProcessScanRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            processes.append(ProcessScanRecord(**raw))
        except ValidationError as exc:
            warning = _ToolRecordWarning(
                warning_type="vol_psscan_record_validation_failed",
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=f"{_PSSCAN_TOOL_NAME}:record_validation_warning",
                evidence_id=evidence_id,
                input_args={"record_index": index},
                output=warning,
            )

    result = PsscanResult(
        evidence_id=evidence_id,
        plugin_name=_PSSCAN_PLUGIN,
        volatility_version=volatility_version,
        processes=processes,
        command_executed=command_string,
        runtime_seconds=runtime_seconds,
        invoked_at=invoked_at,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_PSSCAN_TOOL_NAME,
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=result,
    )

    return result


def vol_pstree(evidence_id: str, case_dir: str = "case-data") -> PstreeResult:
    """Run windows.pstree.PsTree against a registered memory_image.

    Reconstructs the parent-child process hierarchy from each EPROCESS's
    ``InheritedFromUniqueProcessId``. Built on the same active-list walk
    as pslist (so total record count matches pslist exactly — verified
    on Rocba: 2186 vs 2186), but adds three resolved-string fields per
    node (audit, cmd, path) and the recursive `children` structure the
    week-6 validator uses to anchor masquerading detection.

    Resolves ``evidence_id`` via CASE.yaml. Validates ``artifact_class``
    is ``memory_image``. Translates the host path to the VM path under
    ``SIFT_VM_EVIDENCE_PREFIX``. Captures the Volatility version,
    invokes the runner, parses the recursive output, and returns a typed
    PstreeResult.

    Per-record validation note: pydantic validates the whole subtree
    when constructing a top-level ProcessTreeRecord. If any descendant
    has a malformed field (negative PID, non-UTC timestamp, etc.), the
    *entire top-level subtree* is skipped and a single
    `vol_pstree:record_validation_warning` line is logged with the
    top-level index. This is coarser than pslist/psscan's per-row skip,
    a deliberate trade-off — preserving the tree shape is the validator's
    primary use case, and per-descendant recovery would force walking
    the raw dict tree manually before construction.

    Cost: typically 25-45 seconds per call against a 19 GB Windows 10
    image (Rocba: 29.5s observed). Dramatically faster than psscan
    because pstree walks the same active EPROCESS list as pslist;
    runner default timeout (300s) is sufficient.
    """
    case_dir_path = Path(case_dir).resolve()

    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        _log_tool_rejection(
            case_dir_path,
            _PSTREE_TOOL_NAME,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            _PSTREE_TOOL_NAME,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        raise ValueError("evidence is not a memory image")

    host_prefix = str(case_dir_path / "evidence")
    try:
        vm_path = translate_to_vm_path(
            record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX
        )
    except ValueError:
        _log_tool_rejection(
            case_dir_path,
            _PSTREE_TOOL_NAME,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _PSTREE_PLUGIN, vm_path
    )
    raw_rows = parse_pstree_json(stdout)

    processes: list[ProcessTreeRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            processes.append(ProcessTreeRecord(**raw))
        except ValidationError as exc:
            warning = _ToolRecordWarning(
                warning_type="vol_pstree_record_validation_failed",
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=f"{_PSTREE_TOOL_NAME}:record_validation_warning",
                evidence_id=evidence_id,
                input_args={"record_index": index},
                output=warning,
            )

    result = PstreeResult(
        evidence_id=evidence_id,
        plugin_name=_PSTREE_PLUGIN,
        volatility_version=volatility_version,
        processes=processes,
        command_executed=command_string,
        runtime_seconds=runtime_seconds,
        invoked_at=invoked_at,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_PSTREE_TOOL_NAME,
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=result,
    )

    return result


def vol_netscan(evidence_id: str, case_dir: str = "case-data") -> NetscanResult:
    """Run windows.netscan.NetScan against a registered memory_image.

    Pool-tag scans the network object table and recovers TCP / UDP
    endpoint structures across IPv4 and IPv6. Returns a flat list of
    NetworkRecord rows — one per endpoint or connection. The same
    field set applies across all four protocol families; UDP records
    use ``state == ""`` and ``foreign_addr == "*"`` rather than null,
    matching the netstat convention.

    Resolves ``evidence_id`` via CASE.yaml. Validates ``artifact_class``
    is ``memory_image``. Translates the host path to the VM path under
    ``SIFT_VM_EVIDENCE_PREFIX``. Captures the Volatility version,
    invokes the runner, parses the output, and returns a typed
    NetscanResult. Per-record validation failures are audit-logged as
    `vol_netscan:record_validation_warning` entries and the bad row
    is skipped.

    Cross-source value: combined with vol_pslist / vol_psscan /
    vol_pstree, the validator can flag PIDs bound to ports in netscan
    that are missing from pslist's active-list walk — DKOM hiding
    leaves a pool entry the network plugin still sees.

    Cost: typically 5-12 minutes per call against a 19 GB Windows 10
    image (Rocba: 8m57s observed). Slower than psscan because netscan
    walks more pool families (TCP endpoint, TCP listener, UDP endpoint).
    Runner timeout is bumped to 1200s; the LLM should not call this
    redundantly.

    Null-tolerant fields: ``pid`` and ``owner`` are both optional in
    NetworkRecord (kernel-only endpoints, or sockets whose owning
    process exited but whose pool entry survives — same recovery
    semantic as psscan's exited rows).
    """
    case_dir_path = Path(case_dir).resolve()

    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        _log_tool_rejection(
            case_dir_path,
            _NETSCAN_TOOL_NAME,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_tool_rejection(
            case_dir_path,
            _NETSCAN_TOOL_NAME,
            _RejectionReason.WRONG_ARTIFACT_CLASS,
            evidence_id,
        )
        raise ValueError("evidence is not a memory image")

    host_prefix = str(case_dir_path / "evidence")
    try:
        vm_path = translate_to_vm_path(
            record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX
        )
    except ValueError:
        _log_tool_rejection(
            case_dir_path,
            _NETSCAN_TOOL_NAME,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _NETSCAN_PLUGIN, vm_path, timeout_seconds=_NETSCAN_TIMEOUT_SECONDS
    )
    raw_rows = parse_netscan_json(stdout)

    connections: list[NetworkRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            connections.append(NetworkRecord(**raw))
        except ValidationError as exc:
            warning = _ToolRecordWarning(
                warning_type="vol_netscan_record_validation_failed",
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=f"{_NETSCAN_TOOL_NAME}:record_validation_warning",
                evidence_id=evidence_id,
                input_args={"record_index": index},
                output=warning,
            )

    result = NetscanResult(
        evidence_id=evidence_id,
        plugin_name=_NETSCAN_PLUGIN,
        volatility_version=volatility_version,
        connections=connections,
        command_executed=command_string,
        runtime_seconds=runtime_seconds,
        invoked_at=invoked_at,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_NETSCAN_TOOL_NAME,
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=result,
    )

    return result


__all__ = [
    "translate_to_vm_path",
    "vol_netscan",
    "vol_pslist",
    "vol_psscan",
    "vol_pstree",
]
