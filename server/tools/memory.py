"""Typed MCP tools for the Volatility 3 `windows.{pslist,psscan}` plugins.

Both tools compose the Phase B layers:
  - the agent supplies an `evidence_id`
  - the tool resolves it via case-data/CASE.yaml to an EvidenceRecord
  - validates `artifact_class is memory_image`
  - translates the host-side absolute_path to the VM-side path under
    SIFT_VM_EVIDENCE_PREFIX
  - captures the Volatility version (reproducibility metadata)
  - invokes the SSH-based runner with the pinned plugin name
  - parses the PascalCase JSON output to snake_case dicts
  - constructs ProcessRecord rows; per-record validation failures are
    audit-logged as warning entries and the bad row is skipped, so
    one corrupt EPROCESS does not collapse the whole call
  - returns a typed result (PslistResult / PsscanResult) with full
    provenance

Architectural guarantee per CLAUDE.md "Ground truth isolation" rule 3:
the agent cannot construct a path and cannot name a plugin. Plugin
names are pinned in this module; the path comes from the evidence
registry. The runner's plugin_name regex is defense-in-depth.

Why both plugins live in one module: they share the EPROCESS row shape
(verified empirically — see schemas.PsscanResult docstring) and reuse
all of the resolve/translate/audit scaffolding. The two `vol_*`
functions are intentional near-duplicates rather than a parameterized
helper, per CLAUDE.md "three similar lines is better than a premature
abstraction." When a third memory plugin (pstree, netscan, ...) lands,
the duplication will be visible enough to motivate a real extraction.
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
    parse_pslist_json,
    parse_psscan_json,
    run_vol_plugin,
)
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
    ProcessRecord,
    ProcessScanRecord,
    PslistResult,
    PsscanResult,
)


_PSLIST_PLUGIN = "windows.pslist.PsList"
_PSSCAN_PLUGIN = "windows.psscan.PsScan"
_CASE_FILENAME = "CASE.yaml"
_TOOL_NAME = "vol_pslist"
_PSSCAN_TOOL_NAME = "vol_psscan"
_WARNING_TOOL_NAME = "vol_pslist:record_validation_warning"
_PSSCAN_WARNING_TOOL_NAME = "vol_psscan:record_validation_warning"

# Pool-tag scanning walks the full memory layer rather than the active
# EPROCESS list, so psscan is materially slower than pslist. On Rocba
# (19 GB Windows 10 image, SIFT 2026.1 / Vol 3 2.27.0) one observed run
# was 6m36s; runner default is 300s so this tool overrides explicitly.
# 900s gives ~2x the observed runtime as headroom for slower disks or
# the cold-cache case where Volatility re-resolves PDB symbols.
_PSSCAN_TIMEOUT_SECONDS = 900


class _PslistRecordWarning(BaseModel):
    """Audit payload for a Volatility row that failed schema validation.

    Persisted into the chain only via its `output_hash`. The full
    warning text is not written elsewhere in the prototype; recovery
    is bounded to "row at index N was skipped". If full recoverability
    becomes required, write the warning blob to extractions/ and
    reference the path here.
    """

    warning_type: str = "vol_pslist_record_validation_failed"
    record_index: int
    validation_error: str


class _PsscanRecordWarning(BaseModel):
    """Mirror of `_PslistRecordWarning` for the psscan tool. Distinct
    `warning_type` keeps the failure mode greppable in the audit chain
    when both plugins ran against the same image."""

    warning_type: str = "vol_psscan_record_validation_failed"
    record_index: int
    validation_error: str


class _RejectionReason(StrEnum):
    """Why a vol_pslist call was rejected before the runner was invoked."""

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    WRONG_ARTIFACT_CLASS = "wrong_artifact_class"
    PATH_TRANSLATION_FAILED = "path_translation_failed"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected vol_pslist call.

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


def _log_rejection(
    case_dir: Path, reason: _RejectionReason, evidence_id: str
) -> None:
    """Append one rejection line to the audit chain.

    The rejection's tool_name is ``vol_pslist:rejected_<reason>`` —
    greppable from the JSONL and unambiguous about which rejection
    path fired.
    """
    rejection = _RejectionRecord(reason=reason, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_TOOL_NAME}:rejected_{reason.value}",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=rejection,
    )


def _log_psscan_rejection(
    case_dir: Path, reason: _RejectionReason, evidence_id: str
) -> None:
    """Mirror of `_log_rejection` for vol_psscan. Tool name prefix is
    `vol_psscan:rejected_<reason>` so a chain reader can tell which of
    the two plugin tools rejected a probe — both can run against the
    same evidence, and a probe campaign that walks the registry will
    leave traces under both prefixes."""
    rejection = _RejectionRecord(reason=reason, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_PSSCAN_TOOL_NAME}:rejected_{reason.value}",
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
        _log_rejection(
            case_dir_path,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_rejection(
            case_dir_path,
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
        _log_rejection(
            case_dir_path,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _PSLIST_PLUGIN, vm_path
    )
    raw_rows = parse_pslist_json(stdout)

    processes: list[ProcessRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            processes.append(ProcessRecord(**raw))
        except ValidationError as exc:
            warning = _PslistRecordWarning(
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=_WARNING_TOOL_NAME,
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
        tool_name=_TOOL_NAME,
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
        _log_psscan_rejection(
            case_dir_path,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    if record.artifact_class is not ArtifactClass.MEMORY_IMAGE:
        _log_psscan_rejection(
            case_dir_path,
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
        _log_psscan_rejection(
            case_dir_path,
            _RejectionReason.PATH_TRANSLATION_FAILED,
            evidence_id,
        )
        raise

    volatility_version = get_vol_version()
    invoked_at = datetime.now(tz=timezone.utc)
    stdout, command_string, runtime_seconds = run_vol_plugin(
        _PSSCAN_PLUGIN, vm_path, timeout_seconds=_PSSCAN_TIMEOUT_SECONDS
    )
    raw_rows = parse_psscan_json(stdout)

    processes: list[ProcessScanRecord] = []
    for index, raw in enumerate(raw_rows):
        try:
            processes.append(ProcessScanRecord(**raw))
        except ValidationError as exc:
            warning = _PsscanRecordWarning(
                record_index=index,
                validation_error=str(exc),
            )
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=_PSSCAN_WARNING_TOOL_NAME,
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


__all__ = ["translate_to_vm_path", "vol_pslist", "vol_psscan"]
