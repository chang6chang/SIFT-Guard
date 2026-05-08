"""`record_correlation` — typed MCP tool the validator subagent calls
to commit a cross-source / cross-plugin observation about findings.

Five correlation types, dispatched on `correlation_type`:

  - `corroborates` — N findings agree (≥1 target_finding_ids,
    plus a `strength` qualifier).
  - `contradicts` — two findings make incompatible claims (a/b
    finding-id pair, plus `severity` and `resolvable_by_followup`).
  - `strengthens` / `weakens` — one new piece of evidence shifts an
    existing finding's confidence (one target_finding_id).
  - `request_followup` — validator asks the orchestrator to dispatch
    a named analyst with a focus context (target_analyst,
    related_finding_ids, focus_context dict, rationale).

Architectural enforcement of the validator contract: the agent cannot
drift away from the schema (Literal-validated correlation_type per
variant), the back-pointers (every correlation must reference ≥1
audit-chain line via `evidence_refs`), or the finding-id provenance
(every named finding_id must resolve to an entry in
`findings.jsonl`). Per CLAUDE.md "architectural guardrails beat
prompt guardrails".

Five distinct rejection paths — every one writes a chain line so
that rejection cannot become an unrecorded probe channel:

    record_correlation:rejected_unknown_type
    record_correlation:rejected_unknown_case_id
    record_correlation:rejected_invalid_audit_ref
    record_correlation:rejected_invalid_payload
    record_correlation:rejected_unknown_finding
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from pydantic import BaseModel, ValidationError

from server.audit import append_audit_entry, peek_next_line_number
from server.correlations_log import append_correlation_entry
from server.findings_log import read_finding_ids
from server.schemas import (
    ContradictsCorrelation,
    CorroboratesCorrelation,
    CorrelationChainEntry,
    CorrelationType,
    CrossHostCorrelation,
    EvidenceRef,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)


_TOOL_NAME = "record_correlation"
_CASE_FILENAME = "CASE.yaml"
_AUDIT_RELATIVE_PATH = ("audit", "sift-guard-mcp.jsonl")

_VALID_CORRELATION_TYPES: frozenset[str] = frozenset(
    t.value for t in CorrelationType
)


class _RejectionReason(StrEnum):
    """Why a record_correlation call was refused."""

    UNKNOWN_TYPE = "unknown_type"
    UNKNOWN_CASE_ID = "unknown_case_id"
    INVALID_AUDIT_REF = "invalid_audit_ref"
    INVALID_PAYLOAD = "invalid_payload"
    UNKNOWN_FINDING = "unknown_finding"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected record_correlation call."""

    reason: _RejectionReason
    case_id: str | None
    correlation_type: str | None


def _resolve_case_id(case_dir: Path) -> str | None:
    """Return the registered `case_id` from CASE.yaml, or None if the
    file is missing or malformed. The agent's `case_id` argument must
    match this value exactly — no on-the-fly case bootstrapping."""
    case_yaml = case_dir / _CASE_FILENAME
    if not case_yaml.exists():
        return None
    try:
        with case_yaml.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return None
    cid = doc.get("case_id")
    return cid if isinstance(cid, str) else None


def _read_audit_index(audit_path: Path) -> dict[int, str]:
    """Read the audit chain into a `{line_number: tool_name}` map.
    Same helper-shape as `server/tools/findings.py`'s.
    """
    if not audit_path.exists():
        return {}
    index: dict[int, str] = {}
    with audit_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            line_no = row.get("line_number")
            tool_name = row.get("tool_name")
            if isinstance(line_no, int) and isinstance(tool_name, str):
                index[line_no] = tool_name
    return index


def _log_rejection(
    case_dir: Path,
    reason: _RejectionReason,
    case_id: str | None,
    correlation_type: str | None,
) -> None:
    rejection = _RejectionRecord(
        reason=reason, case_id=case_id, correlation_type=correlation_type
    )
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_TOOL_NAME}:rejected_{reason.value}",
        evidence_id=None,
        input_args={
            "case_id": case_id,
            "correlation_type": correlation_type,
        },
        output=rejection,
    )


def _success_input_args(
    case_id: str,
    correlation_type: str,
    iteration_number: int,
    finding_ids: list[str],
    refs: list[EvidenceRef],
) -> dict:
    return {
        "case_id": case_id,
        "correlation_type": correlation_type,
        "iteration_number": iteration_number,
        "finding_ids": sorted(set(finding_ids)),
        "evidence_refs": [
            {"source_tool": r.source_tool, "audit_line": r.audit_line}
            for r in refs
        ],
    }


def _build_payload(
    *,
    correlation_id: str,
    correlation_type: str,
    case_id: str,
    iteration_number: int,
    created_at: datetime,
    audit_line: int,
    evidence_refs: list[EvidenceRef],
    hypothesis: str,
    target_finding_ids: list[str] | None,
    finding_a_id: str | None,
    finding_b_id: str | None,
    target_finding_id: str | None,
    strength: str | None,
    severity: str | None,
    resolvable_by_followup: bool | None,
    target_analyst: str | None,
    related_finding_ids: list[str] | None,
    focus_context: dict[str, Any] | None,
    rationale: str | None,
    host_ids: list[str] | None,
    shared_indicator: dict[str, Any] | None,
):
    """Construct the typed pydantic correlation by `correlation_type`.

    Per-type required-field check happens here: pydantic's
    ValidationError surfaces if a required field is missing or an
    unrelated-to-this-type field carries a non-default value
    (e.g., corroborates with finding_a_id set).
    """
    common = dict(
        correlation_id=correlation_id,
        case_id=case_id,
        iteration_number=iteration_number,
        created_at=created_at,
        audit_line=audit_line,
        evidence_refs=evidence_refs,
        hypothesis=hypothesis,
    )
    if correlation_type == CorrelationType.CORROBORATES.value:
        if (
            finding_a_id is not None
            or finding_b_id is not None
            or target_finding_id is not None
            or severity is not None
            or resolvable_by_followup is not None
            or target_analyst is not None
            or related_finding_ids is not None
            or focus_context not in (None, {})
            or rationale is not None
            or host_ids is not None
            or shared_indicator not in (None, {})
        ):
            raise ValueError(
                "corroborates accepts target_finding_ids + strength only"
            )
        if target_finding_ids is None or strength is None:
            raise ValueError(
                "corroborates requires target_finding_ids and strength"
            )
        return CorroboratesCorrelation(
            **common,
            target_finding_ids=target_finding_ids,
            strength=strength,  # type: ignore[arg-type]
        )
    if correlation_type == CorrelationType.CONTRADICTS.value:
        if (
            target_finding_ids is not None
            or target_finding_id is not None
            or strength is not None
            or target_analyst is not None
            or related_finding_ids is not None
            or focus_context not in (None, {})
            or rationale is not None
            or host_ids is not None
            or shared_indicator not in (None, {})
        ):
            raise ValueError(
                "contradicts accepts finding_a_id + finding_b_id + "
                "severity + resolvable_by_followup only"
            )
        if (
            finding_a_id is None
            or finding_b_id is None
            or severity is None
            or resolvable_by_followup is None
        ):
            raise ValueError(
                "contradicts requires finding_a_id, finding_b_id, "
                "severity, and resolvable_by_followup"
            )
        return ContradictsCorrelation(
            **common,
            finding_a_id=finding_a_id,
            finding_b_id=finding_b_id,
            severity=severity,  # type: ignore[arg-type]
            resolvable_by_followup=resolvable_by_followup,
        )
    if correlation_type == CorrelationType.STRENGTHENS.value:
        if (
            target_finding_ids is not None
            or finding_a_id is not None
            or finding_b_id is not None
            or strength is not None
            or severity is not None
            or resolvable_by_followup is not None
            or target_analyst is not None
            or related_finding_ids is not None
            or focus_context not in (None, {})
            or rationale is not None
            or host_ids is not None
            or shared_indicator not in (None, {})
        ):
            raise ValueError(
                "strengthens accepts target_finding_id only"
            )
        if target_finding_id is None:
            raise ValueError("strengthens requires target_finding_id")
        return StrengthensCorrelation(
            **common, target_finding_id=target_finding_id
        )
    if correlation_type == CorrelationType.WEAKENS.value:
        if (
            target_finding_ids is not None
            or finding_a_id is not None
            or finding_b_id is not None
            or strength is not None
            or severity is not None
            or resolvable_by_followup is not None
            or target_analyst is not None
            or related_finding_ids is not None
            or focus_context not in (None, {})
            or rationale is not None
            or host_ids is not None
            or shared_indicator not in (None, {})
        ):
            raise ValueError(
                "weakens accepts target_finding_id only"
            )
        if target_finding_id is None:
            raise ValueError("weakens requires target_finding_id")
        return WeakensCorrelation(
            **common, target_finding_id=target_finding_id
        )
    if correlation_type == CorrelationType.REQUEST_FOLLOWUP.value:
        if (
            target_finding_ids is not None
            or finding_a_id is not None
            or finding_b_id is not None
            or target_finding_id is not None
            or strength is not None
            or severity is not None
            or resolvable_by_followup is not None
            or host_ids is not None
            or shared_indicator not in (None, {})
        ):
            raise ValueError(
                "request_followup accepts target_analyst + "
                "related_finding_ids + focus_context + rationale only"
            )
        if (
            target_analyst is None
            or related_finding_ids is None
            or rationale is None
        ):
            raise ValueError(
                "request_followup requires target_analyst, "
                "related_finding_ids, and rationale"
            )
        return RequestFollowupCorrelation(
            **common,
            target_analyst=target_analyst,  # type: ignore[arg-type]
            related_finding_ids=related_finding_ids,
            focus_context=focus_context or {},
            rationale=rationale,
        )
    if correlation_type == CorrelationType.CROSS_HOST.value:
        if (
            finding_a_id is not None
            or finding_b_id is not None
            or target_finding_id is not None
            or severity is not None
            or resolvable_by_followup is not None
            or target_analyst is not None
            or related_finding_ids is not None
            or focus_context not in (None, {})
            or rationale is not None
        ):
            raise ValueError(
                "cross_host accepts target_finding_ids + host_ids + "
                "shared_indicator + strength only"
            )
        if (
            target_finding_ids is None
            or host_ids is None
            or strength is None
        ):
            raise ValueError(
                "cross_host requires target_finding_ids, host_ids, "
                "and strength"
            )
        return CrossHostCorrelation(
            **common,
            target_finding_ids=target_finding_ids,
            host_ids=host_ids,
            shared_indicator=shared_indicator or {},
            strength=strength,  # type: ignore[arg-type]
        )
    # Unreachable: caller checks type membership before calling us.
    raise ValueError(f"unknown correlation_type {correlation_type!r}")


def _collect_referenced_finding_ids(payload) -> list[str]:
    """Return every finding-id field on the typed correlation payload,
    flattened into one list. Used to validate them all against
    `findings.jsonl` in one pass."""
    ids: list[str] = []
    for attr in (
        "target_finding_ids",
        "related_finding_ids",
    ):
        v = getattr(payload, attr, None)
        if isinstance(v, list):
            ids.extend(v)
    for attr in (
        "target_finding_id",
        "finding_a_id",
        "finding_b_id",
    ):
        v = getattr(payload, attr, None)
        if isinstance(v, str):
            ids.append(v)
    return ids


def record_correlation(
    *,
    case_id: str,
    iteration_number: int,
    correlation_type: str,
    evidence_refs: list[EvidenceRef],
    hypothesis: str,
    target_finding_ids: list[str] | None = None,
    finding_a_id: str | None = None,
    finding_b_id: str | None = None,
    target_finding_id: str | None = None,
    strength: str | None = None,
    severity: str | None = None,
    resolvable_by_followup: bool | None = None,
    target_analyst: str | None = None,
    related_finding_ids: list[str] | None = None,
    focus_context: dict[str, Any] | None = None,
    rationale: str | None = None,
    host_ids: list[str] | None = None,
    shared_indicator: dict[str, Any] | None = None,
    case_dir: str = "case-data",
):
    """Commit a correlation entry to the case.

    Resolves `case_id` against the registered CASE.yaml. Validates
    `correlation_type` against the 5-member CorrelationType enum.
    Validates each `EvidenceRef` against the live audit chain (line
    must exist; tool_name must match `source_tool`). Builds the
    typed pydantic correlation by dispatcher; per-type required-field
    check happens at construction time. Validates each referenced
    `finding_id` resolves to an entry in `findings.jsonl`. Server
    fills `correlation_id` (UUIDv4), `created_at` (UTC now), and
    `audit_line` (this call's audit-chain line, peeked).

    Errors are sanitized — invalid case_id, unknown correlation_type,
    mismatched audit refs, payload-shape errors, and unresolvable
    finding-ids all raise ValueError with generic messages while the
    audit chain captures the rejection context for operator review.
    """
    case_dir_path = Path(case_dir).resolve()

    # 1. correlation_type membership.
    if correlation_type not in _VALID_CORRELATION_TYPES:
        _log_rejection(
            case_dir_path,
            _RejectionReason.UNKNOWN_TYPE,
            case_id,
            correlation_type,
        )
        raise ValueError("correlation_type not in allow-list")

    # 2. case_id resolution against CASE.yaml.
    registered = _resolve_case_id(case_dir_path)
    if registered is None or registered != case_id:
        _log_rejection(
            case_dir_path,
            _RejectionReason.UNKNOWN_CASE_ID,
            case_id,
            correlation_type,
        )
        raise ValueError("case_id not found in CASE.yaml")

    # 3. Audit-line provenance.
    audit_path = case_dir_path.joinpath(*_AUDIT_RELATIVE_PATH)
    audit_index = _read_audit_index(audit_path)
    for ref in evidence_refs:
        actual = audit_index.get(ref.audit_line)
        if actual is None or actual != ref.source_tool:
            _log_rejection(
                case_dir_path,
                _RejectionReason.INVALID_AUDIT_REF,
                case_id,
                correlation_type,
            )
            raise ValueError("evidence_ref does not match audit chain")

    # 4. Per-type payload construction. The dispatcher rejects
    #    cross-type field overflows + missing required fields with a
    #    plain ValueError; pydantic's ValidationError surfaces enum /
    #    length / pattern errors. Either lands as
    #    `:rejected_invalid_payload`.
    correlation_id = str(uuid4())
    created_at = datetime.now(tz=timezone.utc)
    # Peek the audit line BEFORE the success-audit append. The
    # contract is single-process / no concurrent writes (see
    # `server/audit.py:peek_next_line_number`), so the line we peek
    # is the line our success-append will use.
    audit_line = peek_next_line_number(case_dir_path)
    try:
        payload = _build_payload(
            correlation_id=correlation_id,
            correlation_type=correlation_type,
            case_id=case_id,
            iteration_number=iteration_number,
            created_at=created_at,
            audit_line=audit_line,
            evidence_refs=evidence_refs,
            hypothesis=hypothesis,
            target_finding_ids=target_finding_ids,
            finding_a_id=finding_a_id,
            finding_b_id=finding_b_id,
            target_finding_id=target_finding_id,
            strength=strength,
            severity=severity,
            resolvable_by_followup=resolvable_by_followup,
            target_analyst=target_analyst,
            related_finding_ids=related_finding_ids,
            focus_context=focus_context,
            rationale=rationale,
            host_ids=host_ids,
            shared_indicator=shared_indicator,
        )
    except (ValueError, ValidationError):
        _log_rejection(
            case_dir_path,
            _RejectionReason.INVALID_PAYLOAD,
            case_id,
            correlation_type,
        )
        raise ValueError("correlation payload failed validation")

    # 5. Finding-id existence.
    referenced_ids = _collect_referenced_finding_ids(payload)
    known_ids = read_finding_ids(case_dir_path)
    missing = [fid for fid in referenced_ids if fid not in known_ids]
    if missing:
        _log_rejection(
            case_dir_path,
            _RejectionReason.UNKNOWN_FINDING,
            case_id,
            correlation_type,
        )
        raise ValueError("referenced finding_id not in findings.jsonl")

    # 6. Append to the correlations chain.
    chain_entry: CorrelationChainEntry = append_correlation_entry(
        case_dir_path, payload
    )

    # 7. Audit success. The output_hash is the digest of the
    #    CorrelationChainEntry — so audit-replay can verify "the line
    #    in correlations.jsonl that this correlation points at hashes
    #    to what the audit chain claimed".
    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_TOOL_NAME,
        evidence_id=None,
        input_args=_success_input_args(
            case_id, correlation_type, iteration_number,
            referenced_ids, evidence_refs,
        ),
        output=chain_entry,
    )

    return payload


__all__ = ["record_correlation"]
