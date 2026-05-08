"""`record_finding` — typed MCP tool analyst subagents call to commit a
DRAFT finding to the case.

Architectural enforcement of the analyst contract: the agent cannot
drift away from the schema (Literal-validated category / severity /
confidence / analyst), the back-pointers (every finding must reference
≥1 audit-chain line by tool_name + line_number), or the lifecycle
(self-marked DISPUTED is rejected and audited). Per CLAUDE.md
"architectural guardrails beat prompt guardrails".

Five distinct rejection paths — every one writes a chain line so that
rejection cannot become an unrecorded probe channel:

    record_finding:rejected_evidence_not_found
    record_finding:rejected_unknown_analyst
    record_finding:rejected_disputed_self_marked
    record_finding:rejected_invalid_audit_ref
    record_finding:rejected_schema_validation_failed

The rejection messages the agent sees are sanitized — operator-visible
detail (the offending evidence_id, audit line, etc.) lands in the
audit chain only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

import yaml
from pydantic import BaseModel, ValidationError

from server.audit import append_audit_entry, peek_next_line_number
from server.correlations_log import read_correlation_ids
from server.findings_log import (
    append_finding_entry,
    read_finding_state,
)
from server.schemas import (
    AnalystName,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
    EvidenceRefSourceTool,
    FindingCategory,
    FindingChainEntry,
    FindingConfidence,
    FindingSeverity,
    FindingUpdate,
    PromotionRule,
)


_TOOL_NAME = "record_finding"
_CASE_FILENAME = "CASE.yaml"
_AUDIT_RELATIVE_PATH = ("audit", "sift-guard-mcp.jsonl")

# Single source of truth for the analyst allow-list. Keep in sync with
# the `AnalystName` Literal in server/schemas.py — schema constrains
# the *type*; this set is what the runtime check rejects against.
# Same set, two enforcement layers: schema for protocol-level, runtime
# for audit-on-rejection visibility.
ALLOWED_ANALYSTS: frozenset[str] = frozenset(
    {"process_analyst", "network_analyst", "disk_analyst", "validator"}
)

# Source tools an EvidenceRef is allowed to point at. Mirrors the
# EvidenceRefSourceTool Literal — duplicated here so the runtime check
# can run before pydantic validation (we want the audit-on-rejection
# path to fire on a typo'd source_tool, not a schema ValidationError).
ALLOWED_SOURCE_TOOLS: frozenset[str] = frozenset(
    {
        "register_evidence",
        "vol_pslist",
        "vol_psscan",
        "vol_pstree",
        "vol_netscan",
        # Week 8 additions: cmdline + malfind on the memory side,
        # plus four disk-side tier-1 tools whose audit_line is a
        # legitimate citation surface for record_finding.
        "vol_cmdline",
        "vol_malfind",
        "disk_mft_timeline",
        "disk_prefetch",
        "disk_evtx",
        "disk_registry",
        # Tier-2 tools added 2026-05-06: a tier-2 result's
        # `audit_line` field is the analyst's direct entry point for
        # citing a derived analysis as evidence.
        "query_records",
        "group_by",
        "set_difference",
        "subtree",
    }
)


class _RejectionReason(StrEnum):
    """Why a record_finding call was refused."""

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    UNKNOWN_ANALYST = "unknown_analyst"
    DISPUTED_SELF_MARKED = "disputed_self_marked"
    INVALID_AUDIT_REF = "invalid_audit_ref"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"


class _RejectionRecord(BaseModel):
    """Audit payload for a rejected record_finding call.

    Same intent as the memory tools' _RejectionRecord — the
    `evidence_id` is operator-visible via the audit log but never
    echoed in the sanitized exception. Distinct class (not imported
    from server.tools.memory) because the memory module's enum
    differs and we don't want that coupling for the sake of saving
    eight lines.
    """

    reason: _RejectionReason
    evidence_id: str | None  # may be None if the input that failed was the id itself


def _resolve_evidence(
    evidence_id: str, case_dir: Path
) -> EvidenceRecord | None:
    """Look up an evidence_id in CASE.yaml. Same shape as the memory
    tools' helper. Duplicated here rather than imported to keep
    server.tools.findings and server.tools.memory loose-coupled —
    findings has no other dependency on memory."""
    case_yaml = case_dir / _CASE_FILENAME
    if not case_yaml.exists():
        return None
    with case_yaml.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    for entry in doc.get("evidence", []):
        if entry.get("evidence_id") == evidence_id:
            return EvidenceRecord.model_validate(entry)
    return None


def _read_audit_index(audit_path: Path) -> dict[int, str]:
    """Read the audit chain into a {line_number: tool_name} map.

    Used by the `evidence_refs` provenance check. Streamed line-by-
    line to keep memory bounded even on a long-running case (an audit
    chain of 100k lines is ~30 MB; we hold only the tool_name per
    line). Malformed lines are skipped silently — the chain reader's
    job is provenance lookup, not chain integrity verification.
    Integrity is the audit-replay tooling's job (separate code path).
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
                import json

                row = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            line_no = row.get("line_number")
            tool_name = row.get("tool_name")
            if isinstance(line_no, int) and isinstance(tool_name, str):
                index[line_no] = tool_name
    return index


def _log_rejection(
    case_dir: Path, reason: _RejectionReason, evidence_id: str | None
) -> None:
    """Append one rejection line to the audit chain. Tool name is
    `record_finding:rejected_<reason>` for greppability."""
    rejection = _RejectionRecord(reason=reason, evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_TOOL_NAME}:rejected_{reason.value}",
        evidence_id=evidence_id,
        input_args={"evidence_id": evidence_id},
        output=rejection,
    )


def _success_input_args(
    evidence_id: str, analyst: str, refs: list[EvidenceRef]
) -> dict:
    """Build the audit `input_args` dict for a successful record_finding.

    Captures what the agent supplied: the evidence_id, the claimed
    analyst, and the audit-line back-pointers. Title and description
    are not in the audit input — they're in the finding payload, and
    a digest of the FindingChainEntry is the audit line's output_hash.
    The two together let an auditor reconstruct what was claimed
    without bloating the audit chain.
    """
    return {
        "evidence_id": evidence_id,
        "analyst": analyst,
        "evidence_refs": [
            {"source_tool": r.source_tool, "audit_line": r.audit_line}
            for r in refs
        ],
    }


def record_finding(
    *,
    evidence_id: str,
    analyst: str,
    category: FindingCategory,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: str,
    description: str,
    evidence_refs: list[EvidenceRef],
    hypothesis: str | None = None,
    host_id: str | None = None,
    case_dir: str = "case-data",
) -> DraftFinding:
    """Commit a DRAFT finding to the case.

    Resolves `evidence_id` against the registered CASE.yaml. Validates
    `analyst` against the allow-list. Rejects `confidence == "DISPUTED"`
    architecturally — analysts cannot self-mark DISPUTED; that state
    is the validator's. Validates each `EvidenceRef` against the live
    audit chain — the line must exist and its `tool_name` must match
    the ref's `source_tool`. Constructs a DraftFinding with
    server-controlled `finding_id` (UUIDv4), `created_at` (UTC now),
    `state` ("DRAFT"), and `tool_invocations` (derived from
    `evidence_refs`). Appends to `<case_dir>/findings.jsonl` (the
    findings hash chain) and writes a `record_finding` line to the
    audit chain whose `output_hash` is the finding chain entry's
    `this_finding_hash`.

    Two hash chains advance per successful call: the audit chain
    (one line, `tool_name == "record_finding"`) and the findings
    chain (one line, the wrapper carrying the DraftFinding payload).
    """
    case_dir_path = Path(case_dir).resolve()

    # 1. Evidence-id resolution. Audit-on-reject before raising — same
    #    pattern as the memory tools, same probe-channel reasoning.
    record = _resolve_evidence(evidence_id, case_dir_path)
    if record is None:
        _log_rejection(
            case_dir_path,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
        )
        raise ValueError("evidence_id not found in CASE.yaml")

    # 2. Analyst allow-list.
    if analyst not in ALLOWED_ANALYSTS:
        _log_rejection(
            case_dir_path,
            _RejectionReason.UNKNOWN_ANALYST,
            evidence_id,
        )
        raise ValueError("analyst not in allow-list")

    # 3. Self-marked DISPUTED is rejected. The Literal accepts the
    #    value (so the schema is the same one the validator will use
    #    when it promotes a finding) but only the validator may
    #    write it — enforced here, audited.
    if confidence == "DISPUTED":
        _log_rejection(
            case_dir_path,
            _RejectionReason.DISPUTED_SELF_MARKED,
            evidence_id,
        )
        raise ValueError(
            "DISPUTED confidence is reserved for the validator"
        )

    # 4. Audit-line provenance. Each EvidenceRef must point at a real
    #    line in sift-guard-mcp.jsonl, AND the audit entry's tool_name
    #    must match the ref's source_tool. Either failure audits a
    #    single rejection line — we don't enumerate every bad ref to
    #    keep the audit chain compact.
    audit_path = case_dir_path.joinpath(*_AUDIT_RELATIVE_PATH)
    audit_index = _read_audit_index(audit_path)
    for ref in evidence_refs:
        actual = audit_index.get(ref.audit_line)
        if actual is None or actual != ref.source_tool:
            _log_rejection(
                case_dir_path,
                _RejectionReason.INVALID_AUDIT_REF,
                evidence_id,
            )
            raise ValueError("evidence_ref does not match audit chain")

    # 5. Construct the DraftFinding. Server-controlled fields are set
    #    here regardless of what the agent claimed elsewhere. pydantic
    #    enforces the length / count constraints that the function
    #    signature can't carry; a ValidationError lands as a
    #    schema_validation_failed rejection.
    try:
        finding = DraftFinding(
            finding_id=str(uuid4()),
            evidence_id=evidence_id,
            analyst=analyst,  # type: ignore[arg-type]
            state="DRAFT",
            category=category,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_refs=evidence_refs,
            hypothesis=hypothesis,
            host_id=host_id,
            created_at=datetime.now(tz=timezone.utc),
            tool_invocations=sorted(
                {f"{r.source_tool}:{r.audit_line}" for r in evidence_refs}
            ),
        )
    except ValidationError:
        _log_rejection(
            case_dir_path,
            _RejectionReason.SCHEMA_VALIDATION_FAILED,
            evidence_id,
        )
        # Sanitized: the pydantic message can be verbose and may echo
        # field values back at the agent. The audit chain captures the
        # rejection; the agent gets only the generic reason.
        raise ValueError("finding failed schema validation")

    # 6. Append to the findings chain. Returns the wrapper entry for
    #    the audit-chain output_hash.
    chain_entry: FindingChainEntry = append_finding_entry(
        case_dir_path, finding
    )

    # 7. Audit success. The output_hash of this audit line is the
    #    digest of the FindingChainEntry — so audit-replay tooling
    #    can verify "the line in findings.jsonl that this finding
    #    points at hashes to what the audit chain claimed".
    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_TOOL_NAME,
        evidence_id=evidence_id,
        input_args=_success_input_args(evidence_id, analyst, evidence_refs),
        output=chain_entry,
    )

    return finding


_UPDATE_TOOL_NAME = "update_finding"
_VALID_PROMOTION_RULES: frozenset[str] = frozenset(
    {"R1", "R2", "R3", "R4", "R5", "R6"}
)


class _UpdateRejectionReason(StrEnum):
    """Why an update_finding call was refused."""

    UNKNOWN_FINDING = "unknown_finding"
    UNKNOWN_CORRELATION = "unknown_correlation"
    UNKNOWN_RULE = "unknown_rule"
    INVALID_STATE_TRANSITION = "invalid_state_transition"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"
    # R5 ("quiet stabilization") is the only rule whose definition
    # has no driving correlations. Any other rule with an empty
    # driving_correlation_ids list is rejected here so the audit
    # chain captures the failure before reaching pydantic — the
    # tool-layer rejection has a typed, greppable suffix; a bare
    # pydantic ValidationError from the model_validator would land
    # under SCHEMA_VALIDATION_FAILED and be harder to triage.
    EMPTY_CORRELATIONS_FOR_NON_R5 = "empty_correlations_for_non_R5"


class _UpdateRejectionRecord(BaseModel):
    """Audit payload for a rejected update_finding call."""

    reason: _UpdateRejectionReason
    finding_id: str | None
    promotion_rule: str | None


def _log_update_rejection(
    case_dir: Path,
    reason: _UpdateRejectionReason,
    finding_id: str | None,
    promotion_rule: str | None,
) -> None:
    rejection = _UpdateRejectionRecord(
        reason=reason,
        finding_id=finding_id,
        promotion_rule=promotion_rule,
    )
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_UPDATE_TOOL_NAME}:rejected_{reason.value}",
        evidence_id=None,
        input_args={
            "finding_id": finding_id,
            "promotion_rule": promotion_rule,
        },
        output=rejection,
    )


def _is_valid_state_transition(prev_state: str, new_state: str) -> bool:
    """DRAFT can go to DRAFT or CONFIRMED; CONFIRMED stays CONFIRMED.
    Any other shape is rejected — once a finding is CONFIRMED the
    orchestrator does not un-confirm it. DISPUTED is reserved for
    the validator's downstream handling and is not a target state
    for `update_finding`."""
    if prev_state == "DRAFT":
        return new_state in ("DRAFT", "CONFIRMED")
    if prev_state == "CONFIRMED":
        return new_state == "CONFIRMED"
    return False


def update_finding(
    *,
    finding_id: str,
    iteration_number: int,
    new_state: str,
    new_confidence: str,
    promotion_rule: str,
    driving_correlation_ids: list[str],
    orchestrator_version: str,
    case_dir: str = "case-data",
) -> FindingUpdate:
    """Record an orchestrator promotion event against an existing
    finding.

    Reads the most recent record for `finding_id` (DRAFT or prior
    UPDATE, last-write-wins) to derive `previous_state` and
    `previous_confidence` — server-derived rather than agent-supplied
    so a buggy / malicious orchestrator cannot spoof the predecessor.
    Validates the transition is allowed (DRAFT → DRAFT or CONFIRMED;
    CONFIRMED → CONFIRMED). Validates each `driving_correlation_id`
    resolves to a real entry in `correlations.jsonl`. Validates
    `promotion_rule` against the R1..R6 Literal. Constructs a
    `FindingUpdate` with server-controlled `update_id` (UUIDv4),
    `created_at` (UTC now), and `audit_line` (this call's audit-chain
    line). Appends to the SAME `findings.jsonl` chain as DRAFT
    entries, distinguished by `record_kind = "update"`. Audits
    `update_finding:success` on success and a typed
    `update_finding:rejected_*` line on every failure path.

    Six distinct rejection paths:

        update_finding:rejected_unknown_finding
        update_finding:rejected_unknown_correlation
        update_finding:rejected_unknown_rule
        update_finding:rejected_invalid_state_transition
        update_finding:rejected_schema_validation_failed
        update_finding:rejected_empty_correlations_for_non_R5
    """
    case_dir_path = Path(case_dir).resolve()

    # 1. promotion_rule allow-list. Cheap pre-check; the Literal in
    #    the FindingUpdate schema would also catch this but we want
    #    the audited rejection line to fire on a typo'd rule rather
    #    than a generic schema error.
    if promotion_rule not in _VALID_PROMOTION_RULES:
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.UNKNOWN_RULE,
            finding_id,
            promotion_rule,
        )
        raise ValueError("promotion_rule not in allow-list")

    # 1b. Empty driving_correlation_ids is allowed iff the rule is R5
    #     ("quiet stabilization" — fires when no correlations exist on
    #     the finding for two iterations of silence). Every other rule
    #     must cite at least one correlation that drove its decision;
    #     an empty list there would break the audit-trail invariant.
    #     Catching it here (before chain reads) keeps the rejection
    #     suffix typed and the error path cheap.
    if not driving_correlation_ids and promotion_rule != "R5":
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.EMPTY_CORRELATIONS_FOR_NON_R5,
            finding_id,
            promotion_rule,
        )
        raise ValueError(
            "driving_correlation_ids must be non-empty for non-R5 promotions"
        )

    # 2. Look up the existing finding by id. Read the chain to find
    #    the latest state/confidence for this finding_id. Missing
    #    finding_id is the unknown_finding rejection.
    prev = read_finding_state(case_dir_path, finding_id)
    if prev is None:
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.UNKNOWN_FINDING,
            finding_id,
            promotion_rule,
        )
        raise ValueError("finding_id not found in findings.jsonl")
    previous_state, previous_confidence = prev

    # 3. State-transition rule.
    if not _is_valid_state_transition(previous_state, new_state):
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.INVALID_STATE_TRANSITION,
            finding_id,
            promotion_rule,
        )
        raise ValueError("state transition not allowed")

    # 4. driving_correlation_ids existence.
    known_correlations = read_correlation_ids(case_dir_path)
    missing = [
        cid for cid in driving_correlation_ids if cid not in known_correlations
    ]
    if missing:
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.UNKNOWN_CORRELATION,
            finding_id,
            promotion_rule,
        )
        raise ValueError(
            "driving_correlation_id not in correlations.jsonl"
        )

    # 5. Construct the FindingUpdate. pydantic enforces the Literal
    #    constraints we couldn't pre-check (new_state ∈ {DRAFT,
    #    CONFIRMED}, new_confidence ∈ enum, etc.); a ValidationError
    #    becomes the schema_validation_failed rejection path.
    update_id = str(uuid4())
    created_at = datetime.now(tz=timezone.utc)
    audit_line = peek_next_line_number(case_dir_path)
    try:
        update = FindingUpdate(
            update_id=update_id,
            finding_id=finding_id,
            iteration_number=iteration_number,
            previous_state=previous_state,  # type: ignore[arg-type]
            new_state=new_state,  # type: ignore[arg-type]
            previous_confidence=previous_confidence,  # type: ignore[arg-type]
            new_confidence=new_confidence,  # type: ignore[arg-type]
            promotion_rule=promotion_rule,  # type: ignore[arg-type]
            driving_correlation_ids=driving_correlation_ids,
            created_at=created_at,
            audit_line=audit_line,
            orchestrator_version=orchestrator_version,
        )
    except ValidationError:
        _log_update_rejection(
            case_dir_path,
            _UpdateRejectionReason.SCHEMA_VALIDATION_FAILED,
            finding_id,
            promotion_rule,
        )
        raise ValueError("update failed schema validation")

    # 6. Append to the findings chain (same chain as DRAFT entries).
    chain_entry: FindingChainEntry = append_finding_entry(
        case_dir_path, update
    )

    # 7. Audit success. The output_hash is the digest of the
    #    FindingChainEntry just written.
    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_UPDATE_TOOL_NAME,
        evidence_id=None,
        input_args={
            "finding_id": finding_id,
            "iteration_number": iteration_number,
            "new_state": new_state,
            "new_confidence": new_confidence,
            "promotion_rule": promotion_rule,
            "driving_correlation_ids": sorted(set(driving_correlation_ids)),
            "orchestrator_version": orchestrator_version,
        },
        output=chain_entry,
    )

    return update


__all__ = [
    "ALLOWED_ANALYSTS",
    "ALLOWED_SOURCE_TOOLS",
    "record_finding",
    "update_finding",
]
