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
from server.rejections_log import append_rejection_record
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

_VALID_CORRELATION_TYPES: frozenset[str] = frozenset(t.value for t in CorrelationType)


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


class _PrefixResolutionRecord(BaseModel):
    """Audit payload for the soft-resolution of truncated finding-id
    prefixes (analyst drift telemetry).

    Emitted by ``_resolve_finding_id_prefixes`` whenever one or more
    finding-id-typed fields on a record_correlation call arrive as a
    UUID *prefix* (8..35 chars) instead of a full UUID v4 (36 chars
    with dashes) and resolve uniquely against findings.jsonl. The
    call still proceeds with the resolved full ids; this is telemetry
    for analyst drift, not a rejection.
    """

    case_id: str
    correlation_type: str
    resolutions: list[dict[str, str]]


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
    raw_input: dict | None = None,
) -> None:
    """Append one rejection line to the audit chain, plus a sanitized
    copy of ``raw_input`` to the side-channel rejections log so the
    operator console can render *what* was rejected — not just *that
    something* was rejected. Mirrors the contract in
    ``server.tools.findings._log_rejection`` (commit a036662). The
    hash-chained audit log still stores only the input hash; the
    side-channel writer takes care of redaction
    (``<evidence>…</evidence>`` stripping, length cap) before disk.
    """
    rejection = _RejectionRecord(reason=reason, case_id=case_id, correlation_type=correlation_type)
    entry = append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{_TOOL_NAME}:rejected_{reason.value}",
        evidence_id=None,
        input_args={
            "case_id": case_id,
            "correlation_type": correlation_type,
        },
        output=rejection,
    )
    if raw_input is not None:
        append_rejection_record(case_dir, entry, raw_input)


# Validator drift handler: truncated UUID prefixes on finding-id fields.
#
# The 2026-05-19 multi-host run (and prior runs going back to 2026-05-13)
# logged 10+ ``record_correlation:rejected_invalid_payload`` events where
# the validator emitted an 8-character UUID prefix (e.g. ``"d441ae99"``)
# in place of a full UUID v4 string. Same drift shape across every
# correlation type — the validator was likely token-saving by quoting
# the leading hex group of the UUID, treating it as a "short id" like
# git's commit prefixes. The schema requires full UUID v4 (validated
# by pydantic at construction time), so every truncated prefix burns
# a 5-10K-token validator retry while contributing nothing — the
# finding *exists*, the analyst just named it by prefix.
#
# Soft-resolve any string that's 8..35 chars (i.e. shorter than a full
# 36-char UUID, longer than a meaningless 1-7 char fragment) against
# findings.jsonl. Unique prefix → swap in the full id, emit one
# ``:finding_id_prefix_resolved`` audit line per call so an operator
# can see the drift telemetry. Ambiguous prefix (multiple findings
# share the leading substring) or no match → leave the string alone;
# pydantic's UUID v4 validator will reject it cleanly via
# ``:rejected_invalid_payload`` and the operator still sees the
# original drift in the side-channel rejections log. The 8-char floor
# is conservative: 32 bits of hex collision is large enough that an
# 80-finding case will almost never see overlap, while a 4-char prefix
# would routinely collide.

_PREFIX_MIN_LENGTH = 8
_FULL_UUID_LENGTH = 36


def _build_finding_id_prefix_index(case_dir_path: Path) -> dict[str, str]:
    """Build a ``{prefix: full_finding_id}`` index from findings.jsonl.

    Only prefixes that resolve to exactly one finding are included so
    an ambiguous prefix flows through to pydantic's UUID v4 validator
    and lands cleanly in ``:rejected_invalid_payload`` (with the
    original prefix preserved in the side-channel rejections log) —
    rather than getting silently mapped onto whichever finding the
    iteration order surfaced first.

    Indexes every leading substring of length 8..35 on every full
    finding-id, so the validator's natural 8-char hex prefix shape
    resolves alongside the dash-included prefixes (``d441ae99``,
    ``d441ae99-3f1a``, etc).
    """
    finding_ids = read_finding_ids(case_dir_path)
    counts: dict[str, list[str]] = {}
    for fid in finding_ids:
        for length in range(_PREFIX_MIN_LENGTH, _FULL_UUID_LENGTH):
            counts.setdefault(fid[:length], []).append(fid)
    return {p: matches[0] for p, matches in counts.items() if len(matches) == 1}


def _resolve_finding_id_prefixes(
    case_dir_path: Path,
    target_finding_ids: list[str] | None,
    finding_a_id: str | None,
    finding_b_id: str | None,
    target_finding_id: str | None,
    related_finding_ids: list[str] | None,
) -> tuple[
    list[str] | None,
    str | None,
    str | None,
    str | None,
    list[str] | None,
    list[tuple[str, str]],
]:
    """Resolve any short-prefix finding-id fields against findings.jsonl.

    Returns a tuple matching the input shape plus a `resolutions` list
    of ``(prefix, full_id)`` pairs for audit telemetry. The findings.jsonl
    scan is deferred until at least one field has a short value, so
    correlations with full UUIDs don't pay the I/O cost.
    """

    def _is_short(v: str | None) -> bool:
        return isinstance(v, str) and _PREFIX_MIN_LENGTH <= len(v.strip()) < _FULL_UUID_LENGTH

    needs_resolve = (
        _is_short(finding_a_id)
        or _is_short(finding_b_id)
        or _is_short(target_finding_id)
        or (isinstance(target_finding_ids, list) and any(_is_short(v) for v in target_finding_ids))
        or (isinstance(related_finding_ids, list) and any(_is_short(v) for v in related_finding_ids))
    )
    if not needs_resolve:
        return (
            target_finding_ids,
            finding_a_id,
            finding_b_id,
            target_finding_id,
            related_finding_ids,
            [],
        )

    index = _build_finding_id_prefix_index(case_dir_path)
    resolutions: list[tuple[str, str]] = []

    def _resolve_scalar(v: str | None) -> str | None:
        if not _is_short(v):
            return v
        candidate = v.strip()
        full = index.get(candidate) or index.get(candidate.lower())
        if full is None:
            return v
        resolutions.append((candidate, full))
        return full

    def _resolve_list(items: list[str] | None) -> list[str] | None:
        if not isinstance(items, list):
            return items
        return [_resolve_scalar(item) for item in items]

    return (
        _resolve_list(target_finding_ids),
        _resolve_scalar(finding_a_id),
        _resolve_scalar(finding_b_id),
        _resolve_scalar(target_finding_id),
        _resolve_list(related_finding_ids),
        resolutions,
    )


def _log_prefix_resolutions(
    case_dir_path: Path,
    case_id: str,
    correlation_type: str,
    resolutions: list[tuple[str, str]],
) -> None:
    """Append one informational audit line per call that resolved at
    least one prefix. No-op when ``resolutions`` is empty."""
    if not resolutions:
        return
    record = _PrefixResolutionRecord(
        case_id=case_id,
        correlation_type=correlation_type,
        resolutions=[{"prefix": p, "full_id": f} for p, f in resolutions],
    )
    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=f"{_TOOL_NAME}:finding_id_prefix_resolved",
        evidence_id=None,
        input_args={
            "case_id": case_id,
            "correlation_type": correlation_type,
            "resolution_count": len(resolutions),
        },
        output=record,
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
        "evidence_refs": [{"source_tool": r.source_tool, "audit_line": r.audit_line} for r in refs],
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

    Per-type required-field check happens here: a `ValueError` lands
    if a required field is missing. Irrelevant-to-this-type fields
    are *silently ignored* rather than rejected — the 2026-05-13
    SRL-v2 run had 23 ``record_correlation:rejected_invalid_payload``
    events, every one of them a legitimate correlation where the
    validator additionally passed a per-type-irrelevant field
    (e.g. ``strength`` on a ``strengthens`` call, or
    ``resolvable_by_followup`` on a ``request_followup`` call).
    Each rejection burned 5-10K tokens of validator reasoning on the
    retry while contributing nothing to the audit trail's integrity:
    the *type* and *required* fields were all correct, the
    overflow fields just wouldn't have been persisted.

    The schema's integrity is preserved by construction: only the
    type-relevant fields ever land on the typed pydantic record. We
    don't need a guardrail against the validator typing extra
    kwargs — the schema's serialization is the guardrail.
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
        # Back-compat: the validator agent frequently emits
        # ``finding_a_id`` + ``finding_b_id`` (the contradicts-style
        # pair shape) on a corroborates call instead of the
        # ``target_finding_ids`` list. The 2026-05-13 SRL-v2 run lost
        # 37/65 correlations to this single mismatch — every rejected
        # entry had non-null ``finding_a_id`` + ``finding_b_id`` and a
        # null ``target_finding_ids``. Promote the pair into the list
        # when the canonical field is missing so the legitimate
        # correlation lands instead of triggering a 5-10K token retry.
        if target_finding_ids is None and finding_a_id and finding_b_id:
            target_finding_ids = [finding_a_id, finding_b_id]
        if target_finding_ids is None or strength is None:
            raise ValueError("corroborates requires target_finding_ids and strength")
        return CorroboratesCorrelation(
            **common,
            target_finding_ids=target_finding_ids,
            strength=strength,  # type: ignore[arg-type]
        )
    if correlation_type == CorrelationType.CONTRADICTS.value:
        # Back-compat: the 2026-05-19 multi-host run logged 4 contradicts
        # rejections where the validator passed the corroborates-style
        # ``strength`` (or null) instead of the canonical
        # ``severity`` + ``resolvable_by_followup`` pair. Map strength
        # to severity (strong→fundamental, moderate→material,
        # weak→minor) when severity is missing; default
        # ``resolvable_by_followup`` to True (more permissive — the
        # orchestrator can dispatch a followup; a contradiction the
        # validator declared unresolvable would be the unusual case).
        _STRENGTH_TO_SEVERITY = {
            "strong": "fundamental",
            "moderate": "material",
            "weak": "minor",
        }
        if severity is None and strength is not None:
            severity = _STRENGTH_TO_SEVERITY.get(strength, "material")
        if severity is None:
            severity = "material"
        if resolvable_by_followup is None:
            resolvable_by_followup = True
        # Promote target_finding_ids pair to a/b when the validator
        # emitted the corroborates shape instead of the contradicts pair.
        if (
            finding_a_id is None
            and finding_b_id is None
            and isinstance(target_finding_ids, list)
            and len(target_finding_ids) >= 2
        ):
            finding_a_id, finding_b_id = target_finding_ids[0], target_finding_ids[1]
        if finding_a_id is None or finding_b_id is None:
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
        if target_finding_id is None:
            raise ValueError("strengthens requires target_finding_id")
        return StrengthensCorrelation(**common, target_finding_id=target_finding_id)
    if correlation_type == CorrelationType.WEAKENS.value:
        if target_finding_id is None:
            raise ValueError("weakens requires target_finding_id")
        return WeakensCorrelation(**common, target_finding_id=target_finding_id)
    if correlation_type == CorrelationType.REQUEST_FOLLOWUP.value:
        # Back-compat: the validator agent routinely emits the finding-id
        # under one of the *other* finding-id field names instead of the
        # canonical ``related_finding_ids``. The 2026-05-14 xp-tdungan run
        # had 6/16 request_followup correlations rejected solely because of
        # this field-name drift — the validator alternated between
        # ``target_finding_id`` (singular), ``target_finding_ids`` (the
        # corroborates-style list), and ``finding_a_id`` (the
        # contradicts-style pair). Promote whichever shape arrived into
        # ``related_finding_ids`` so the legitimate followup lands.
        if related_finding_ids is None:
            if isinstance(target_finding_ids, list) and target_finding_ids:
                related_finding_ids = list(target_finding_ids)
            elif target_finding_id:
                related_finding_ids = [target_finding_id]
            elif finding_a_id and finding_b_id:
                related_finding_ids = [finding_a_id, finding_b_id]
            elif finding_a_id:
                related_finding_ids = [finding_a_id]
        # Back-compat: when ``rationale`` is omitted, fall back to
        # ``hypothesis`` — the two carry the same justification text from
        # the validator's perspective, and ``hypothesis`` is already
        # validated min_length=1 at the correlation call boundary. The
        # schema requires ``rationale`` min_length=20, so guard against
        # the hypothesis being too short before substituting.
        if rationale is None and hypothesis and len(hypothesis) >= 20:
            rationale = hypothesis
        if target_analyst is None or not related_finding_ids or rationale is None:
            raise ValueError(
                "request_followup requires target_analyst, related_finding_ids, and rationale"
            )
        return RequestFollowupCorrelation(
            **common,
            target_analyst=target_analyst,  # type: ignore[arg-type]
            related_finding_ids=related_finding_ids,
            focus_context=focus_context or {},
            rationale=rationale,
        )
    if correlation_type == CorrelationType.CROSS_HOST.value:
        # Same back-compat as corroborates: accept the pair shape when
        # the canonical list is missing.
        if target_finding_ids is None and finding_a_id and finding_b_id:
            target_finding_ids = [finding_a_id, finding_b_id]
        # 2026-05-19 multi-host re-run: 2 cross_host correlations
        # rejected because the validator emitted the request_followup-
        # style ``related_finding_ids`` instead of the canonical
        # ``target_finding_ids``. Promote the alternate shape when
        # the canonical field is missing.
        if (
            target_finding_ids is None
            and isinstance(related_finding_ids, list)
            and len(related_finding_ids) >= 2
        ):
            target_finding_ids = list(related_finding_ids)
        # 2026-05-19 multi-host: 12 cross_host correlations rejected
        # solely because ``strength`` was null — the validator omitted
        # it on calls that otherwise carried target_finding_ids/host_ids
        # /shared_indicator/rationale. ``strength`` exists to gate
        # promotion (R3 / R6 use it); a missing value isn't a content
        # bug, it's a schema-field-omission bug. Default to "moderate":
        # the orchestrator still promotes via R3, and the validator can
        # explicitly downgrade with ``strength="weak"`` when needed.
        if strength is None:
            strength = "moderate"
        if target_finding_ids is None or host_ids is None:
            raise ValueError("cross_host requires target_finding_ids and host_ids")
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

    # Snapshot of every analyst-supplied argument, captured once so
    # all five rejection paths can hand the same payload to the
    # side-channel rejections log. The hash-chained audit log keeps
    # storing only `{case_id, correlation_type}` (per its sanitization
    # contract); this snapshot lives in `audit/rejections.jsonl` and
    # is what the operator console renders when a rejection fires.
    # See `server.rejections_log` for the redaction rules.
    raw_input: dict[str, object] = {
        "case_id": case_id,
        "iteration_number": iteration_number,
        "correlation_type": correlation_type,
        "evidence_refs": [
            {"source_tool": r.source_tool, "audit_line": r.audit_line}
            for r in evidence_refs
        ],
        "hypothesis": hypothesis,
        "target_finding_ids": target_finding_ids,
        "finding_a_id": finding_a_id,
        "finding_b_id": finding_b_id,
        "target_finding_id": target_finding_id,
        "strength": strength,
        "severity": severity,
        "resolvable_by_followup": resolvable_by_followup,
        "target_analyst": target_analyst,
        "related_finding_ids": related_finding_ids,
        "focus_context": focus_context,
        "rationale": rationale,
        "host_ids": host_ids,
        "shared_indicator": shared_indicator,
    }

    # 1. correlation_type membership.
    if correlation_type not in _VALID_CORRELATION_TYPES:
        _log_rejection(
            case_dir_path,
            _RejectionReason.UNKNOWN_TYPE,
            case_id,
            correlation_type,
            raw_input,
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
            raw_input,
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
                raw_input,
            )
            raise ValueError("evidence_ref does not match audit chain")

    # 3b. Resolve any truncated UUID prefixes against findings.jsonl.
    #     Validator drift handler — see ``_resolve_finding_id_prefixes``
    #     docstring above. Runs after the audit-ref check so a call with
    #     mismatched audit refs doesn't pay the findings.jsonl scan cost.
    #     ``raw_input`` was snapshotted at the top of the function, so
    #     a rejection further down still echoes the original analyst
    #     prefix to the side-channel rejections log.
    (
        target_finding_ids,
        finding_a_id,
        finding_b_id,
        target_finding_id,
        related_finding_ids,
        _prefix_resolutions,
    ) = _resolve_finding_id_prefixes(
        case_dir_path,
        target_finding_ids,
        finding_a_id,
        finding_b_id,
        target_finding_id,
        related_finding_ids,
    )
    _log_prefix_resolutions(case_dir_path, case_id, correlation_type, _prefix_resolutions)

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
            raw_input,
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
            raw_input,
        )
        raise ValueError("referenced finding_id not in findings.jsonl")

    # 6. Append to the correlations chain.
    chain_entry: CorrelationChainEntry = append_correlation_entry(case_dir_path, payload)

    # 7. Audit success. The output_hash is the digest of the
    #    CorrelationChainEntry — so audit-replay can verify "the line
    #    in correlations.jsonl that this correlation points at hashes
    #    to what the audit chain claimed".
    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_TOOL_NAME,
        evidence_id=None,
        input_args=_success_input_args(
            case_id,
            correlation_type,
            iteration_number,
            referenced_ids,
            evidence_refs,
        ),
        output=chain_entry,
    )

    return payload


__all__ = ["record_correlation"]
