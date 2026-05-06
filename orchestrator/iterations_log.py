"""Hash-chained JSONL writer for orchestrator iteration records.

iterations.jsonl is the FOURTH hash-chained log in the substrate
(audit, findings, correlations are the first three). It is written
exclusively by the orchestrator at the end of every loop iteration.
Each line records the iteration's timing, the analysts dispatched,
the new findings/correlations observed during the iteration, the
promotion decisions made, and the termination check.

Why a separate file (and a separate writer) from the other three
chains:

  - The audit chain records *what each MCP tool call looked like*.
  - The findings chain records *what analysts/orchestrator claim*
    about the case (DRAFT + UPDATE).
  - The correlations chain records *what the validator observes*
    about findings.
  - The iterations chain records *what the orchestrator did per
    iteration of the self-correction loop*: the meta-narrative the
    other three chains support.
  - Distinct on-disk files mean a downstream consumer can stream one
    without parsing the others.
  - Distinct hash field names (`prev_iteration_hash` /
    `this_iteration_hash`) mean a line accidentally read from one
    file cannot be silently misinterpreted as the other.

Four writers, four roles, four chains. The rule-of-three case for
extracting a `HashChainedJsonl` base class is now the rule of four;
extraction is still deferred to a separate post-week-6 commit per
the standing convention. Tracked in `docs/decisions-log.md`.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

_ITERATIONS_FILENAME = "iterations.jsonl"
_GENESIS_PREV_HASH = "0" * 64
_HEX64_PATTERN = r"^[0-9a-f]{64}$"


class TerminationCheck(BaseModel):
    """The orchestrator's PLAN-step decision for one iteration.

    Three flags + a verdict. R_a / R_b / R_c are independent
    conditions; the verdict is "terminate" if any flag is true,
    otherwise "continue". A separate `max_iterations_reached` flag
    captures the safety-net hard cap.
    """

    R_a_zero_unresolved: bool
    R_b_disputed_set_unchanged: bool
    R_c_token_budget_exceeded: bool
    max_iterations_reached: bool = False
    decision: Literal["continue", "terminate"]


class RecordedPromotion(BaseModel):
    """One promotion decision the orchestrator made (and possibly
    persisted) during PROMOTE. Mirrors `PromotionDecision` from
    `orchestrator.promotion` but as a pydantic model so it serializes
    cleanly into the JSONL line.

    `applied` is true if the orchestrator wrote a corresponding
    `update_finding` MCP call; false for R6 (no-change) decisions
    which are skipped per the rule's idempotent-no-op semantics.
    `update_id` is populated only when `applied` is true; otherwise
    None.
    """

    finding_id: str
    new_state: Literal["DRAFT", "CONFIRMED"]
    new_confidence: Literal["LOW", "MEDIUM", "HIGH", "DISPUTED"]
    promotion_rule: Literal["R1", "R2", "R3", "R4", "R5", "R6"]
    driving_correlation_ids: list[str]
    applied: bool
    update_id: str | None = None


class IterationPayload(BaseModel):
    """The body of one iterations.jsonl line.

    Wrapped in `IterationChainEntry` for hashing.
    """

    iteration_number: int = Field(ge=0)
    started_at: datetime
    completed_at: datetime
    analysts_dispatched: list[str] = Field(default_factory=list)
    analyst_findings_added: list[str] = Field(default_factory=list)
    validator_correlations_added: list[str] = Field(default_factory=list)
    promotions_made: list[RecordedPromotion] = Field(default_factory=list)
    followup_requests_consumed: list[str] = Field(default_factory=list)
    tokens_used_uncached: int = Field(ge=0, default=0)
    cumulative_tokens_uncached: int = Field(ge=0, default=0)
    termination_check: TerminationCheck

    @field_validator("started_at", "completed_at")
    @classmethod
    def _validate_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("timestamps must be timezone-aware UTC")
        return v.astimezone(timezone.utc)


def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.astimezone(timezone.utc).isoformat()
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


class IterationChainEntry(BaseModel):
    """One JSONL line of the hash-chained iterations log.

    Same chain semantics as the other three logs:
    `prev_iteration_hash` = previous record's `this_iteration_hash`
    (genesis = 64 zeros); `this_iteration_hash` = sha256 over a
    canonical JSON serialization of every other field.
    """

    line_number: int = Field(ge=1)
    timestamp: datetime
    iteration: IterationPayload
    prev_iteration_hash: str = Field(pattern=_HEX64_PATTERN)
    this_iteration_hash: str = Field(pattern=_HEX64_PATTERN)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("timestamp must be timezone-aware UTC")
        return v.astimezone(timezone.utc)

    @classmethod
    def compute_this_iteration_hash(cls, **fields: Any) -> str:
        payload = {
            k: v for k, v in fields.items() if k != "this_iteration_hash"
        }
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_chain_state(iterations_path: Path) -> tuple[int, str]:
    """(next_line_number, prev_iteration_hash). Mirrors the other
    chain readers exactly."""
    if not iterations_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with iterations_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_iteration_hash"]


def append_iteration_entry(
    case_dir: Path | str, payload: IterationPayload
) -> IterationChainEntry:
    """Append one hash-chained record to
    `<case_dir>/iterations.jsonl`.

    Single-process: no file lock. Same convention as the other three
    chain writers.
    """
    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)
    iterations_path = case_dir_path / _ITERATIONS_FILENAME

    line_number, prev_iteration_hash = _read_chain_state(iterations_path)
    timestamp = datetime.now(tz=timezone.utc)

    chained_fields = dict(
        line_number=line_number,
        timestamp=timestamp,
        iteration=payload.model_dump(mode="json"),
        prev_iteration_hash=prev_iteration_hash,
    )
    this_iteration_hash = IterationChainEntry.compute_this_iteration_hash(
        **chained_fields
    )

    entry = IterationChainEntry(
        line_number=line_number,
        timestamp=timestamp,
        iteration=payload,
        prev_iteration_hash=prev_iteration_hash,
        this_iteration_hash=this_iteration_hash,
    )

    serialized = entry.model_dump_json()
    with iterations_path.open("a", encoding="utf-8") as f:
        f.write(serialized + "\n")
        f.flush()
        os.fsync(f.fileno())

    return entry


def read_iterations(case_dir: Path | str) -> list[IterationChainEntry]:
    """Stream iterations.jsonl back into typed entries. Used by
    tests and by the loop's PLAN step (R_b: comparing the current
    DISPUTED set to the prior iteration's DISPUTED set requires the
    prior iteration's record).
    """
    case_dir_path = Path(case_dir).resolve()
    iterations_path = case_dir_path / _ITERATIONS_FILENAME
    if not iterations_path.exists():
        return []

    entries: list[IterationChainEntry] = []
    with iterations_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            entries.append(IterationChainEntry.model_validate_json(stripped))
    return entries


__all__ = [
    "IterationChainEntry",
    "IterationPayload",
    "RecordedPromotion",
    "TerminationCheck",
    "append_iteration_entry",
    "read_iterations",
]
