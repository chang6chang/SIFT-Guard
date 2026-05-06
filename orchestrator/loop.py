"""5-step self-correction loop driver.

The loop is the project's flagship piece — it is what makes
SIFT-Guard autonomously self-correcting. Each iteration runs five
steps in order:

  1. ANALYZE   — dispatch analyst subagents (or only those with a
                 pending request_followup from the prior iteration).
  2. CORRELATE — dispatch the validator subagent over the current
                 DRAFT findings.
  3. PROMOTE   — apply R1-R6 per finding; write update_finding for
                 every non-R6 decision.
  4. PLAN      — compute termination flags (R_a / R_b / R_c plus
                 the safety-net `max_iterations_reached`).
  5. WRITE     — append the iteration record to iterations.jsonl.

The loop is synchronous. The user's design notes mentioned `async def
run_loop` for asyncio.gather'd parallel analyst dispatch, but the
substrate's hash-chain writers are not multi-process-safe (see
`dispatch.py` docstring). Until per-process file locking lands,
sequential dispatch is the only safe option, so a sync loop is
ergonomic and removes the asyncio overhead in tests.

The `update_finding` MCP call is the only place the orchestrator
talks to the SIFT-Guard server directly. Subagents own all other
tool surface; the orchestrator never calls vol_* / tier-2 /
record_finding / record_correlation. That separation enforces the
three-writer architecture from week 6 day 1.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from orchestrator import ORCHESTRATOR_VERSION
from orchestrator.dispatch import (
    DispatchResult,
    dispatch_analyst,
    dispatch_validator,
)
from orchestrator.iterations_log import (
    IterationChainEntry,
    IterationPayload,
    RecordedPromotion,
    TerminationCheck,
    append_iteration_entry,
)
from orchestrator.promotion import PromotionDecision, promote
from server.findings_log import read_finding_state
from server.schemas import (
    ContradictsCorrelation,
    CorrelationChainEntry,
    CorroboratesCorrelation,
    DraftFinding,
    FindingChainEntry,
    FindingUpdate,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)


logger = logging.getLogger(__name__)

TOKEN_BUDGET_UNCACHED = 500_000

ARTIFACT_TO_ANALYSTS: dict[str, list[str]] = {
    "memory_image": ["process_analyst", "network_analyst"],
    # Future artifact classes (disk_image, triage_zip, registry_hive,
    # event_log, pcap) wire in here when their analysts ship.
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class _IterationState:
    """Mutable bookkeeping for one iteration. Becomes an
    IterationPayload at WRITE time.
    """

    iteration_number: int
    started_at: datetime
    analysts_dispatched: list[str] = field(default_factory=list)
    analyst_finding_ids_added: list[str] = field(default_factory=list)
    validator_correlation_ids_added: list[str] = field(default_factory=list)
    promotions: list[RecordedPromotion] = field(default_factory=list)
    followup_consumed: list[str] = field(default_factory=list)
    tokens_uncached: int = 0
    dispatch_results: list[DispatchResult] = field(default_factory=list)


@dataclass
class LoopOutcome:
    iterations: list[IterationChainEntry]
    termination_reason: str
    cumulative_tokens_uncached: int


def _read_case_id(case_dir: Path) -> str:
    case_yaml = case_dir / "CASE.yaml"
    doc = yaml.safe_load(case_yaml.read_text())
    return doc["case_id"]


def _read_artifact_class(case_dir: Path, evidence_id: str) -> str:
    case_yaml = case_dir / "CASE.yaml"
    doc = yaml.safe_load(case_yaml.read_text())
    for record in doc.get("evidence", []):
        if record.get("evidence_id") == evidence_id:
            return record["artifact_class"]
    raise KeyError(f"evidence_id {evidence_id} not found in CASE.yaml")


def _read_findings_chain(case_dir: Path) -> list[FindingChainEntry]:
    path = case_dir / "findings.jsonl"
    if not path.exists():
        return []
    entries: list[FindingChainEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            entries.append(FindingChainEntry.model_validate_json(stripped))
    return entries


def _read_correlations_chain(case_dir: Path) -> list[CorrelationChainEntry]:
    path = case_dir / "correlations.jsonl"
    if not path.exists():
        return []
    entries: list[CorrelationChainEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            entries.append(CorrelationChainEntry.model_validate_json(stripped))
    return entries


def _latest_records_by_finding(
    chain: list[FindingChainEntry],
) -> dict[str, DraftFinding | FindingUpdate]:
    """Last-write-wins over the chain. Returns the most recent
    record (DRAFT or UPDATE) keyed by finding_id."""
    latest: dict[str, DraftFinding | FindingUpdate] = {}
    for entry in chain:
        latest[entry.finding.finding_id] = entry.finding
    return latest


def _draft_by_finding(
    chain: list[FindingChainEntry],
) -> dict[str, DraftFinding]:
    """The original DRAFT entry per finding_id (first seen)."""
    drafts: dict[str, DraftFinding] = {}
    for entry in chain:
        if isinstance(entry.finding, DraftFinding):
            drafts.setdefault(entry.finding.finding_id, entry.finding)
    return drafts


def _correlations_for_finding(
    correlations: list[CorrelationChainEntry], finding_id: str
):
    """Return correlations from the chain that reference finding_id
    in any role (target, finding_a/b, related)."""
    out = []
    for entry in correlations:
        c = entry.correlation
        if isinstance(c, CorroboratesCorrelation):
            if finding_id in c.target_finding_ids:
                out.append(c)
        elif isinstance(c, ContradictsCorrelation):
            if c.finding_a_id == finding_id or c.finding_b_id == finding_id:
                out.append(c)
        elif isinstance(c, (StrengthensCorrelation, WeakensCorrelation)):
            if c.target_finding_id == finding_id:
                out.append(c)
        elif isinstance(c, RequestFollowupCorrelation):
            if finding_id in c.related_finding_ids:
                out.append(c)
    return out


def _build_findings_summary(
    case_dir: Path,
) -> list[dict[str, Any]]:
    """Construct the validator's findings_summary input.

    Includes only findings whose latest state is DRAFT — CONFIRMED
    findings are out of scope per the validator's contract. Each
    summary entry is small (id, analyst, title, category,
    confidence, state, evidence_refs) so the validator's prompt
    stays tractable.
    """
    chain = _read_findings_chain(case_dir)
    drafts = _draft_by_finding(chain)
    summary: list[dict[str, Any]] = []
    for fid, draft in drafts.items():
        latest_state = read_finding_state(case_dir, fid)
        state, conf = latest_state if latest_state else (draft.state, draft.confidence)
        if state != "DRAFT":
            continue
        summary.append(
            {
                "finding_id": fid,
                "analyst": draft.analyst,
                "title": draft.title,
                "category": draft.category,
                "severity": draft.severity,
                "confidence": conf,
                "state": state,
                "evidence_refs": [
                    {
                        "source_tool": ref.source_tool,
                        "audit_line": ref.audit_line,
                        "detail": ref.detail,
                    }
                    for ref in draft.evidence_refs
                ],
            }
        )
    return summary


def _disputed_set(case_dir: Path) -> frozenset[str]:
    """Set of finding_ids whose latest record has confidence=DISPUTED."""
    chain = _read_findings_chain(case_dir)
    drafts = _draft_by_finding(chain)
    out: set[str] = set()
    for fid in drafts:
        st = read_finding_state(case_dir, fid)
        if st and st[1] == "DISPUTED":
            out.add(fid)
    return frozenset(out)


def _unresolved_set(case_dir: Path) -> frozenset[str]:
    """Set of finding_ids whose latest record is DRAFT or DISPUTED."""
    chain = _read_findings_chain(case_dir)
    drafts = _draft_by_finding(chain)
    out: set[str] = set()
    for fid in drafts:
        st = read_finding_state(case_dir, fid)
        if not st:
            continue
        state, conf = st
        if state == "DRAFT" or conf == "DISPUTED":
            out.add(fid)
    return frozenset(out)


async def _call_update_finding_async(
    case_cwd: Path, args: dict[str, Any]
) -> dict[str, Any]:
    """Spawn a fresh MCP server stdio session and call update_finding."""
    python_exe = str(PROJECT_ROOT / ".venv" / "bin" / "python")
    env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    params = StdioServerParameters(
        command=python_exe,
        args=["-m", "server.main"],
        env=env,
        cwd=str(case_cwd),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("update_finding", arguments=args)
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    if result.content:
        for block in result.content:
            text = getattr(block, "text", None)
            if text:
                try:
                    return json.loads(text)
                except (ValueError, TypeError):
                    continue
    return {}


def _call_update_finding(case_cwd: Path, args: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(_call_update_finding_async(case_cwd, args))


def _step_analyze(
    state: _IterationState,
    *,
    case_dir: Path,
    case_cwd: Path,
    case_id: str,
    evidence_id: str,
    analysts: list[str],
    focus_contexts: dict[str, dict[str, Any]] | None,
    dispatch_fn,
) -> None:
    """Sequential analyst dispatch. focus_contexts is a per-analyst
    dict for iter ≥2; iter 1 passes None."""
    findings_before = {
        e.finding.finding_id
        for e in _read_findings_chain(case_dir)
        if isinstance(e.finding, DraftFinding)
    }
    for agent in analysts:
        focus = focus_contexts.get(agent) if focus_contexts else None
        result = dispatch_fn(
            agent=agent,
            evidence_id=evidence_id,
            case_id=case_id,
            iteration_number=state.iteration_number,
            cwd=case_cwd,
            focus_context=focus,
        )
        state.dispatch_results.append(result)
        state.analysts_dispatched.append(agent)
        state.tokens_uncached += result.tokens_uncached
        if not result.succeeded:
            logger.warning(
                "analyst %s did not complete cleanly (stop_reason=%s)",
                agent,
                result.stop_reason,
            )
    findings_after_chain = _read_findings_chain(case_dir)
    findings_after = {
        e.finding.finding_id
        for e in findings_after_chain
        if isinstance(e.finding, DraftFinding)
    }
    state.analyst_finding_ids_added = sorted(findings_after - findings_before)


def _step_correlate(
    state: _IterationState,
    *,
    case_dir: Path,
    case_cwd: Path,
    case_id: str,
    evidence_id: str,
    dispatch_fn,
) -> list[CorrelationChainEntry]:
    """Build findings_summary, dispatch validator, return new
    correlations from the chain."""
    correlations_before = {
        e.correlation.correlation_id for e in _read_correlations_chain(case_dir)
    }
    findings_summary = _build_findings_summary(case_dir)
    if not findings_summary:
        logger.info("step_correlate: no DRAFT findings; skipping validator")
        return []

    result = dispatch_fn(
        evidence_id=evidence_id,
        case_id=case_id,
        iteration_number=state.iteration_number,
        findings_summary=findings_summary,
        cwd=case_cwd,
    )
    state.dispatch_results.append(result)
    state.tokens_uncached += result.tokens_uncached
    if not result.succeeded:
        logger.warning(
            "validator did not complete cleanly (stop_reason=%s)",
            result.stop_reason,
        )

    correlations_chain = _read_correlations_chain(case_dir)
    correlations_after = {
        e.correlation.correlation_id for e in correlations_chain
    }
    new_ids = correlations_after - correlations_before
    state.validator_correlation_ids_added = sorted(new_ids)
    return [
        e for e in correlations_chain if e.correlation.correlation_id in new_ids
    ]


def _step_promote(
    state: _IterationState,
    *,
    case_dir: Path,
    case_cwd: Path,
    iterations_so_far: int,
    update_fn,
) -> None:
    """Apply R1-R6 per DRAFT finding. Skip R6 (no-op). For each
    non-R6 decision, call update_finding via MCP and record the
    update_id."""
    chain = _read_findings_chain(case_dir)
    correlations = _read_correlations_chain(case_dir)
    latest = _latest_records_by_finding(chain)
    drafts = _draft_by_finding(chain)

    for fid, draft in drafts.items():
        st = read_finding_state(case_dir, fid)
        if not st:
            continue
        cur_state, _ = st
        if cur_state == "CONFIRMED":
            continue
        f_record = latest.get(fid, draft)
        c_for_f = _correlations_for_finding(correlations, fid)
        decision = promote(f_record, c_for_f, iterations_so_far)
        if decision.promotion_rule == "R6":
            state.promotions.append(
                RecordedPromotion(
                    finding_id=fid,
                    new_state=decision.new_state,
                    new_confidence=decision.new_confidence,
                    promotion_rule=decision.promotion_rule,
                    driving_correlation_ids=decision.driving_correlation_ids,
                    applied=False,
                    update_id=None,
                )
            )
            continue

        # R1-R5: apply via update_finding. R1 emits state=DRAFT but
        # the substrate accepts that transition as long as
        # confidence changes. R2-R5 emit CONFIRMED.
        # update_finding requires driving_correlation_ids min_length=1.
        # R5 (quiet stabilization) has none — pass a synthetic empty
        # path: skip the update for R5 too. R5 represents "no change
        # warranted from correlations". Treat it as an in-memory
        # promotion without an on-disk update_finding.
        if not decision.driving_correlation_ids:
            state.promotions.append(
                RecordedPromotion(
                    finding_id=fid,
                    new_state=decision.new_state,
                    new_confidence=decision.new_confidence,
                    promotion_rule=decision.promotion_rule,
                    driving_correlation_ids=[],
                    applied=False,
                    update_id=None,
                )
            )
            continue

        try:
            response = update_fn(
                case_cwd,
                {
                    "finding_id": fid,
                    "iteration_number": state.iteration_number,
                    "new_state": decision.new_state,
                    "new_confidence": decision.new_confidence,
                    "promotion_rule": decision.promotion_rule,
                    "driving_correlation_ids": decision.driving_correlation_ids,
                    "orchestrator_version": ORCHESTRATOR_VERSION,
                },
            )
            update_id = response.get("update_id") if isinstance(response, dict) else None
            applied = update_id is not None
        except Exception as exc:  # noqa: BLE001
            logger.error("update_finding failed for %s: %s", fid, exc)
            update_id = None
            applied = False

        state.promotions.append(
            RecordedPromotion(
                finding_id=fid,
                new_state=decision.new_state,
                new_confidence=decision.new_confidence,
                promotion_rule=decision.promotion_rule,
                driving_correlation_ids=decision.driving_correlation_ids,
                applied=applied,
                update_id=update_id,
            )
        )


def _step_plan(
    state: _IterationState,
    *,
    case_dir: Path,
    cumulative_tokens: int,
    prior_disputed: frozenset[str] | None,
    iteration_number: int,
    max_iterations: int,
) -> TerminationCheck:
    R_a = len(_unresolved_set(case_dir)) == 0
    cur_disputed = _disputed_set(case_dir)
    R_b = (
        prior_disputed is not None
        and prior_disputed == cur_disputed
        and len(cur_disputed) > 0
        and iteration_number > 1
    )
    R_c = cumulative_tokens >= TOKEN_BUDGET_UNCACHED
    max_reached = iteration_number >= max_iterations
    decision = "terminate" if (R_a or R_b or R_c or max_reached) else "continue"
    return TerminationCheck(
        R_a_zero_unresolved=R_a,
        R_b_disputed_set_unchanged=bool(R_b),
        R_c_token_budget_exceeded=R_c,
        max_iterations_reached=max_reached,
        decision=decision,
    )


def _next_iter_dispatch_plan(
    state: _IterationState, new_correlations: list[CorrelationChainEntry]
) -> tuple[list[str], dict[str, dict[str, Any]], list[str]]:
    """From the validator's request_followup correlations in this
    iteration, derive (analysts_for_next_iter, focus_contexts,
    consumed_correlation_ids).
    """
    analysts: list[str] = []
    focus: dict[str, dict[str, Any]] = {}
    consumed: list[str] = []
    for entry in new_correlations:
        c = entry.correlation
        if isinstance(c, RequestFollowupCorrelation):
            consumed.append(c.correlation_id)
            if c.target_analyst not in analysts:
                analysts.append(c.target_analyst)
            # Last followup wins for focus; multiple followups against
            # the same analyst will be folded by intersection in a
            # future iteration's design. For now: latest replaces.
            focus[c.target_analyst] = c.focus_context
    return analysts, focus, consumed


def run_loop(
    *,
    case_dir: Path,
    evidence_id: str,
    max_iterations: int = 10,
    token_budget: int = TOKEN_BUDGET_UNCACHED,
    dispatch_analyst_fn=dispatch_analyst,
    dispatch_validator_fn=dispatch_validator,
    update_finding_fn=_call_update_finding,
    case_cwd: Path | None = None,
) -> LoopOutcome:
    """Drive the 5-step loop until a termination flag fires.

    `case_cwd` defaults to `case_dir.parent` — the directory the MCP
    server should run from so its `CASE_DIR = "case-data"` constant
    resolves correctly. Tests override the dispatch / update
    functions to keep the loop pure-Python.
    """
    case_dir = case_dir.resolve()
    if case_cwd is None:
        case_cwd = case_dir.parent

    case_id = _read_case_id(case_dir)
    artifact_class = _read_artifact_class(case_dir, evidence_id)
    initial_analysts = ARTIFACT_TO_ANALYSTS.get(artifact_class, [])
    if not initial_analysts:
        raise ValueError(
            f"no analysts mapped for artifact_class={artifact_class!r}"
        )

    iteration_records: list[IterationChainEntry] = []
    cumulative_tokens = 0
    prior_disputed: frozenset[str] | None = None
    pending_analysts = list(initial_analysts)
    pending_focus: dict[str, dict[str, Any]] | None = None
    termination_reason = "max_iterations_reached"

    for iteration_number in range(1, max_iterations + 1):
        if not pending_analysts:
            logger.info(
                "iter %d: no analysts pending; terminating", iteration_number
            )
            termination_reason = "no_followup_pending"
            break

        state = _IterationState(
            iteration_number=iteration_number,
            started_at=datetime.now(tz=timezone.utc),
        )

        _step_analyze(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            case_id=case_id,
            evidence_id=evidence_id,
            analysts=pending_analysts,
            focus_contexts=pending_focus,
            dispatch_fn=dispatch_analyst_fn,
        )

        new_correlations = _step_correlate(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            case_id=case_id,
            evidence_id=evidence_id,
            dispatch_fn=dispatch_validator_fn,
        )

        _step_promote(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            iterations_so_far=iteration_number - 1,
            update_fn=update_finding_fn,
        )

        cumulative_tokens += state.tokens_uncached
        termination = _step_plan(
            state,
            case_dir=case_dir,
            cumulative_tokens=cumulative_tokens,
            prior_disputed=prior_disputed,
            iteration_number=iteration_number,
            max_iterations=max_iterations,
        )

        next_analysts, next_focus, consumed = _next_iter_dispatch_plan(
            state, new_correlations
        )
        state.followup_consumed = consumed

        completed_at = datetime.now(tz=timezone.utc)
        payload = IterationPayload(
            iteration_number=state.iteration_number,
            started_at=state.started_at,
            completed_at=completed_at,
            analysts_dispatched=state.analysts_dispatched,
            analyst_findings_added=state.analyst_finding_ids_added,
            validator_correlations_added=state.validator_correlation_ids_added,
            promotions_made=state.promotions,
            followup_requests_consumed=state.followup_consumed,
            tokens_used_uncached=state.tokens_uncached,
            cumulative_tokens_uncached=cumulative_tokens,
            termination_check=termination,
        )
        entry = append_iteration_entry(case_dir, payload)
        iteration_records.append(entry)

        if termination.decision == "terminate":
            if termination.R_a_zero_unresolved:
                termination_reason = "R_a_zero_unresolved"
            elif termination.R_b_disputed_set_unchanged:
                termination_reason = "R_b_disputed_set_unchanged"
            elif termination.R_c_token_budget_exceeded:
                termination_reason = "R_c_token_budget_exceeded"
            else:
                termination_reason = "max_iterations_reached"
            break

        prior_disputed = _disputed_set(case_dir)
        pending_analysts = next_analysts
        pending_focus = next_focus if next_focus else None

    return LoopOutcome(
        iterations=iteration_records,
        termination_reason=termination_reason,
        cumulative_tokens_uncached=cumulative_tokens,
    )


__all__ = [
    "ARTIFACT_TO_ANALYSTS",
    "LoopOutcome",
    "TOKEN_BUDGET_UNCACHED",
    "run_loop",
]
