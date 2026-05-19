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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from orchestrator import ORCHESTRATOR_VERSION
from orchestrator.dispatch import (
    DispatchResult,
    dispatch_analyst,
    dispatch_validator,
)


# Coarse-grained event hook for run-time observers (the sift-guard
# CLI's real-time progress display, primarily). The callback is
# invoked synchronously between dispatches; it receives a
# kebab-string event name and a free-form payload dict. Keep
# callbacks fast — they run on the loop's main thread.
ProgressCallback = Callable[[str, dict[str, Any]], None]


def _emit(on_progress: ProgressCallback | None, event: str, payload: dict[str, Any]) -> None:
    if on_progress is None:
        return
    try:
        on_progress(event, payload)
    except Exception:  # noqa: BLE001
        # Progress callbacks are observers; their exceptions must
        # never bring down the loop. Log and continue.
        logger.exception("on_progress callback raised on event %s; suppressing", event)
from orchestrator.iterations_log import (
    IterationChainEntry,
    IterationPayload,
    RecordedPromotion,
    TerminationCheck,
    append_iteration_entry,
)
from orchestrator.manifest import CaseManifest
from orchestrator.promotion import promote
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
    # Disk-image artifact class wires to disk_analyst (week 8).
    "disk_image": ["disk_analyst"],
    # Future artifact classes (triage_zip, registry_hive, event_log,
    # pcap) wire in here when their analysts ship.
}

# Manifest evidence_type → analysts. Mirrors ARTIFACT_TO_ANALYSTS but
# keyed on the manifest's narrower type bucket. The two maps are kept
# parallel: ARTIFACT_TO_ANALYSTS resolves an evidence_id's CASE.yaml
# artifact_class for the single-evidence run mode; MANIFEST_TYPE_TO_ANALYSTS
# resolves a manifest's evidence_type bucket for run-case mode.
MANIFEST_TYPE_TO_ANALYSTS: dict[str, list[str]] = {
    "memory": ["process_analyst", "network_analyst"],
    "disk": ["disk_analyst"],
    # "unknown" intentionally absent — unknown evidence is skipped
    # at dispatch time with a warning written to the iteration log.
}

# Multi-evidence runs see more findings, more correlations, more
# token cost. Default budget scales with host count: 500K base + 250K
# per host. The `--token-budget` CLI flag overrides this.
TOKEN_BUDGET_MULTI_BASE = 500_000
TOKEN_BUDGET_PER_HOST = 250_000

# Parallel analyst dispatch cap. Each in-flight analyst spawns a
# `claude -p --agent <name>` subprocess plus its MCP-server child;
# the limit prevents wide cases (12+ analyst-jobs per iteration) from
# saturating CPU / RAM / Anthropic-side concurrency. 12 covers the
# common 4-host case (4 × 3 analysts) without queueing; raise via the
# `parallel_max_workers` argument to `run_loop_multi_host` for wider
# cases.
DEFAULT_PARALLEL_MAX_WORKERS = 12

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


def _correlations_for_finding(correlations: list[CorrelationChainEntry], finding_id: str):
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
    case_dir: Path, case_cwd: Path, args: dict[str, Any]
) -> dict[str, Any]:
    """Spawn a fresh MCP server stdio session and call update_finding.

    ``SIFT_GUARD_CASE_DIR`` is set to ``case_dir`` (the actual case
    directory holding ``findings.jsonl`` / ``correlations.jsonl``),
    not ``case_cwd``. The 2026-05-13 SRL-v2 run hit this: the env
    var was being set to ``case_dir.parent`` (the CLI's working
    cwd), so the MCP server's update_finding couldn't find the
    finding_ids — every R3/R4 promotion logged ``applied=False`` and
    zero ``update_finding`` audit lines hit the chain. The subprocess
    cwd is ``case_cwd`` (matches the analyst-dispatch convention so
    relative-path debugging is consistent), but the case data path is
    pinned via the env var.
    """
    python_exe = str(PROJECT_ROOT / ".venv" / "bin" / "python")
    env = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT),
        "SIFT_GUARD_CASE_DIR": str(case_dir),
    }
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


def _call_update_finding(
    case_dir: Path, case_cwd: Path, args: dict[str, Any]
) -> dict[str, Any]:
    return asyncio.run(_call_update_finding_async(case_dir, case_cwd, args))


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
        e.finding.finding_id for e in findings_after_chain if isinstance(e.finding, DraftFinding)
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
    correlations_before = {e.correlation.correlation_id for e in _read_correlations_chain(case_dir)}
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
    correlations_after = {e.correlation.correlation_id for e in correlations_chain}
    new_ids = correlations_after - correlations_before
    state.validator_correlation_ids_added = sorted(new_ids)
    return [e for e in correlations_chain if e.correlation.correlation_id in new_ids]


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
        #
        # R5 ("quiet stabilization") writes update_finding with an
        # empty `driving_correlation_ids` list — the rule's defining
        # precondition is "no correlations on F across two iterations
        # of silence", and as of the 2026-05-07 schema relaxation the
        # FindingUpdate model permits an empty list iff
        # promotion_rule == "R5". The chain therefore records R5
        # promotions just like R1-R4 promotions (same on-disk shape,
        # same audit-trail provenance), and the unresolved-set check
        # in `_step_plan` correctly drops R5'd findings. Prior to the
        # relaxation R5 was an in-memory-only promotion that left
        # findings stuck DRAFT; see docs/decisions-log.md for the
        # architectural-tension write-up.

        try:
            response = update_fn(
                case_dir,
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
        raise ValueError(f"no analysts mapped for artifact_class={artifact_class!r}")

    iteration_records: list[IterationChainEntry] = []
    cumulative_tokens = 0
    prior_disputed: frozenset[str] | None = None
    pending_analysts = list(initial_analysts)
    pending_focus: dict[str, dict[str, Any]] | None = None
    termination_reason = "max_iterations_reached"

    for iteration_number in range(1, max_iterations + 1):
        if not pending_analysts:
            logger.info("iter %d: no analysts pending; terminating", iteration_number)
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

        next_analysts, next_focus, consumed = _next_iter_dispatch_plan(state, new_correlations)
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


# ---------------------------------------------------------------------------
# Multi-evidence (run-case) loop. Sits alongside `run_loop` rather than
# replacing it — the single-evidence path is the original contract and
# stays load-bearing for the existing accuracy report and integration
# tests. The multi-host variant walks a `CaseManifest` produced by
# `orchestrator.inventory` + registers, dispatches per-host analysts
# in sequence, then runs a single host-grouped CORRELATE step over
# every host's DRAFT findings.
# ---------------------------------------------------------------------------


def _build_findings_summary_grouped_by_host(
    case_dir: Path, manifest: CaseManifest
) -> list[dict[str, Any]]:
    """Build the validator's findings input as host-grouped blocks.

    Returns a list of {host_id, host_label, findings: [...]} dicts.
    Hosts with zero DRAFT findings produce an empty `findings` list
    rather than being omitted — gives the validator a clear "this
    host had nothing this iteration" signal.

    Findings whose `host_id` does not match any manifest host are
    grouped under the synthetic host_id `"_unattributed"` — should
    be empty under normal run-case dispatch but defends against the
    pathological case of a finding written without host context
    during a run-case iteration.
    """
    chain = _read_findings_chain(case_dir)
    drafts = _draft_by_finding(chain)

    by_host: dict[str, list[dict[str, Any]]] = {h.host_id: [] for h in manifest.hosts}
    by_host["_unattributed"] = []

    for fid, draft in drafts.items():
        latest_state = read_finding_state(case_dir, fid)
        state, conf = latest_state if latest_state else (draft.state, draft.confidence)
        if state != "DRAFT":
            continue
        finding_dict = {
            "finding_id": fid,
            "analyst": draft.analyst,
            "title": draft.title,
            "category": draft.category,
            "severity": draft.severity,
            "confidence": conf,
            "state": state,
            "host_id": draft.host_id,
            "evidence_refs": [
                {
                    "source_tool": ref.source_tool,
                    "audit_line": ref.audit_line,
                    "detail": ref.detail,
                }
                for ref in draft.evidence_refs
            ],
        }
        bucket_key = draft.host_id if draft.host_id in by_host else "_unattributed"
        by_host[bucket_key].append(finding_dict)

    out: list[dict[str, Any]] = []
    for host in manifest.hosts:
        out.append(
            {
                "host_id": host.host_id,
                "host_label": host.host_label,
                "findings": by_host[host.host_id],
            }
        )
    if by_host["_unattributed"]:
        out.append(
            {
                "host_id": "_unattributed",
                "host_label": "(no host_id)",
                "findings": by_host["_unattributed"],
            }
        )
    return out


def _step_analyze_multi_host(
    state: _IterationState,
    *,
    case_dir: Path,
    case_cwd: Path,
    case_id: str,
    manifest: CaseManifest,
    pending_host_ids: list[str] | None,
    pending_focus: dict[str, dict[str, Any]] | None,
    dispatch_fn,
    on_progress: ProgressCallback | None = None,
    parallel: bool = True,
    parallel_max_workers: int = DEFAULT_PARALLEL_MAX_WORKERS,
) -> list[str]:
    """Analyst dispatch across hosts/evidence/analysts, optionally in parallel.

    Work plan: every (host, evidence_file, analyst) triple where the
    analyst applies to the evidence_type. ``pending_host_ids`` (when
    set) restricts the sweep to those hosts only — the
    request_followup mechanism's targeted re-run path.
    ``pending_focus`` is a per-analyst dict applied across hosts.

    Parallelism:
      - ``parallel=True`` (default) submits every job to a
        ``ThreadPoolExecutor`` bounded by ``parallel_max_workers``.
        Memory / disk analysts on the same host run alongside each
        other; analysts on different hosts also run in parallel.
        The hash-chained writers (audit, findings, correlations,
        extractions, iterations) all serialize via
        ``server._chain_lock`` so the chain integrity holds across
        the concurrent MCP-server processes one-per-analyst spawns.
      - ``parallel=False`` is the legacy sequential path — kept as a
        fallback for the ``--no-parallel`` CLI flag and for tests
        whose ordering assertions depend on deterministic dispatch.

    Concurrency safety:
      - ``state`` mutations (``dispatch_results.append``,
        ``tokens_uncached +=``, ``analysts_dispatched.append``) live
        under ``state_lock``.
      - ``on_progress`` emissions live under ``emit_lock`` so the
        callback can assume single-thread ordering even when
        dispatch parallelism is wide.

    Per-analyst ``findings_added`` in the ``analyze_done`` event is
    *approximate* under parallel mode: the pre/post chain snapshot
    around one analyst can see findings written by another that
    finished in between. Iteration-level
    ``state.analyst_finding_ids_added`` (computed at the end against
    the iteration's start snapshot) remains exact.

    Returns the list of host_ids actually dispatched against (used
    by the caller to build the iteration record's
    ``manifest_summary`` block). Sorted for determinism even under
    parallel completion order.
    """
    findings_before = {
        e.finding.finding_id
        for e in _read_findings_chain(case_dir)
        if isinstance(e.finding, DraftFinding)
    }

    # 1. Collect jobs + skip-events deterministically.
    jobs: list[tuple[Any, Any, str, dict[str, Any] | None]] = []
    skip_events: list[dict[str, Any]] = []
    dispatched_host_ids_set: set[str] = set()
    for host in manifest.hosts:
        if pending_host_ids is not None and host.host_id not in pending_host_ids:
            continue
        host_has_active_evidence = False
        for ef in host.evidence_files:
            analysts = MANIFEST_TYPE_TO_ANALYSTS.get(ef.evidence_type)
            if analysts is None:
                logger.warning(
                    "skipping unknown evidence_type %s on host %s (evidence_id %s)",
                    ef.evidence_type,
                    host.host_id,
                    ef.evidence_id,
                )
                skip_events.append(
                    {
                        "host_id": host.host_id,
                        "host_label": host.host_label,
                        "evidence_id": ef.evidence_id,
                        "evidence_type": ef.evidence_type,
                    }
                )
                continue
            host_has_active_evidence = True
            for agent in analysts:
                focus = pending_focus.get(agent) if pending_focus else None
                jobs.append((host, ef, agent, focus))
        if host_has_active_evidence:
            dispatched_host_ids_set.add(host.host_id)

    # 2. Emit skip events synchronously (no dispatch happens for these).
    for payload in skip_events:
        _emit(on_progress, "host_skip", payload)

    # 3. Locks for state mutation + progress emission. Both are
    # threading.Lock — fine-grained, contention is rare since
    # each protected section is microseconds.
    state_lock = threading.Lock()
    emit_lock = threading.Lock()

    def safe_emit(event: str, payload: dict[str, Any]) -> None:
        with emit_lock:
            _emit(on_progress, event, payload)

    def _count_draft_finding_ids_for(analyst_name: str, host_id: str) -> int:
        """Count DRAFT findings attributable to a specific (analyst,
        host) pair. The 2026-05-13 SRL-v2 run made the cost of
        omitting this filter very visible: a disk_analyst dispatch
        that timed out at 1800s with zero tool calls still got the
        console line ``→ 14 new finding(s)`` — because the global
        DRAFT count diff included findings recorded by the
        process_analyst + network_analyst dispatches running in
        parallel during the same wall window. Filtering by analyst +
        host_id disambiguates: a timed-out disk_analyst now correctly
        reports 0 new findings of its own, regardless of what its
        sibling analysts produce.
        """
        return len(
            {
                e.finding.finding_id
                for e in _read_findings_chain(case_dir)
                if isinstance(e.finding, DraftFinding)
                and e.finding.analyst == analyst_name
                and e.finding.host_id == host_id
            }
        )

    def run_one_job(host, ef, agent, focus) -> None:
        safe_emit(
            "analyze_start",
            {
                "host_id": host.host_id,
                "host_label": host.host_label,
                "analyst": agent,
                "evidence_id": ef.evidence_id,
                "focused": focus is not None,
            },
        )
        pre_dispatch_findings_count = _count_draft_finding_ids_for(agent, host.host_id)
        result = dispatch_fn(
            agent=agent,
            evidence_id=ef.evidence_id,
            case_id=case_id,
            iteration_number=state.iteration_number,
            cwd=case_cwd,
            focus_context=focus,
            host_id=host.host_id,
            host_label=host.host_label,
        )
        with state_lock:
            state.dispatch_results.append(result)
            state.analysts_dispatched.append(f"{agent}@{host.host_id}")
            state.tokens_uncached += result.tokens_uncached
        if not result.succeeded:
            logger.warning(
                "analyst %s on host %s did not complete cleanly (stop_reason=%s)",
                agent,
                host.host_id,
                result.stop_reason,
            )
        post_dispatch_findings_count = _count_draft_finding_ids_for(agent, host.host_id)
        safe_emit(
            "analyze_done",
            {
                "host_id": host.host_id,
                "host_label": host.host_label,
                "analyst": agent,
                "evidence_id": ef.evidence_id,
                "findings_added": post_dispatch_findings_count
                - pre_dispatch_findings_count,
                "tokens_uncached": result.tokens_uncached,
                "duration_ms": result.duration_ms,
                "succeeded": result.succeeded,
                "stop_reason": result.stop_reason,
            },
        )

    # 4. Run jobs.
    if parallel and len(jobs) > 1:
        max_workers = min(len(jobs), parallel_max_workers)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="analyst") as pool:
            futures = [pool.submit(run_one_job, *job) for job in jobs]
            for fut in as_completed(futures):
                # Re-raise on exception so loop crashes cleanly
                # instead of silently swallowing analyst failures.
                fut.result()
    else:
        for job in jobs:
            run_one_job(*job)

    findings_after_chain = _read_findings_chain(case_dir)
    findings_after = {
        e.finding.finding_id for e in findings_after_chain if isinstance(e.finding, DraftFinding)
    }
    state.analyst_finding_ids_added = sorted(findings_after - findings_before)
    return sorted(dispatched_host_ids_set)


def _step_correlate_multi_host(
    state: _IterationState,
    *,
    case_dir: Path,
    case_cwd: Path,
    case_id: str,
    manifest: CaseManifest,
    dispatch_fn,
    on_progress: ProgressCallback | None = None,
) -> list[CorrelationChainEntry]:
    """Cross-host CORRELATE. Single validator dispatch over all
    hosts' DRAFT findings, framed as host-grouped blocks. The
    validator can emit per-host correlations (corroborates,
    contradicts, etc.) AND cross-host correlations linking
    findings across hosts.

    Validator dispatch uses the FIRST host's first memory evidence_id
    as the `evidence_id` argument — the validator's tool surface
    requires one for the prompt's `evidence_id:` line, but its
    findings reasoning spans every host. If no memory evidence
    exists in the manifest, falls back to the first host's first
    evidence_file regardless of type.
    """
    correlations_before = {e.correlation.correlation_id for e in _read_correlations_chain(case_dir)}
    host_grouped = _build_findings_summary_grouped_by_host(case_dir, manifest)
    total_drafts = sum(len(b["findings"]) for b in host_grouped)
    host_count_with_drafts = sum(1 for b in host_grouped if b["findings"])
    if total_drafts == 0:
        logger.info("step_correlate (multi-host): no DRAFT findings; skipping validator")
        _emit(
            on_progress,
            "correlate_skip",
            {"reason": "no_draft_findings"},
        )
        return []
    _emit(
        on_progress,
        "correlate_start",
        {
            "draft_findings": total_drafts,
            "host_count": host_count_with_drafts,
        },
    )

    # Choose a representative evidence_id for the validator's
    # prompt envelope. Prefer a memory image (the validator's tool
    # surface includes vol_*); fall back to whatever the first host
    # has.
    representative_evidence_id: str | None = None
    for host in manifest.hosts:
        for ef in host.evidence_files:
            if ef.evidence_type == "memory":
                representative_evidence_id = ef.evidence_id
                break
        if representative_evidence_id is not None:
            break
    if representative_evidence_id is None:
        representative_evidence_id = manifest.hosts[0].evidence_files[0].evidence_id

    result = dispatch_fn(
        evidence_id=representative_evidence_id,
        case_id=case_id,
        iteration_number=state.iteration_number,
        host_grouped_findings=host_grouped,
        cwd=case_cwd,
    )
    state.dispatch_results.append(result)
    state.tokens_uncached += result.tokens_uncached
    if not result.succeeded:
        logger.warning(
            "validator (multi-host) did not complete cleanly (stop_reason=%s)",
            result.stop_reason,
        )

    correlations_chain = _read_correlations_chain(case_dir)
    correlations_after = {e.correlation.correlation_id for e in correlations_chain}
    new_ids = correlations_after - correlations_before
    state.validator_correlation_ids_added = sorted(new_ids)
    new_entries = [e for e in correlations_chain if e.correlation.correlation_id in new_ids]
    cross_host_count = sum(
        1
        for e in new_entries
        if getattr(e.correlation, "correlation_type", None) == "cross_host"
    )
    _emit(
        on_progress,
        "correlate_done",
        {
            "correlations_added": len(new_entries),
            "cross_host": cross_host_count,
            "tokens_uncached": result.tokens_uncached,
            "duration_ms": result.duration_ms,
            "succeeded": result.succeeded,
            "stop_reason": result.stop_reason,
        },
    )
    return new_entries


def _next_iter_multi_host_plan(
    new_correlations: list[CorrelationChainEntry],
    manifest: CaseManifest,
) -> tuple[list[str], dict[str, dict[str, Any]], list[str]]:
    """From the validator's request_followup correlations, derive
    `(host_ids_for_next_iter, focus_contexts, consumed_correlation_ids)`.

    Single-host followup convention extended for run-case: a
    request_followup whose `focus_context` carries a `host_id`
    targets that host. Without a host_id key, the followup applies
    to every host (rare).
    """
    host_ids_to_dispatch: set[str] = set()
    focus: dict[str, dict[str, Any]] = {}
    consumed: list[str] = []
    known_host_ids = {h.host_id for h in manifest.hosts}
    for entry in new_correlations:
        c = entry.correlation
        if isinstance(c, RequestFollowupCorrelation):
            consumed.append(c.correlation_id)
            target_host = c.focus_context.get("host_id") if c.focus_context else None
            if target_host and target_host in known_host_ids:
                host_ids_to_dispatch.add(target_host)
            else:
                # No host scoping — re-dispatch all hosts.
                host_ids_to_dispatch.update(known_host_ids)
            focus[c.target_analyst] = dict(c.focus_context or {})
    return sorted(host_ids_to_dispatch), focus, consumed


def _manifest_summary_for_log(
    manifest: CaseManifest,
    dispatched_host_ids: list[str],
) -> dict[str, Any]:
    """Compact dict for IterationPayload.manifest_summary."""
    return {
        "host_count": len(manifest.hosts),
        "evidence_counts_by_host": {h.host_id: h.evidence_count for h in manifest.hosts},
        "dispatched_host_ids": dispatched_host_ids,
    }


def _default_multi_host_token_budget(host_count: int) -> int:
    """Heuristic: 500K base + 250K per host. Capped at 5M."""
    return min(
        TOKEN_BUDGET_MULTI_BASE + TOKEN_BUDGET_PER_HOST * host_count,
        5_000_000,
    )


def run_loop_multi_host(
    *,
    case_dir: Path,
    manifest: CaseManifest,
    max_iterations: int = 10,
    token_budget: int | None = None,
    dispatch_analyst_fn=dispatch_analyst,
    dispatch_validator_fn=dispatch_validator,
    update_finding_fn=_call_update_finding,
    case_cwd: Path | None = None,
    on_progress: ProgressCallback | None = None,
    parallel: bool = True,
    parallel_max_workers: int = DEFAULT_PARALLEL_MAX_WORKERS,
) -> LoopOutcome:
    """Multi-evidence variant of `run_loop`.

    Walks the manifest. For each iteration:
      1. ANALYZE — dispatch per-host per-evidence-file analysts.
         pending_host_ids (when set) restricts the sweep to a
         followup-targeted subset.
      2. CORRELATE — single validator dispatch over host-grouped
         DRAFT findings; can emit `cross_host` correlations.
      3. PROMOTE — same R1-R6 engine; cross_host correlations feed
         R3 strong-corroboration the same as same-host
         corroborates correlations (independent sources).
      4. PLAN — same termination flags. R_c uses the multi-host
         budget heuristic by default.
      5. WRITE — iteration record carries `manifest_summary`.

    Parallel dispatch is on by default. The hash-chained writers
    (audit / findings / correlations / extractions / iterations)
    serialize via ``server._chain_lock``, so multiple
    parallel-dispatched subagent MCP-server processes can safely
    write to the same chain files concurrently. The validator
    (CORRELATE) and PROMOTE / PLAN / WRITE steps stay sequential —
    correlations depend on the full DRAFT set being settled.
    Set ``parallel=False`` for the legacy in-order dispatch (used
    by the ``--no-parallel`` CLI flag and ordering-sensitive tests).
    """
    case_dir = case_dir.resolve()
    if case_cwd is None:
        case_cwd = case_dir.parent

    if token_budget is None:
        token_budget = _default_multi_host_token_budget(len(manifest.hosts))

    iteration_records: list[IterationChainEntry] = []
    cumulative_tokens = 0
    prior_disputed: frozenset[str] | None = None
    pending_host_ids: list[str] | None = None  # None = all hosts
    pending_focus: dict[str, dict[str, Any]] | None = None
    termination_reason = "max_iterations_reached"

    for iteration_number in range(1, max_iterations + 1):
        if pending_host_ids is not None and not pending_host_ids:
            logger.info("iter %d: no host pending; terminating", iteration_number)
            termination_reason = "no_followup_pending"
            _emit(on_progress, "terminate", {"reason": "no_followup_pending"})
            break

        state = _IterationState(
            iteration_number=iteration_number,
            started_at=datetime.now(tz=timezone.utc),
        )
        _emit(
            on_progress,
            "iteration_start",
            {
                "iteration": iteration_number,
                "max_iterations": max_iterations,
                "pending_host_ids": list(pending_host_ids) if pending_host_ids else None,
            },
        )

        dispatched_host_ids = _step_analyze_multi_host(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            case_id=manifest.case_id,
            manifest=manifest,
            pending_host_ids=pending_host_ids,
            pending_focus=pending_focus,
            dispatch_fn=dispatch_analyst_fn,
            on_progress=on_progress,
            parallel=parallel,
            parallel_max_workers=parallel_max_workers,
        )

        new_correlations = _step_correlate_multi_host(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            case_id=manifest.case_id,
            manifest=manifest,
            dispatch_fn=dispatch_validator_fn,
            on_progress=on_progress,
        )

        _step_promote(
            state,
            case_dir=case_dir,
            case_cwd=case_cwd,
            iterations_so_far=iteration_number - 1,
            update_fn=update_finding_fn,
        )
        rule_counts: dict[str, int] = {}
        for prom in state.promotions:
            rule_counts[prom.promotion_rule] = rule_counts.get(prom.promotion_rule, 0) + 1
        _emit(
            on_progress,
            "promote",
            {
                "rule_counts": rule_counts,
                "applied": sum(1 for p in state.promotions if p.applied),
                "total": len(state.promotions),
            },
        )

        cumulative_tokens += state.tokens_uncached
        # PLAN reuses the single-evidence helper but with the
        # caller-provided budget.
        R_a = len(_unresolved_set(case_dir)) == 0
        cur_disputed = _disputed_set(case_dir)
        R_b = (
            prior_disputed is not None
            and prior_disputed == cur_disputed
            and len(cur_disputed) > 0
            and iteration_number > 1
        )
        R_c = cumulative_tokens >= token_budget
        max_reached = iteration_number >= max_iterations
        decision = "terminate" if (R_a or R_b or R_c or max_reached) else "continue"
        termination = TerminationCheck(
            R_a_zero_unresolved=R_a,
            R_b_disputed_set_unchanged=bool(R_b),
            R_c_token_budget_exceeded=R_c,
            max_iterations_reached=max_reached,
            decision=decision,
        )

        next_host_ids, next_focus, consumed = _next_iter_multi_host_plan(new_correlations, manifest)
        state.followup_consumed = consumed
        _emit(
            on_progress,
            "plan",
            {
                "decision": termination.decision,
                "next_host_ids": next_host_ids,
                "followups_consumed": len(consumed),
                "next_focus_analysts": sorted(next_focus.keys()) if next_focus else [],
            },
        )

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
            manifest_summary=_manifest_summary_for_log(manifest, dispatched_host_ids),
        )
        entry = append_iteration_entry(case_dir, payload)
        iteration_records.append(entry)

        _emit(
            on_progress,
            "iteration_done",
            {
                "iteration": iteration_number,
                "tokens_uncached": state.tokens_uncached,
                "cumulative_tokens_uncached": cumulative_tokens,
                "findings_added": len(state.analyst_finding_ids_added),
                "correlations_added": len(state.validator_correlation_ids_added),
                "promotions_applied": sum(1 for p in state.promotions if p.applied),
            },
        )

        if termination.decision == "terminate":
            if termination.R_a_zero_unresolved:
                termination_reason = "R_a_zero_unresolved"
            elif termination.R_b_disputed_set_unchanged:
                termination_reason = "R_b_disputed_set_unchanged"
            elif termination.R_c_token_budget_exceeded:
                termination_reason = "R_c_token_budget_exceeded"
            else:
                termination_reason = "max_iterations_reached"
            _emit(on_progress, "terminate", {"reason": termination_reason})
            break

        prior_disputed = _disputed_set(case_dir)
        pending_host_ids = next_host_ids if next_host_ids else None
        pending_focus = next_focus if next_focus else None

    return LoopOutcome(
        iterations=iteration_records,
        termination_reason=termination_reason,
        cumulative_tokens_uncached=cumulative_tokens,
    )


__all__ = [
    "ARTIFACT_TO_ANALYSTS",
    "LoopOutcome",
    "MANIFEST_TYPE_TO_ANALYSTS",
    "ProgressCallback",
    "TOKEN_BUDGET_MULTI_BASE",
    "TOKEN_BUDGET_PER_HOST",
    "TOKEN_BUDGET_UNCACHED",
    "run_loop",
    "run_loop_multi_host",
]
