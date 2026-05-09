"""Tests for orchestrator.loop.run_loop().

The loop is exercised end-to-end with mocked subagent dispatch and
the real update_finding implementation (called directly, bypassing
the MCP subprocess layer for unit-test speed). The mocks write
DraftFinding / Correlation entries directly to the on-disk chains
the way the real subagents would, so the loop's read-after-dispatch
delta detection is genuine.

Coverage:
  - First iteration dispatches both analysts for memory_image
  - Iteration 2 dispatches only analysts named in prior
    request_followup, with focus_context
  - Termination on R_a (zero unresolved)
  - Termination on R_c (token budget exceeded)
  - Hard stop at max_iterations
  - iterations.jsonl chain is written correctly across iterations
  - PROMOTE writes update_finding entries on R3/R4
  - PROMOTE skips R6 (no-change)
  - PROMOTE skips already-CONFIRMED findings
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from orchestrator.dispatch import DispatchResult
from orchestrator.iterations_log import read_iterations
from orchestrator.loop import (
    TOKEN_BUDGET_UNCACHED,
    LoopOutcome,
    run_loop,
)
from server.audit import append_audit_entry
from server.findings_log import append_finding_entry, read_finding_state
from server.correlations_log import append_correlation_entry
from server.schemas import (
    CorroboratesCorrelation,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
    RequestFollowupCorrelation,
)
from server.tools.findings import update_finding as _real_update_finding


_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
EVID = "550e8400-e29b-41d4-a716-446655440000"
SHA = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"


def _seed_case(tmp_path: Path) -> Path:
    """Build a tmp case dir with CASE.yaml + a registered memory
    evidence record + an audit chain seeded with one vol_pslist
    line (so EvidenceRefs at audit_line=1 validate)."""
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()

    fake = evidence_dir / "Rocba-Memory.raw"
    fake.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=EVID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(fake),
        sha256=SHA,
        size_bytes=1024,
        artifact_class="memory_image",
        registered_at=_NOW,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": "case-rocba",
        "registered_at": _NOW.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))

    class _Stub(BaseModel):
        ok: str = "ok"

    append_audit_entry(
        case_dir=case_dir,
        tool_name="vol_pslist",
        evidence_id=EVID,
        input_args={"evidence_id": EVID},
        output=_Stub(),
    )
    return case_dir


def _make_draft(analyst: str, title_seed: str) -> DraftFinding:
    return DraftFinding(
        finding_id=str(uuid.uuid4()),
        evidence_id=EVID,
        analyst=analyst,
        state="DRAFT",
        category=("process_hidden" if analyst == "process_analyst" else "network_anomaly"),
        severity="medium",
        confidence="MEDIUM",
        title=f"Synthetic finding {title_seed}",
        description=(
            f"A synthetic DraftFinding planted by the loop test for "
            f"analyst {analyst}. The mock dispatch writes this entry "
            f"directly to findings.jsonl as if the analyst had run."
        ),
        evidence_refs=[EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="seed")],
        created_at=_NOW,
        tool_invocations=["vol_pslist:1"],
    )


class _MockDispatcher:
    """Records each dispatch + plants synthetic on-disk side effects.

    Per analyst, the mock writes one DraftFinding to findings.jsonl
    when called. The validator mock writes one CorroboratesCorrelation
    targeting one of the existing DRAFT findings.

    A separate `audit_fn` mocks the audit-chain side effect (each
    successful dispatch ends with a `record_finding` audit entry).
    """

    def __init__(
        self,
        case_dir: Path,
        *,
        analyst_findings: dict[str, list[DraftFinding]] | None = None,
        validator_correlations_per_iter: list[list] | None = None,
        token_per_dispatch: int = 10000,
    ):
        self.case_dir = case_dir
        self._analyst_findings = analyst_findings or {}
        self._validator_corrs = list(validator_correlations_per_iter or [])
        self._token = token_per_dispatch
        self.analyst_calls: list[dict[str, Any]] = []
        self.validator_calls: list[dict[str, Any]] = []
        self._iter_correlations_idx = 0

    def dispatch_analyst(
        self,
        *,
        agent: str,
        evidence_id: str,
        case_id: str,
        iteration_number: int,
        cwd: Path,
        focus_context: dict[str, Any] | None = None,
    ) -> DispatchResult:
        self.analyst_calls.append(
            {
                "agent": agent,
                "iteration_number": iteration_number,
                "focus_context": focus_context,
            }
        )
        for finding in self._analyst_findings.get(agent, []):
            append_finding_entry(self.case_dir, finding)

            class _Stub(BaseModel):
                ok: str = "ok"

            append_audit_entry(
                case_dir=self.case_dir,
                tool_name="record_finding",
                evidence_id=evidence_id,
                input_args={"agent": agent},
                output=_Stub(),
            )
        return DispatchResult(
            agent=agent,
            session_id=str(uuid.uuid4()),
            stop_reason="end_turn",
            num_turns=1,
            duration_ms=1000,
            duration_api_ms=500,
            total_cost_usd=0.10,
            input_tokens=1000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=2000,
            output_tokens=self._token - 1000,
            tokens_uncached=self._token,
            final_text="",
        )

    def dispatch_validator(
        self,
        *,
        evidence_id: str,
        case_id: str,
        iteration_number: int,
        findings_summary: list[dict[str, Any]],
        cwd: Path,
    ) -> DispatchResult:
        self.validator_calls.append(
            {
                "iteration_number": iteration_number,
                "findings_summary": findings_summary,
            }
        )
        if self._iter_correlations_idx < len(self._validator_corrs):
            for corr in self._validator_corrs[self._iter_correlations_idx]:
                append_correlation_entry(self.case_dir, corr)

                class _Stub(BaseModel):
                    ok: str = "ok"

                append_audit_entry(
                    case_dir=self.case_dir,
                    tool_name="record_correlation",
                    evidence_id=evidence_id,
                    input_args={"iter": iteration_number},
                    output=_Stub(),
                )
            self._iter_correlations_idx += 1
        return DispatchResult(
            agent="validator",
            session_id=str(uuid.uuid4()),
            stop_reason="end_turn",
            num_turns=1,
            duration_ms=1000,
            duration_api_ms=500,
            total_cost_usd=0.05,
            input_tokens=500,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=1000,
            output_tokens=self._token - 500,
            tokens_uncached=self._token,
            final_text="",
        )


def _real_update_via_kwargs(case_cwd: Path, args: dict[str, Any]) -> dict[str, Any]:
    """Adapter: the loop calls update_finding_fn(case_cwd, args). The
    real tool takes a case_dir kwarg. Both case-data dirs sit at the
    same path under tmp_path."""
    result = _real_update_finding(
        case_dir=str(case_cwd / "case-data"),
        **args,
    )
    return result.model_dump(mode="json")


def _make_corroborates(target_fid: str, strength: str) -> CorroboratesCorrelation:
    return CorroboratesCorrelation(
        correlation_id=str(uuid.uuid4()),
        case_id="case-rocba",
        iteration_number=1,
        created_at=_NOW,
        audit_line=1,
        evidence_refs=[EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="seed")],
        hypothesis=(
            "Synthetic corroborates correlation planted by the loop "
            "test fixture. Drives R3/R4 promotion in PROMOTE step."
        ),
        target_finding_ids=[target_fid],
        strength=strength,
    )


def _make_request_followup(
    target_analyst: str, related_fid: str, focus: dict[str, Any]
) -> RequestFollowupCorrelation:
    return RequestFollowupCorrelation(
        correlation_id=str(uuid.uuid4()),
        case_id="case-rocba",
        iteration_number=1,
        created_at=_NOW,
        audit_line=1,
        evidence_refs=[EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="seed")],
        hypothesis=(
            "Synthetic request_followup correlation that asks the "
            "named analyst to re-run with the given focus context."
        ),
        target_analyst=target_analyst,
        related_finding_ids=[related_fid],
        focus_context=focus,
        rationale="Synthetic followup rationale for loop tests.",
    )


# ----------------------------------------------------------------------
# First iteration: both analysts dispatched
# ----------------------------------------------------------------------


class TestFirstIterationDispatch:
    def test_both_analysts_dispatched_for_memory_image(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        net_finding = _make_draft("network_analyst", "n1")
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={
                "process_analyst": [proc_finding],
                "network_analyst": [net_finding],
            },
            validator_correlations_per_iter=[
                [_make_corroborates(proc_finding.finding_id, "strong")]
            ],
        )
        outcome = run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert isinstance(outcome, LoopOutcome)
        agents_first = [c["agent"] for c in mock.analyst_calls if c["iteration_number"] == 1]
        assert sorted(agents_first) == ["network_analyst", "process_analyst"]


# ----------------------------------------------------------------------
# Iteration 2: only followup-targeted analyst, with focus_context
# ----------------------------------------------------------------------


class TestSecondIterationFollowup:
    def test_only_followup_target_dispatched_in_iter2(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        net_finding = _make_draft("network_analyst", "n1")
        followup_corr = _make_request_followup(
            target_analyst="process_analyst",
            related_fid=proc_finding.finding_id,
            focus={"pids": [7900]},
        )
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={
                "process_analyst": [proc_finding],
                "network_analyst": [net_finding],
            },
            validator_correlations_per_iter=[
                [followup_corr],  # iter 1 emits followup
                [],  # iter 2 emits nothing
            ],
        )
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=3,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        agents_iter2 = [c for c in mock.analyst_calls if c["iteration_number"] == 2]
        assert len(agents_iter2) == 1
        assert agents_iter2[0]["agent"] == "process_analyst"
        assert agents_iter2[0]["focus_context"] == {"pids": [7900]}


# ----------------------------------------------------------------------
# Termination conditions
# ----------------------------------------------------------------------


class TestTerminationRa:
    def test_zero_unresolved_terminates_loop(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        # Validator strongly corroborates → R3 promotes to CONFIRMED.
        # After PROMOTE the unresolved set is empty → R_a fires.
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={"process_analyst": [proc_finding]},
            validator_correlations_per_iter=[
                [_make_corroborates(proc_finding.finding_id, "strong")]
            ],
        )
        outcome = run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=5,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert outcome.termination_reason == "R_a_zero_unresolved"
        assert len(outcome.iterations) == 1


class TestTerminationRc:
    def test_token_budget_terminates_loop(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        # 250K per dispatch × 3 dispatches/iter (process+network+
        # validator) = 750K — exceeds 500K budget after iter 1.
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={
                "process_analyst": [proc_finding],
                "network_analyst": [],
            },
            validator_correlations_per_iter=[[]],  # no correlations,
            # nothing promotes
            token_per_dispatch=250_000,
        )
        outcome = run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=5,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert outcome.termination_reason == "R_c_token_budget_exceeded"
        assert outcome.cumulative_tokens_uncached >= TOKEN_BUDGET_UNCACHED


class TestTerminationMaxIterations:
    def test_max_iterations_hard_stop(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        # No findings → no validator dispatch → no termination R_a/R_b/R_c.
        # After max_iterations we hard-stop with max_reached.
        # But the loop also has "no analysts pending" early exit when
        # there are no followups. Provide a single empty analyst path
        # that still produces no promotable state, and watch the
        # max-iter stop fire before R_a clears.
        proc_finding = _make_draft("process_analyst", "p1")
        # No correlations → nothing promotes → unresolved stays.
        # Iter 1 dispatches both analysts. Iter 2 has no pending
        # analysts (no followup), so the loop exits via
        # "no_followup_pending" — the max-iter path needs continuous
        # followups. Use a chain of followup correlations to stretch
        # the loop, then verify max-iter cap.
        followup = _make_request_followup(
            target_analyst="process_analyst",
            related_fid=proc_finding.finding_id,
            focus={"pids": [7900]},
        )
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={
                "process_analyst": [proc_finding],
            },
            validator_correlations_per_iter=[
                [followup],
                [followup],
                [followup],
            ],
        )
        outcome = run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert outcome.termination_reason == "max_iterations_reached"
        assert len(outcome.iterations) == 2


# ----------------------------------------------------------------------
# iterations.jsonl chain integrity
# ----------------------------------------------------------------------


class TestIterationsChainOnDisk:
    def test_chain_written_per_iteration(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        followup = _make_request_followup(
            target_analyst="process_analyst",
            related_fid=proc_finding.finding_id,
            focus={"pids": [7900]},
        )
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={"process_analyst": [proc_finding]},
            validator_correlations_per_iter=[[followup], []],
        )
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=3,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        entries = read_iterations(case_dir)
        assert len(entries) >= 2
        # Chain links forward: entry N+1's prev_iteration_hash ==
        # entry N's this_iteration_hash.
        for prev, curr in zip(entries, entries[1:]):
            assert curr.prev_iteration_hash == prev.this_iteration_hash


# ----------------------------------------------------------------------
# PROMOTE behavior
# ----------------------------------------------------------------------


class TestPromoteWritesUpdates:
    def test_r3_writes_update_finding(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={"process_analyst": [proc_finding]},
            validator_correlations_per_iter=[
                [_make_corroborates(proc_finding.finding_id, "strong")]
            ],
        )
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        st = read_finding_state(case_dir, proc_finding.finding_id)
        assert st == ("CONFIRMED", "HIGH")


class TestPromoteSkipsR6:
    def test_no_correlations_no_update_written(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={"process_analyst": [proc_finding]},
            validator_correlations_per_iter=[[]],  # no correlations
        )
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=1,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        # R6: no update written; finding stays in DRAFT/MEDIUM.
        st = read_finding_state(case_dir, proc_finding.finding_id)
        assert st == ("DRAFT", "MEDIUM")


class TestR5PersistsToChain:
    """Integration-shaped pin on the 2026-05-07 R5 persistence hotfix.

    Three DRAFT findings with no correlations on any of them. The
    rule engine returns R5 ("quiet stabilization → CONFIRMED at
    F.confidence") once `iterations_so_far >= 2`. Before the
    hotfix, R5 decisions were recorded in iterations.jsonl with
    `applied=False` and never reached findings.jsonl, leaving
    R5-eligible findings stuck DRAFT forever and making R_a
    unreachable on any chain that contained them. The hotfix wires
    R5 through `update_finding` (with empty
    `driving_correlation_ids`, permitted iff `promotion_rule ==
    "R5"`) so the chain reflects R5 promotions and `R_a` clears.

    Test simulates two PROMOTE-step invocations directly (bypassing
    run_loop's dispatch flow):
      - 1st invocation: `iterations_so_far=1` — R5 doesn't fire
        (rule requires >=2). All three remain DRAFT.
      - 2nd invocation: `iterations_so_far=2` — R5 fires on each.
        All three become CONFIRMED in findings.jsonl.

    Then `_step_plan` is invoked to confirm `R_a_zero_unresolved`
    fires on the post-R5 state.
    """

    def test_three_silent_drafts_reach_confirmed_via_r5(self, tmp_path: Path):
        from orchestrator.loop import (
            _IterationState,
            _step_plan,
            _step_promote,
            _unresolved_set,
        )

        case_dir = _seed_case(tmp_path)

        # Plant three DRAFTs — different analysts, different titles,
        # all evidence_id=EVID. No correlations are written.
        d1 = _make_draft("process_analyst", "silent-1")
        d2 = _make_draft("process_analyst", "silent-2")
        d3 = _make_draft("network_analyst", "silent-3")
        for d in (d1, d2, d3):
            append_finding_entry(case_dir, d)

        # Sanity: all three are DRAFT/MEDIUM in the chain.
        for fid in (d1.finding_id, d2.finding_id, d3.finding_id):
            assert read_finding_state(case_dir, fid) == ("DRAFT", "MEDIUM")
        assert len(_unresolved_set(case_dir)) == 3

        # === PROMOTE call 1: iterations_so_far=1 — R5 not yet
        # eligible. All three should be R6 (no chain growth, still
        # DRAFT).
        state1 = _IterationState(iteration_number=2, started_at=_NOW)
        _step_promote(
            state1,
            case_dir=case_dir,
            case_cwd=tmp_path,
            iterations_so_far=1,
            update_fn=_real_update_via_kwargs,
        )
        for fid in (d1.finding_id, d2.finding_id, d3.finding_id):
            assert read_finding_state(case_dir, fid) == ("DRAFT", "MEDIUM")
        assert all(p.promotion_rule == "R6" for p in state1.promotions)
        assert len(_unresolved_set(case_dir)) == 3

        # === PROMOTE call 2: iterations_so_far=2 — R5 fires.
        # Three update_finding writes append; chain reflects
        # CONFIRMED. driving_correlation_ids is empty (R5's defining
        # precondition), permitted by the model_validator.
        state2 = _IterationState(iteration_number=3, started_at=_NOW)
        _step_promote(
            state2,
            case_dir=case_dir,
            case_cwd=tmp_path,
            iterations_so_far=2,
            update_fn=_real_update_via_kwargs,
        )

        # All three R5'd. `applied=True` because the chain write
        # actually happened (the pre-hotfix bug had applied=False).
        r5_promotions = [p for p in state2.promotions if p.promotion_rule == "R5"]
        assert len(r5_promotions) == 3
        assert all(p.applied for p in r5_promotions), (
            "R5 promotions must reach the chain (post-hotfix). "
            "applied=False indicates the in-memory-only workaround "
            "regressed; see docs/decisions-log.md 2026-05-07 R5 entry."
        )
        assert all(p.update_id is not None for p in r5_promotions)
        assert all(p.driving_correlation_ids == [] for p in r5_promotions)

        # Chain truth: all three findings are CONFIRMED.
        for fid in (d1.finding_id, d2.finding_id, d3.finding_id):
            assert read_finding_state(case_dir, fid) == ("CONFIRMED", "MEDIUM")
        assert len(_unresolved_set(case_dir)) == 0

        # R_a fires on _step_plan (the load-bearing assertion: the
        # bug's symptom was max_iterations_reached firing instead of
        # R_a even when R5 logically resolved every finding).
        termination = _step_plan(
            state2,
            case_dir=case_dir,
            cumulative_tokens=0,
            prior_disputed=None,
            iteration_number=3,
            max_iterations=10,
        )
        assert termination.R_a_zero_unresolved is True
        assert termination.decision == "terminate"


class TestPromoteSkipsConfirmed:
    def test_already_confirmed_finding_skipped(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        proc_finding = _make_draft("process_analyst", "p1")
        # Iter 1: corroborates strong → CONFIRMED/HIGH.
        # Iter 2 followup re-runs analyst but finding is now CONFIRMED;
        # PROMOTE should skip. We assert no second update_finding
        # write occurs.
        followup = _make_request_followup(
            target_analyst="process_analyst",
            related_fid=proc_finding.finding_id,
            focus={"pids": [7900]},
        )
        mock = _MockDispatcher(
            case_dir,
            analyst_findings={"process_analyst": [proc_finding]},
            validator_correlations_per_iter=[
                [
                    _make_corroborates(proc_finding.finding_id, "strong"),
                    followup,
                ],
                [_make_corroborates(proc_finding.finding_id, "moderate")],
            ],
        )
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=3,
            dispatch_analyst_fn=mock.dispatch_analyst,
            dispatch_validator_fn=mock.dispatch_validator,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        st = read_finding_state(case_dir, proc_finding.finding_id)
        # Stays at CONFIRMED/HIGH despite iter-2 corroborates moderate.
        assert st == ("CONFIRMED", "HIGH")
        # The recorded promotions list across iterations: only iter 1
        # has an applied=True entry for this finding.
        entries = read_iterations(case_dir)
        applied_count = 0
        for e in entries:
            for p in e.iteration.promotions_made:
                if p.finding_id == proc_finding.finding_id and p.applied:
                    applied_count += 1
        assert applied_count == 1
