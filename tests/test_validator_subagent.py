"""Tests for the validator → orchestrator handoff.

The validator subagent's only output is correlations on
correlations.jsonl. The orchestrator's PROMOTE step reads those
correlations and applies R1-R6. This file simulates the validator
with a stub that writes canned correlations directly to disk, then
asserts the orchestrator promotes findings as the rule engine
expects for each correlation pattern.

These tests overlap with test_promotion.py (which exercises
`promote()` in pure-function isolation) and test_loop.py (which
exercises the full 5-step loop). The angle here is specifically the
validator-output → orchestrator-PROMOTE pipeline: for each of the
five correlation types, does an orchestrator iteration end with the
expected finding state?
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from orchestrator.dispatch import DispatchResult
from orchestrator.loop import run_loop
from server.audit import append_audit_entry
from server.findings_log import append_finding_entry, read_finding_state
from server.correlations_log import append_correlation_entry
from server.schemas import (
    ContradictsCorrelation,
    CorroboratesCorrelation,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)
from server.tools.findings import update_finding as _real_update_finding


_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
EVID = "550e8400-e29b-41d4-a716-446655440000"
SHA = "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"


def _seed_case(tmp_path: Path) -> Path:
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


def _draft(confidence: str = "MEDIUM") -> DraftFinding:
    return DraftFinding(
        finding_id=str(uuid.uuid4()),
        evidence_id=EVID,
        analyst="process_analyst",
        state="DRAFT",
        category="process_hidden",
        severity="medium",
        confidence=confidence,
        title="Synthetic finding for validator handoff tests",
        description=(
            "A synthetic DraftFinding the validator-handoff tests "
            "construct in-memory. Confidence is parameterized by the "
            "test scenario."
        ),
        evidence_refs=[EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="seed")],
        created_at=_NOW,
        tool_invocations=["vol_pslist:1"],
    )


def _ok_dispatch_result(agent: str, tokens: int = 5000) -> DispatchResult:
    return DispatchResult(
        agent=agent,
        session_id=str(uuid.uuid4()),
        stop_reason="end_turn",
        num_turns=1,
        duration_ms=1000,
        duration_api_ms=500,
        total_cost_usd=0.05,
        input_tokens=tokens // 5,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=tokens,
        output_tokens=tokens - tokens // 5,
        tokens_uncached=tokens,
        final_text="",
    )


def _real_update_via_kwargs(
    case_dir: Path, case_cwd: Path, args: dict[str, Any]
) -> dict[str, Any]:
    del case_cwd  # signature matches production; case_dir is what we need
    result = _real_update_finding(
        case_dir=str(case_dir),
        **args,
    )
    return result.model_dump(mode="json")


def _make_validator_stub(case_dir: Path, correlations_per_iter: list[list]):
    """Returns a callable matching dispatch_validator that writes the
    given correlations to correlations.jsonl + audit chain."""

    class _Stub(BaseModel):
        ok: str = "ok"

    state = {"idx": 0}

    def stub(
        *,
        evidence_id: str,
        case_id: str,
        iteration_number: int,
        findings_summary: list[dict[str, Any]],
        cwd: Path,
    ) -> DispatchResult:
        if state["idx"] < len(correlations_per_iter):
            for corr in correlations_per_iter[state["idx"]]:
                append_correlation_entry(case_dir, corr)
                append_audit_entry(
                    case_dir=case_dir,
                    tool_name="record_correlation",
                    evidence_id=evidence_id,
                    input_args={"iter": iteration_number},
                    output=_Stub(),
                )
            state["idx"] += 1
        return _ok_dispatch_result("validator")

    return stub


def _make_analyst_stub(case_dir: Path, drafts_per_analyst: dict[str, list[DraftFinding]]):
    """Returns a callable matching dispatch_analyst that writes the
    canned DraftFinding entries on the first call to each analyst.
    Subsequent calls (iter 2+) write nothing — simulating the analyst
    re-running and finding nothing new."""

    class _Stub(BaseModel):
        ok: str = "ok"

    seen: set[str] = set()

    def stub(
        *,
        agent: str,
        evidence_id: str,
        case_id: str,
        iteration_number: int,
        cwd: Path,
        focus_context: dict[str, Any] | None = None,
    ) -> DispatchResult:
        if agent not in seen:
            for f in drafts_per_analyst.get(agent, []):
                append_finding_entry(case_dir, f)
                append_audit_entry(
                    case_dir=case_dir,
                    tool_name="record_finding",
                    evidence_id=evidence_id,
                    input_args={"agent": agent},
                    output=_Stub(),
                )
            seen.add(agent)
        return _ok_dispatch_result(agent)

    return stub


def _refs() -> list[EvidenceRef]:
    return [EvidenceRef(source_tool="vol_pslist", audit_line=1, detail="seed")]


# ----------------------------------------------------------------------
# corroborates strong → R3 → CONFIRMED/HIGH
# ----------------------------------------------------------------------


class TestCorroboratesStrong:
    def test_strong_promotes_to_high(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        finding = _draft("MEDIUM")
        analyst_stub = _make_analyst_stub(
            case_dir, {"process_analyst": [finding], "network_analyst": []}
        )
        corr = CorroboratesCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic strong corroboration; the orchestrator "
                "should fire R3 and confirm at HIGH."
            ),
            target_finding_ids=[finding.finding_id],
            strength="strong",
        )
        validator_stub = _make_validator_stub(case_dir, [[corr]])
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert read_finding_state(case_dir, finding.finding_id) == (
            "CONFIRMED",
            "HIGH",
        )


# ----------------------------------------------------------------------
# corroborates moderate → R4 → CONFIRMED/MEDIUM (from MEDIUM)
# ----------------------------------------------------------------------


class TestCorroboratesModerate:
    def test_moderate_promotes_to_medium_minimum(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        finding = _draft("LOW")
        analyst_stub = _make_analyst_stub(
            case_dir, {"process_analyst": [finding], "network_analyst": []}
        )
        corr = CorroboratesCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic moderate corroboration; R4 floors confidence "
                "at MEDIUM regardless of starting LOW."
            ),
            target_finding_ids=[finding.finding_id],
            strength="moderate",
        )
        validator_stub = _make_validator_stub(case_dir, [[corr]])
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert read_finding_state(case_dir, finding.finding_id) == (
            "CONFIRMED",
            "MEDIUM",
        )


# ----------------------------------------------------------------------
# contradicts material → R1 → DRAFT/DISPUTED
# ----------------------------------------------------------------------


class TestContradictsMaterial:
    def test_material_disputes(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        f1 = _draft("MEDIUM")
        f2 = _draft("MEDIUM")
        analyst_stub = _make_analyst_stub(
            case_dir, {"process_analyst": [f1, f2], "network_analyst": []}
        )
        corr = ContradictsCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic material contradiction between two findings "
                "the orchestrator should disposition via R1."
            ),
            finding_a_id=f1.finding_id,
            finding_b_id=f2.finding_id,
            severity="material",
            resolvable_by_followup=False,
        )
        validator_stub = _make_validator_stub(case_dir, [[corr]])
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert read_finding_state(case_dir, f1.finding_id) == (
            "DRAFT",
            "DISPUTED",
        )
        assert read_finding_state(case_dir, f2.finding_id) == (
            "DRAFT",
            "DISPUTED",
        )


# ----------------------------------------------------------------------
# weakens on HIGH → R2 → CONFIRMED/MEDIUM
# ----------------------------------------------------------------------


class TestWeakensOnHigh:
    def test_high_demoted_to_medium(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        finding = _draft("HIGH")
        analyst_stub = _make_analyst_stub(
            case_dir, {"process_analyst": [finding], "network_analyst": []}
        )
        weakens = WeakensCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic weakens correlation; on a HIGH-confidence "
                "finding R2 demotes to CONFIRMED/MEDIUM."
            ),
            target_finding_id=finding.finding_id,
        )
        validator_stub = _make_validator_stub(case_dir, [[weakens]])
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        assert read_finding_state(case_dir, finding.finding_id) == (
            "CONFIRMED",
            "MEDIUM",
        )


# ----------------------------------------------------------------------
# request_followup → orchestrator dispatches named analyst with focus
# ----------------------------------------------------------------------


class TestRequestFollowupConsumed:
    def test_iter2_dispatches_with_focus(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        finding = _draft("MEDIUM")

        captured_iter2_calls: list[dict[str, Any]] = []

        seen: set[str] = set()

        class _Stub(BaseModel):
            ok: str = "ok"

        def analyst_stub(
            *,
            agent: str,
            evidence_id: str,
            case_id: str,
            iteration_number: int,
            cwd: Path,
            focus_context: dict[str, Any] | None = None,
        ) -> DispatchResult:
            if iteration_number == 2:
                captured_iter2_calls.append({"agent": agent, "focus_context": focus_context})
            if agent == "process_analyst" and "process_analyst" not in seen:
                append_finding_entry(case_dir, finding)
                append_audit_entry(
                    case_dir=case_dir,
                    tool_name="record_finding",
                    evidence_id=evidence_id,
                    input_args={"agent": agent},
                    output=_Stub(),
                )
                seen.add(agent)
            return _ok_dispatch_result(agent)

        followup = RequestFollowupCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic followup that asks process_analyst to "
                "re-run with focused attention on PID 7900."
            ),
            target_analyst="process_analyst",
            related_finding_ids=[finding.finding_id],
            focus_context={"pids": [7900]},
            rationale="Synthetic followup rationale.",
        )
        validator_stub = _make_validator_stub(case_dir, [[followup], []])

        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=3,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )

        assert len(captured_iter2_calls) == 1
        call = captured_iter2_calls[0]
        assert call["agent"] == "process_analyst"
        assert call["focus_context"] == {"pids": [7900]}


# ----------------------------------------------------------------------
# strengthens alone → R6 → no promotion
# ----------------------------------------------------------------------


class TestStrengthensAlone:
    def test_no_promotion_no_state_change(self, tmp_path: Path):
        case_dir = _seed_case(tmp_path)
        finding = _draft("MEDIUM")
        analyst_stub = _make_analyst_stub(
            case_dir, {"process_analyst": [finding], "network_analyst": []}
        )
        s = StrengthensCorrelation(
            correlation_id=str(uuid.uuid4()),
            case_id="case-rocba",
            iteration_number=1,
            created_at=_NOW,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Synthetic strengthens — supports the finding but is "
                "not a corroboration; orchestrator should not promote."
            ),
            target_finding_id=finding.finding_id,
        )
        validator_stub = _make_validator_stub(case_dir, [[s]])
        run_loop(
            case_dir=case_dir,
            evidence_id=EVID,
            max_iterations=2,
            dispatch_analyst_fn=analyst_stub,
            dispatch_validator_fn=validator_stub,
            update_finding_fn=_real_update_via_kwargs,
            case_cwd=tmp_path,
        )
        # Stays DRAFT/MEDIUM.
        assert read_finding_state(case_dir, finding.finding_id) == (
            "DRAFT",
            "MEDIUM",
        )
