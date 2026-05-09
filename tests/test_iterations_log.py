"""Tests for the iterations.jsonl hash-chained writer.

Mirrors test_correlations_log.py / test_findings_log.py: genesis
append, chain linkage across two appends, canonical hash
recomputation, malformed-line skip in the reader. The fourth chain
in the substrate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.iterations_log import (
    IterationChainEntry,
    IterationPayload,
    RecordedPromotion,
    TerminationCheck,
    append_iteration_entry,
    read_iterations,
)


_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
_NOW_LATER = datetime(2026, 5, 7, 12, 5, 0, tzinfo=timezone.utc)


def _termination_continue() -> TerminationCheck:
    return TerminationCheck(
        R_a_zero_unresolved=False,
        R_b_disputed_set_unchanged=False,
        R_c_token_budget_exceeded=False,
        decision="continue",
    )


def _termination_terminate(R_a: bool = True) -> TerminationCheck:
    return TerminationCheck(
        R_a_zero_unresolved=R_a,
        R_b_disputed_set_unchanged=False,
        R_c_token_budget_exceeded=False,
        decision="terminate",
    )


def _payload(
    iteration_number: int,
    termination: TerminationCheck,
    promotions: list[RecordedPromotion] | None = None,
) -> IterationPayload:
    return IterationPayload(
        iteration_number=iteration_number,
        started_at=_NOW,
        completed_at=_NOW_LATER,
        analysts_dispatched=["process_analyst", "network_analyst"],
        analyst_findings_added=[],
        validator_correlations_added=[],
        promotions_made=promotions or [],
        followup_requests_consumed=[],
        tokens_used_uncached=12000,
        cumulative_tokens_uncached=12000,
        termination_check=termination,
    )


class TestGenesisAppend:
    def test_writes_first_line(self, tmp_path: Path):
        entry = append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        assert entry.line_number == 1
        assert entry.prev_iteration_hash == "0" * 64
        assert len(entry.this_iteration_hash) == 64

    def test_creates_file_on_disk(self, tmp_path: Path):
        append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        path = tmp_path / "iterations.jsonl"
        assert path.exists()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        row = json.loads(lines[0])
        assert row["line_number"] == 1
        assert row["iteration"]["iteration_number"] == 1


class TestChainLinkage:
    def test_two_appends_chain(self, tmp_path: Path):
        first = append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        second = append_iteration_entry(tmp_path, _payload(2, _termination_terminate()))
        assert second.line_number == 2
        assert second.prev_iteration_hash == first.this_iteration_hash
        assert second.this_iteration_hash != first.this_iteration_hash

    def test_three_appends_full_chain(self, tmp_path: Path):
        a = append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        b = append_iteration_entry(tmp_path, _payload(2, _termination_continue()))
        c = append_iteration_entry(tmp_path, _payload(3, _termination_terminate()))
        assert b.prev_iteration_hash == a.this_iteration_hash
        assert c.prev_iteration_hash == b.this_iteration_hash


class TestHashComputable:
    def test_recomputed_hash_matches_stored(self, tmp_path: Path):
        entry = append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        recomputed = IterationChainEntry.compute_this_iteration_hash(
            line_number=entry.line_number,
            timestamp=entry.timestamp,
            iteration=entry.iteration.model_dump(mode="json"),
            prev_iteration_hash=entry.prev_iteration_hash,
        )
        assert recomputed == entry.this_iteration_hash


class TestReadIterations:
    def test_empty_returns_empty_list(self, tmp_path: Path):
        assert read_iterations(tmp_path) == []

    def test_reads_back_chain(self, tmp_path: Path):
        append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        append_iteration_entry(tmp_path, _payload(2, _termination_terminate()))
        entries = read_iterations(tmp_path)
        assert len(entries) == 2
        assert entries[0].iteration.iteration_number == 1
        assert entries[1].iteration.iteration_number == 2
        assert entries[1].iteration.termination_check.decision == "terminate"

    def test_promotions_round_trip(self, tmp_path: Path):
        prom = RecordedPromotion(
            finding_id="11111111-1111-4111-8111-111111111111",
            new_state="CONFIRMED",
            new_confidence="HIGH",
            promotion_rule="R3",
            driving_correlation_ids=["22222222-2222-4222-8222-222222222222"],
            applied=True,
            update_id="33333333-3333-4333-8333-333333333333",
        )
        append_iteration_entry(
            tmp_path,
            _payload(1, _termination_terminate(), promotions=[prom]),
        )
        entries = read_iterations(tmp_path)
        assert len(entries[0].iteration.promotions_made) == 1
        rt = entries[0].iteration.promotions_made[0]
        assert rt.promotion_rule == "R3"
        assert rt.applied is True
        assert rt.update_id == "33333333-3333-4333-8333-333333333333"


class TestDistinctHashFieldNames:
    """A line read out of context must not be silently misread as
    one of the other three chain types. The hash field names are
    distinct on purpose."""

    def test_field_names_are_iteration_specific(self, tmp_path: Path):
        append_iteration_entry(tmp_path, _payload(1, _termination_continue()))
        path = tmp_path / "iterations.jsonl"
        row = json.loads(path.read_text().strip())
        assert "prev_iteration_hash" in row
        assert "this_iteration_hash" in row
        assert "prev_line_hash" not in row
        assert "prev_finding_hash" not in row
        assert "prev_correlation_hash" not in row
