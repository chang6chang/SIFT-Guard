"""Tests for the discriminated `findings.jsonl` payload union.

Validates that:

  - A legacy DraftFinding line written before `record_kind` existed
    parses back as `DraftFinding` (defaults to `record_kind="draft"`).
  - A new DraftFinding line with `record_kind="draft"` parses back
    as `DraftFinding` via the discriminator.
  - A new FindingUpdate line with `record_kind="update"` parses back
    as `FindingUpdate` via the discriminator.
  - Replaying the chain in line-order with last-write-wins on
    `finding_id` derives the current state of any finding.

Migration semantic per the substrate prompt: legacy lines lack
`record_kind`; the chain reader injects `"draft"` so the discriminated
union dispatches them correctly. New writes always populate the field.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from server.findings_log import read_finding_state
from server.schemas import (
    DraftFinding,
    FindingChainEntry,
    FindingUpdate,
)


_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
FID = "11111111-1111-4111-8111-111111111111"
EVID = "550e8400-e29b-41d4-a716-446655440000"


def _legacy_chain_line() -> dict:
    """Hand-rolled legacy line — no `record_kind` on the inner
    DraftFinding payload. Mirrors how the existing on-disk
    findings.jsonl line 1 looks."""
    return {
        "line_number": 1,
        "timestamp": _NOW.isoformat(),
        "finding": {
            "finding_id": FID,
            "evidence_id": EVID,
            "analyst": "process_analyst",
            "state": "DRAFT",
            "category": "process_hidden",
            "severity": "medium",
            "confidence": "MEDIUM",
            "title": "Legacy DraftFinding line ABCDEFGH",
            "description": (
                "A finding line written before the record_kind "
                "discriminator was added. The chain reader injects "
                "record_kind=draft so the discriminated union "
                "dispatches it correctly."
            ),
            "evidence_refs": [
                {
                    "source_tool": "vol_pslist",
                    "audit_line": 1,
                    "detail": "legacy line",
                }
            ],
            "hypothesis": None,
            "created_at": _NOW.isoformat(),
            "tool_invocations": ["vol_pslist:1"],
        },
        "prev_finding_hash": "0" * 64,
        "this_finding_hash": "1" * 64,
    }


def _new_draft_line() -> dict:
    """A DraftFinding line written under the new schema, with
    `record_kind="draft"` explicit."""
    legacy = _legacy_chain_line()
    legacy["finding"]["record_kind"] = "draft"
    legacy["line_number"] = 2
    legacy["prev_finding_hash"] = "1" * 64
    legacy["this_finding_hash"] = "2" * 64
    legacy["finding"]["finding_id"] = "22222222-2222-4222-8222-222222222222"
    legacy["finding"]["title"] = "New DraftFinding with record_kind"
    return legacy


def _update_line() -> dict:
    """A FindingUpdate line written by `update_finding` against FID."""
    return {
        "line_number": 3,
        "timestamp": _NOW.isoformat(),
        "finding": {
            "record_kind": "update",
            "update_id": "33333333-3333-4333-8333-333333333333",
            "finding_id": FID,
            "iteration_number": 1,
            "previous_state": "DRAFT",
            "new_state": "CONFIRMED",
            "previous_confidence": "MEDIUM",
            "new_confidence": "HIGH",
            "promotion_rule": "R3",
            "driving_correlation_ids": [
                "44444444-4444-4444-8444-444444444444"
            ],
            "created_at": _NOW.isoformat(),
            "audit_line": 5,
            "orchestrator_version": "orchestrator-v0.1",
        },
        "prev_finding_hash": "2" * 64,
        "this_finding_hash": "3" * 64,
    }


class TestLegacyLoad:
    def test_legacy_line_parses_as_draft(self):
        entry = FindingChainEntry.model_validate(_legacy_chain_line())
        assert isinstance(entry.finding, DraftFinding)
        assert entry.finding.record_kind == "draft"
        assert entry.finding.state == "DRAFT"

    def test_legacy_line_via_draft_finding_directly(self):
        # `DraftFinding.model_validate(row_without_record_kind)` works
        # because the field has a default value. The fixture-roundtrip
        # test in test_record_finding.py already covers this for the
        # static fixture; this test confirms the same behavior on a
        # hand-rolled legacy row.
        legacy = _legacy_chain_line()["finding"]
        df = DraftFinding.model_validate(legacy)
        assert df.record_kind == "draft"


class TestDiscriminatedUnionDispatch:
    def test_new_draft_line_parses_as_draft(self):
        entry = FindingChainEntry.model_validate(_new_draft_line())
        assert isinstance(entry.finding, DraftFinding)
        assert entry.finding.record_kind == "draft"

    def test_update_line_parses_as_update(self):
        entry = FindingChainEntry.model_validate(_update_line())
        assert isinstance(entry.finding, FindingUpdate)
        assert entry.finding.record_kind == "update"
        assert entry.finding.new_state == "CONFIRMED"
        assert entry.finding.previous_state == "DRAFT"


class TestMixedChainReplay:
    def test_replay_derives_current_state(self, tmp_path: Path):
        # Build a fixture findings.jsonl with [DRAFT, DRAFT, UPDATE]
        # and verify read_finding_state returns the latest values.
        path = tmp_path / "findings.jsonl"
        with path.open("w") as f:
            f.write(json.dumps(_legacy_chain_line()) + "\n")
            f.write(json.dumps(_new_draft_line()) + "\n")
            f.write(json.dumps(_update_line()) + "\n")

        # FID has DRAFT (line 1) + UPDATE (line 3); latest = UPDATE.
        state = read_finding_state(tmp_path, FID)
        assert state == ("CONFIRMED", "HIGH")

        # The other id (only the line 2 DraftFinding) returns its
        # own DRAFT state.
        other = "22222222-2222-4222-8222-222222222222"
        state2 = read_finding_state(tmp_path, other)
        assert state2 == ("DRAFT", "MEDIUM")

        # Unknown id returns None.
        assert read_finding_state(tmp_path, "deadbeef-dead-4dead-8dead-deaddeaddead") is None

    def test_replay_derives_intermediate_state_when_no_update(
        self, tmp_path: Path
    ):
        # Just a DRAFT, no UPDATE — read_finding_state returns the
        # DRAFT's own state/confidence.
        path = tmp_path / "findings.jsonl"
        with path.open("w") as f:
            f.write(json.dumps(_new_draft_line()) + "\n")
        other = "22222222-2222-4222-8222-222222222222"
        state = read_finding_state(tmp_path, other)
        assert state == ("DRAFT", "MEDIUM")
