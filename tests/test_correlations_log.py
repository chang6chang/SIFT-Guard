"""Unit tests for `server.correlations_log` — the hash-chained
writer for `case-data/correlations.jsonl`.

Mirrors the audit / findings / extractions chain shape but uses
distinct hash field names (`prev_correlation_hash` /
`this_correlation_hash`) so a line read out of context cannot be
silently misinterpreted as one of the other chains' lines.

Three writers, three roles, three chains: the validator's chain.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from server.correlations_log import (
    append_correlation_entry,
    read_correlation_ids,
)
from server.schemas import (
    ContradictsCorrelation,
    CorrelationChainEntry,
    CorroboratesCorrelation,
    EvidenceRef,
    RequestFollowupCorrelation,
)


_GENESIS_PREV = "0" * 64
_NOW = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
FID_A = "11111111-1111-4111-8111-111111111111"
FID_B = "22222222-2222-4222-8222-222222222222"
CID_A = "33333333-3333-4333-8333-333333333333"
CID_B = "44444444-4444-4444-8444-444444444444"


def _ev_ref() -> EvidenceRef:
    return EvidenceRef(
        source_tool="set_difference",
        audit_line=10,
        detail="psscan a-b pslist on pid",
    )


def _corroborates(correlation_id: str = CID_A, audit_line: int = 10) -> CorroboratesCorrelation:
    return CorroboratesCorrelation(
        correlation_id=correlation_id,
        case_id="case-rocba",
        iteration_number=0,
        created_at=_NOW,
        audit_line=audit_line,
        evidence_refs=[_ev_ref()],
        hypothesis=(
            "PID 7900 svchost is hidden — the set_difference, the "
            "duplicate-key signal, and the non-null create_time form "
            "a corroborated cluster."
        ),
        target_finding_ids=[FID_A],
        strength="strong",
    )


def _contradicts() -> ContradictsCorrelation:
    return ContradictsCorrelation(
        correlation_id=CID_B,
        case_id="case-rocba",
        iteration_number=1,
        created_at=_NOW,
        audit_line=11,
        evidence_refs=[_ev_ref()],
        hypothesis=(
            "Two findings disagree about whether PID Y is "
            "masquerading; the cmdline plugin would resolve."
        ),
        finding_a_id=FID_A,
        finding_b_id=FID_B,
        severity="material",
        resolvable_by_followup=True,
    )


class TestGenesisAppend:
    def test_first_append_uses_genesis_prev_hash(self, tmp_path: Path):
        entry = append_correlation_entry(tmp_path, _corroborates())
        assert entry.line_number == 1
        assert entry.prev_correlation_hash == _GENESIS_PREV
        assert len(entry.this_correlation_hash) == 64

        chain_path = tmp_path / "correlations.jsonl"
        assert chain_path.exists()
        on_disk = json.loads(chain_path.read_text().strip())
        assert on_disk["this_correlation_hash"] == entry.this_correlation_hash
        # Discriminator survives the round-trip on disk.
        assert on_disk["correlation"]["correlation_type"] == "corroborates"

    def test_chain_links_across_two_appends(self, tmp_path: Path):
        first = append_correlation_entry(tmp_path, _corroborates())
        second = append_correlation_entry(tmp_path, _contradicts())
        assert second.line_number == 2
        assert second.prev_correlation_hash == first.this_correlation_hash

    def test_canonical_hash_recomputable_from_disk(self, tmp_path: Path):
        entry = append_correlation_entry(tmp_path, _corroborates())
        recomputed = CorrelationChainEntry.compute_this_correlation_hash(
            line_number=entry.line_number,
            timestamp=entry.timestamp,
            correlation=entry.correlation.model_dump(mode="json"),
            prev_correlation_hash=entry.prev_correlation_hash,
        )
        assert recomputed == entry.this_correlation_hash


class TestMixedTypesInOneChain:
    def test_three_correlation_types_link_correctly(self, tmp_path: Path):
        # All five concrete subtypes should be writable into the same
        # chain. We test three representative types (one per kind:
        # multi-target, two-target, follow-up request) to confirm the
        # discriminator round-trips without poisoning the chain.
        e1 = append_correlation_entry(tmp_path, _corroborates())
        e2 = append_correlation_entry(tmp_path, _contradicts())
        e3 = append_correlation_entry(
            tmp_path,
            RequestFollowupCorrelation(
                correlation_id="55555555-5555-4555-8555-555555555555",
                case_id="case-rocba",
                iteration_number=2,
                created_at=_NOW,
                audit_line=12,
                evidence_refs=[_ev_ref()],
                hypothesis=(
                    "Need handles + cmdline coverage on PID 7900 "
                    "before promoting; netscan owner field alone is "
                    "ambiguous."
                ),
                target_analyst="process_analyst",
                related_finding_ids=[FID_A],
                focus_context={"pids": [7900]},
                rationale="Re-run with handles plugin focused on PID 7900.",
            ),
        )

        # Linkage holds across mixed types.
        assert e2.prev_correlation_hash == e1.this_correlation_hash
        assert e3.prev_correlation_hash == e2.this_correlation_hash

        # On-disk discriminator labels survive.
        rows = [
            json.loads(l)
            for l in (tmp_path / "correlations.jsonl").read_text().splitlines()
            if l.strip()
        ]
        assert [r["correlation"]["correlation_type"] for r in rows] == [
            "corroborates",
            "contradicts",
            "request_followup",
        ]


class TestReadCorrelationIds:
    def test_empty_for_missing_file(self, tmp_path: Path):
        assert read_correlation_ids(tmp_path) == set()

    def test_returns_all_committed_ids(self, tmp_path: Path):
        append_correlation_entry(
            tmp_path, _corroborates(correlation_id=CID_A)
        )
        append_correlation_entry(tmp_path, _contradicts())
        ids = read_correlation_ids(tmp_path)
        assert ids == {CID_A, CID_B}

    def test_skips_malformed_lines(self, tmp_path: Path):
        append_correlation_entry(
            tmp_path, _corroborates(correlation_id=CID_A)
        )
        # Tamper: append a malformed line. Reader must skip silently
        # — chain integrity is verified by a separate code path; the
        # id collector's job is provenance lookup.
        path = tmp_path / "correlations.jsonl"
        with path.open("a") as f:
            f.write("{not-valid-json\n")
        ids = read_correlation_ids(tmp_path)
        assert ids == {CID_A}
