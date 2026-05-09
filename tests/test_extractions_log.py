"""Unit tests for `server.extractions_log` — the hash-chained writer
for `case-data/extractions.jsonl`.

Mirrors the audit / findings chain shape but uses distinct hash field
names (`prev_extraction_hash` / `this_extraction_hash`) so a line
read out of context cannot be silently misinterpreted as one of the
other chains' lines.
"""

from __future__ import annotations

import json
from pathlib import Path


from server.extractions_log import (
    append_extraction_entry,
    find_extraction_entry,
)
from server.schemas import ExtractionChainEntry


_GENESIS_PREV = "0" * 64
EVID_A = "550e8400-e29b-41d4-a716-446655440000"
EVID_B = "11111111-1111-4111-8111-111111111111"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


class TestGenesisAppend:
    def test_first_append_uses_genesis_prev_hash(self, tmp_path: Path):
        entry = append_extraction_entry(
            case_dir=tmp_path,
            evidence_id=EVID_A,
            plugin_name="windows.pslist.PsList",
            extraction_id=EVID_B,
            extraction_sha256=SHA_A,
            record_count=42,
            runtime_seconds=18.0,
        )
        assert entry.line_number == 1
        assert entry.prev_extraction_hash == _GENESIS_PREV
        assert len(entry.this_extraction_hash) == 64

        # On-disk file mirrors the returned entry.
        chain_path = tmp_path / "extractions.jsonl"
        assert chain_path.exists()
        on_disk = json.loads(chain_path.read_text().strip())
        assert on_disk["this_extraction_hash"] == entry.this_extraction_hash

    def test_chain_links_across_two_appends(self, tmp_path: Path):
        first = append_extraction_entry(
            tmp_path,
            EVID_A,
            "windows.pslist.PsList",
            EVID_B,
            SHA_A,
            10,
            5.0,
        )
        second = append_extraction_entry(
            tmp_path,
            EVID_A,
            "windows.psscan.PsScan",
            EVID_B,
            SHA_B,
            10,
            300.0,
        )
        assert second.line_number == 2
        assert second.prev_extraction_hash == first.this_extraction_hash

    def test_canonical_hash_recomputable_from_disk(self, tmp_path: Path):
        # Tampering check: re-derive `this_extraction_hash` from the
        # other fields and confirm they match — this is the property
        # the chain integrity verifier (and `load_extraction`'s
        # cross-check) leans on.
        entry = append_extraction_entry(
            tmp_path,
            EVID_A,
            "windows.pstree.PsTree",
            EVID_B,
            SHA_C,
            58,
            29.5,
        )
        recomputed = ExtractionChainEntry.compute_this_extraction_hash(
            line_number=entry.line_number,
            timestamp=entry.timestamp,
            evidence_id=entry.evidence_id,
            plugin_name=entry.plugin_name,
            extraction_id=entry.extraction_id,
            extraction_sha256=entry.extraction_sha256,
            record_count=entry.record_count,
            runtime_seconds=entry.runtime_seconds,
            audit_line=entry.audit_line,
            prev_extraction_hash=entry.prev_extraction_hash,
        )
        assert recomputed == entry.this_extraction_hash


class TestFindExtractionEntry:
    def test_returns_none_for_missing_chain_file(self, tmp_path: Path):
        assert find_extraction_entry(tmp_path, EVID_A, "windows.pslist.PsList") is None

    def test_returns_matching_entry_after_append(self, tmp_path: Path):
        append_extraction_entry(
            tmp_path,
            EVID_A,
            "windows.pslist.PsList",
            EVID_B,
            SHA_A,
            10,
            5.0,
        )
        found = find_extraction_entry(tmp_path, EVID_A, "windows.pslist.PsList")
        assert found is not None
        assert found.evidence_id == EVID_A
        assert found.plugin_name == "windows.pslist.PsList"
        assert found.extraction_sha256 == SHA_A

    def test_returns_none_for_pair_not_in_chain(self, tmp_path: Path):
        append_extraction_entry(
            tmp_path,
            EVID_A,
            "windows.pslist.PsList",
            EVID_B,
            SHA_A,
            10,
            5.0,
        )
        # Different evidence_id, same plugin: no match.
        assert (
            find_extraction_entry(
                tmp_path,
                "22222222-2222-4222-8222-222222222222",
                "windows.pslist.PsList",
            )
            is None
        )
        # Same evidence_id, different plugin: no match.
        assert find_extraction_entry(tmp_path, EVID_A, "windows.psscan.PsScan") is None
