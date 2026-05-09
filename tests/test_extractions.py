"""Unit tests for `server.extractions` — write / load / cache lifecycle
for tier-1 Volatility extractions.

`write_extraction` persists a typed result and writes both a `.json`
and a `.sha256` sidecar. `load_extraction` reads it back, verifying
that the .json bytes hash to both the chain entry's recorded
`extraction_sha256` and the .sha256 sidecar; mismatch raises
`HashMismatchError`. `extraction_exists` requires all three artifacts
(.json + .sha256 + chain line) — partial state is treated as missing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.extractions import (
    ExtractionNotFoundError,
    HashMismatchError,
    extraction_exists,
    load_extraction,
    write_extraction,
)
from server.schemas import (
    NetscanResult,
    NetworkRecord,
    PslistResult,
    ProcessRecord,
)


EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _process_record(pid: int, name: str = "x.exe") -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        ppid=4,
        image_file_name=name,
        offset_v=0,
        threads=1,
        handles=None,
        session_id=None,
        wow64=False,
        create_time=NOW_UTC,
        exit_time=None,
    )


def _pslist_result(processes: list[ProcessRecord]) -> PslistResult:
    return PslistResult(
        evidence_id=EVIDENCE_ID,
        plugin_name="windows.pslist.PsList",
        volatility_version="2.27.0",
        processes=processes,
        command_executed="vol -f /tmp/x.raw -r json windows.pslist.PsList",
        runtime_seconds=14.7,
        invoked_at=NOW_UTC,
    )


def _netscan_result(records: list[NetworkRecord]) -> NetscanResult:
    return NetscanResult(
        evidence_id=EVIDENCE_ID,
        plugin_name="windows.netscan.NetScan",
        volatility_version="2.27.0",
        connections=records,
        command_executed="vol -f /tmp/x.raw -r json windows.netscan.NetScan",
        runtime_seconds=537.4,
        invoked_at=NOW_UTC,
    )


class TestWriteExtraction:
    def test_writes_json_sidecar_and_chain_line(self, tmp_path: Path):
        result = _pslist_result([_process_record(4, "System")])
        ref = write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            result,
            runtime_seconds=14.7,
        )

        json_path = tmp_path / "extractions" / EVIDENCE_ID / "windows.pslist.PsList.json"
        sidecar_path = tmp_path / "extractions" / EVIDENCE_ID / "windows.pslist.PsList.sha256"
        chain_path = tmp_path / "extractions.jsonl"

        assert json_path.exists()
        assert sidecar_path.exists()
        assert chain_path.exists()

        # ExtractionRef carries server-derived fields.
        assert ref.evidence_id == EVIDENCE_ID
        assert ref.plugin_name == "windows.pslist.PsList"
        assert ref.cached is False
        assert ref.runtime_seconds == 14.7
        assert ref.record_count == 1
        assert ref.extractions_chain_line == 1
        assert len(ref.extraction_sha256) == 64

        # Sidecar contains exactly the recorded sha256.
        assert sidecar_path.read_text(encoding="utf-8").strip() == ref.extraction_sha256
        # On-disk bytes match the sidecar hash.
        on_disk_hash = hashlib.sha256(json_path.read_bytes()).hexdigest()
        assert on_disk_hash == ref.extraction_sha256

    def test_refuses_overwrite_of_existing_extraction(self, tmp_path: Path):
        result = _pslist_result([_process_record(4, "System")])
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            result,
            runtime_seconds=14.7,
        )
        with pytest.raises(FileExistsError):
            write_extraction(
                tmp_path,
                EVIDENCE_ID,
                "windows.pslist.PsList",
                result,
                runtime_seconds=14.7,
            )

    def test_netscan_result_uses_connections_list_field(self, tmp_path: Path):
        record = NetworkRecord(
            proto="TCPv4",
            local_addr="0.0.0.0",
            local_port=445,
            foreign_addr="0.0.0.0",
            foreign_port=0,
            state="LISTENING",
            pid=4,
            owner="System",
            offset=0,
            created=None,
        )
        ref = write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.netscan.NetScan",
            _netscan_result([record]),
            runtime_seconds=537.4,
        )
        # _record_list_from_result picks `connections`, not `processes`.
        assert ref.record_count == 1


class TestExtractionExists:
    def test_false_when_nothing_written(self, tmp_path: Path):
        assert extraction_exists(tmp_path, EVIDENCE_ID, "windows.pslist.PsList") is False

    def test_true_after_write(self, tmp_path: Path):
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
        )
        assert extraction_exists(tmp_path, EVIDENCE_ID, "windows.pslist.PsList") is True

    def test_partial_state_treated_as_missing(self, tmp_path: Path):
        # Write all three artifacts, then delete the .sha256 sidecar
        # to simulate a crash between .json and .sha256 writes.
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
        )
        sidecar = tmp_path / "extractions" / EVIDENCE_ID / "windows.pslist.PsList.sha256"
        sidecar.unlink()
        # Partial state -> exists() is False, callers fall back to fresh.
        assert extraction_exists(tmp_path, EVIDENCE_ID, "windows.pslist.PsList") is False


class TestLoadExtraction:
    def test_round_trip_yields_cached_ref(self, tmp_path: Path):
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4, "System"), _process_record(100, "smss.exe")]),
            runtime_seconds=14.7,
        )

        ref, parsed = load_extraction(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")
        assert ref.cached is True
        assert ref.runtime_seconds is None
        assert ref.record_count == 2
        # The full PslistResult JSON shape is preserved on disk.
        assert parsed["plugin_name"] == "windows.pslist.PsList"
        assert parsed["volatility_version"] == "2.27.0"
        records = parsed["processes"]
        assert {r["pid"] for r in records} == {4, 100}

    def test_raises_extraction_not_found_when_missing(self, tmp_path: Path):
        with pytest.raises(ExtractionNotFoundError):
            load_extraction(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")

    def test_raises_hash_mismatch_when_json_tampered(self, tmp_path: Path):
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
        )
        # Tamper with the .json: append a single space. The sidecar and
        # chain still reference the old hash; load must reject.
        json_path = tmp_path / "extractions" / EVIDENCE_ID / "windows.pslist.PsList.json"
        with json_path.open("a", encoding="utf-8") as f:
            f.write(" ")
        with pytest.raises(HashMismatchError):
            load_extraction(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")

    def test_raises_hash_mismatch_when_sidecar_tampered(self, tmp_path: Path):
        write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
        )
        sidecar = tmp_path / "extractions" / EVIDENCE_ID / "windows.pslist.PsList.sha256"
        # Replace the sidecar with a wrong-but-well-formed hash.
        sidecar.write_text("0" * 64 + "\n")
        with pytest.raises(HashMismatchError):
            load_extraction(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")

    def test_audit_line_persisted_through_chain_and_load(self, tmp_path: Path):
        """write_extraction(audit_line=N) → load_extraction returns
        ExtractionRef with audit_line=N. Round-trip integrity through
        the extractions.jsonl chain entry."""
        ref = write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
            audit_line=42,
        )
        assert ref.audit_line == 42
        assert ref.cached is False

        # Reload — cached ref must carry the same audit_line.
        loaded_ref, _ = load_extraction(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")
        assert loaded_ref.audit_line == 42
        assert loaded_ref.cached is True

        # Chain entry on disk also carries audit_line.
        from server.extractions_log import find_extraction_entry

        chain_entry = find_extraction_entry(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")
        assert chain_entry is not None
        assert chain_entry.audit_line == 42

    def test_legacy_chain_entry_without_audit_line_loads_as_none(self, tmp_path: Path):
        """Load a chain entry written without `audit_line` (the
        pre-2026-05-06 schema) and confirm it surfaces as None on the
        ExtractionRef. This pins the migration semantic: no
        retroactive backfill of historical entries."""
        # Write a synthetic legacy chain line directly — no audit_line
        # field at all. Mirrors the shape of the 3 lines already on
        # disk in case-data/extractions.jsonl from week-5 verification.
        import json as _json
        from server.schemas import ExtractionChainEntry
        from server.extractions_log import _GENESIS_PREV_HASH

        # Compose the chain line manually with the legacy field set.
        # Real extraction file + sidecar must also exist for the load
        # path to reach the chain-entry read.
        result = _pslist_result([_process_record(4), _process_record(100)])
        payload = result.model_dump_json().encode("utf-8")
        import hashlib

        sha = hashlib.sha256(payload).hexdigest()

        case_dir = tmp_path
        ext_dir = case_dir / "extractions" / EVIDENCE_ID
        ext_dir.mkdir(parents=True)
        (ext_dir / "windows.pslist.PsList.json").write_bytes(payload)
        (ext_dir / "windows.pslist.PsList.sha256").write_text(sha + "\n")

        # Hand-write the chain JSONL line with legacy field set
        # (no audit_line key).
        ts = NOW_UTC
        chained = dict(
            line_number=1,
            timestamp=ts,
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            extraction_id="11111111-1111-4111-8111-111111111111",
            extraction_sha256=sha,
            record_count=2,
            runtime_seconds=14.7,
            audit_line=None,  # explicit None — schema accepts it the same as absent
            prev_extraction_hash=_GENESIS_PREV_HASH,
        )
        this_hash = ExtractionChainEntry.compute_this_extraction_hash(**chained)
        # Build the legacy line by hand WITHOUT including `audit_line` in
        # the JSON output, mirroring the on-disk shape of a pre-fix entry.
        legacy = {k: v for k, v in chained.items() if k != "audit_line"}
        legacy["timestamp"] = ts.isoformat()
        legacy["this_extraction_hash"] = this_hash
        # Stored hash was computed *with* audit_line=None — that's the
        # canonical form the new writer emits for the absent-field case.
        # The legacy on-disk hash from week-5 was computed WITHOUT the
        # field, so its hash differs. For load_extraction's purposes,
        # only the .json sha (matched against sidecar + chain) is
        # verified; this test focuses on the audit_line=None surfacing.
        (case_dir / "extractions.jsonl").write_text(_json.dumps(legacy, default=str) + "\n")

        loaded_ref, _ = load_extraction(case_dir, EVIDENCE_ID, "windows.pslist.PsList")
        assert loaded_ref.audit_line is None, (
            "legacy chain entries without audit_line must load as None — no retroactive backfill"
        )

    def test_chain_line_persisted_runtime_seconds(self, tmp_path: Path):
        # The fresh-write ref carries `runtime_seconds`; the cached
        # load returns `runtime_seconds=None`. But the chain entry
        # itself must persist the original runtime — used by audit
        # tooling to reproduce timing later.
        ref = write_extraction(
            tmp_path,
            EVIDENCE_ID,
            "windows.pslist.PsList",
            _pslist_result([_process_record(4)]),
            runtime_seconds=14.7,
        )
        assert ref.runtime_seconds == 14.7

        from server.extractions_log import find_extraction_entry

        chain_entry = find_extraction_entry(tmp_path, EVIDENCE_ID, "windows.pslist.PsList")
        assert chain_entry is not None
        assert chain_entry.runtime_seconds == 14.7
