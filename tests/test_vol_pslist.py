"""Unit tests for `server.tools.memory.vol_pslist`.

No real SSH. ``server.tools.memory.run_vol_plugin`` and
``server.tools.memory.get_vol_version`` are mocked at the
``server.tools.memory`` namespace where memory.py looked them up.

The audit-chain test (``TestAuditChain``) reads the actual on-disk
``case-data/CASE.yaml`` and ``case-data/audit/sift-guard-mcp.jsonl``
to seed the chain into a tmp_path-isolated case dir, then verifies
the new audit line links back to the copied chain. The on-disk audit
log itself is never written — verified at the end of the test.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from server.extractions import load_extraction
from server.schemas import ArtifactClass, EvidenceRecord
from server.tools.memory import translate_to_vm_path, vol_pslist


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PSLIST_FIXTURE = Path(__file__).parent / "fixtures" / "vol_pslist_sample.json"
ON_DISK_CASE_YAML = PROJECT_ROOT / "case-data" / "CASE.yaml"
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MEMORY_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    filename: str = "Rocba-Memory.raw",
    absolute_path: str | None = None,
) -> Path:
    """Build a tmp case dir with a CASE.yaml entry for one piece of evidence.

    Mirrors what `register_evidence` would have produced. The file at
    `evidence/<filename>` is a placeholder — `vol_pslist` never reads
    its bytes (the runner is mocked), it only needs the path string for
    translation. Pass `absolute_path` to override the stored path
    string (e.g. for tests that exercise the path-translation
    rejection branch with a path outside `evidence/`); when overridden
    the placeholder file is not written.
    """
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()
    if absolute_path is None:
        fake_evidence = evidence_dir / filename
        fake_evidence.write_bytes(b"\x00" * 1024)
        absolute_path = str(fake_evidence)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename=filename,
        absolute_path=absolute_path,
        sha256=VALID_SHA256,
        size_bytes=1024,
        artifact_class=artifact_class,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": case_dir.name,
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    return case_dir


def _bad_record_json() -> str:
    """Three-row pslist output with a middle record that fails ProcessRecord
    validation (PID -1 violates `ge=0`). The flanking rows are valid."""
    return json.dumps(
        [
            {
                "PID": 4, "PPID": 0, "ImageFileName": "System",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
            {
                "PID": -1, "PPID": 0, "ImageFileName": "Bad",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
            {
                "PID": 100, "PPID": 4, "ImageFileName": "smss.exe",
                "Offset(V)": 0, "Threads": 1, "Handles": None,
                "SessionId": None, "Wow64": False,
                "CreateTime": "2024-01-01T00:00:00+00:00", "ExitTime": None,
                "File output": "Disabled", "__children": [],
            },
        ]
    )


# ---------------------------------------------------------------------------
# translate_to_vm_path
# ---------------------------------------------------------------------------


class TestTranslateToVmPath:
    def test_happy_path(self):
        assert (
            translate_to_vm_path(
                "/home/galvarino/case-data/evidence/Foo.raw",
                "/home/galvarino/case-data/evidence",
                "/mnt/rocba",
            )
            == "/mnt/rocba/Foo.raw"
        )

    def test_outside_host_prefix_rejected(self):
        with pytest.raises(ValueError) as exc_info:
            translate_to_vm_path(
                "/etc/passwd",
                "/home/galvarino/case-data/evidence",
                "/mnt/rocba",
            )
        # Sanitized: the offending path must not appear in the message.
        assert "/etc/passwd" not in str(exc_info.value)
        assert "expected host prefix" in str(exc_info.value)


# ---------------------------------------------------------------------------
# evidence resolution + artifact_class gate
# ---------------------------------------------------------------------------


class TestVolPslistResolution:
    def test_evidence_id_not_in_case_yaml_raises_sanitized_value_error(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            vol_pslist(bogus_id, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        # Sanitized: the attempted evidence_id is not echoed back, so a
        # probe-and-read attack cannot map the registry one ID at a time.
        assert bogus_id not in str(exc_info.value)
        # The rejection IS audit-logged — chain-extension assertions
        # live in TestVolPslistRejectionAudit below.

    def test_artifact_class_unknown_rejected_with_sanitized_message(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path, artifact_class=ArtifactClass.UNKNOWN)
        with pytest.raises(ValueError) as exc_info:
            vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))
        assert str(exc_info.value) == "evidence is not a memory image"
        # Sanitized: the actual artifact_class value is internal state.
        assert "unknown" not in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# rejection audit lines — the chain must record every agent call,
# including rejections, otherwise rejection becomes an unrecorded
# probe channel.
# ---------------------------------------------------------------------------


_GENESIS_PREV_HASH = "0" * 64


class TestVolPslistRejectionAudit:
    def test_evidence_not_found_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"

        with pytest.raises(ValueError):
            vol_pslist(bogus_id, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert entry["tool_name"] == "vol_pslist:rejected_evidence_not_found"
        # Operator-visible: the bogus evidence_id IS captured in the
        # audit log (so probes leave a trace), even though the agent's
        # exception did not echo it.
        assert entry["evidence_id"] == bogus_id
        # Chain integrity holds for line 1 of a fresh chain.
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["this_line_hash"])

    def test_wrong_artifact_class_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(
            tmp_path, artifact_class=ArtifactClass.UNKNOWN
        )

        with pytest.raises(ValueError):
            vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"]
            == "vol_pslist:rejected_wrong_artifact_class"
        )
        assert entry["evidence_id"] == VALID_EVIDENCE_ID
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH

    def test_path_translation_failed_writes_rejection_chain_line(
        self, tmp_path: Path
    ):
        # `absolute_path` lives outside the case_dir/evidence/ tree, so
        # `translate_to_vm_path`'s host-prefix check fires after both
        # the evidence-resolution and artifact-class gates have passed.
        # Should be unreachable under a normal `register_evidence`
        # flow (path-confinement blocks it at registration time), but
        # we still record the probe — defense in depth, and the
        # symmetric counterpart of the other two rejection tests.
        case_dir = _make_case_dir(tmp_path, absolute_path="/tmp/Foo.raw")

        with pytest.raises(ValueError) as exc_info:
            vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Sanitized: the offending path is not echoed back to the agent.
        assert "/tmp/Foo.raw" not in str(exc_info.value)
        assert "expected host prefix" in str(exc_info.value)

        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        assert audit_path.exists(), "rejection must extend the chain"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        entry = lines[0]
        assert (
            entry["tool_name"]
            == "vol_pslist:rejected_path_translation_failed"
        )
        assert entry["evidence_id"] == VALID_EVIDENCE_ID
        assert entry["line_number"] == 1
        assert entry["prev_line_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_line_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry["this_line_hash"])


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


class TestVolPslistHappyPath:
    def test_returns_pslist_summary_with_three_records(self, tmp_path: Path):
        """Tier-1 contract: vol_pslist returns a PslistSummary with an
        ExtractionRef and shape signal; the full PslistResult lands on
        disk under extractions/<evidence_id>/windows.pslist.PsList.json
        and is loadable via `load_extraction`."""
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PSLIST_FIXTURE.read_text(encoding="utf-8")
        fake_command = (
            "ssh -p 2222 sansforensics@test.invalid vol "
            "-f /mnt/rocba/Rocba-Memory.raw -r json windows.pslist.PsList"
        )

        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, fake_command, 14.7),
        ) as mock_run:
            summary = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # ExtractionRef is the agent-visible handle for the stored data.
        ref = summary.extraction
        assert ref.plugin_name == "windows.pslist.PsList"
        assert ref.evidence_id == VALID_EVIDENCE_ID
        assert ref.record_count == 3
        assert ref.cached is False
        assert ref.runtime_seconds == 14.7
        assert ref.extractions_chain_line == 1
        assert len(ref.extraction_sha256) == 64

        # Summary distribution fields reflect the three sample rows.
        assert summary.unique_image_names == 3
        assert summary.distinct_ppids == len({0, 4})
        assert summary.pid_range == (4, 440)
        # top_image_names is ordered descending by count; for the
        # three-row sample each name appears once so the order is
        # whichever pydantic preserved from the Counter.most_common
        # tie-break (insertion order).
        names_in_top = {n for n, _ in summary.top_image_names}
        assert names_in_top == {"System", "Registry", "smss.exe"}

        # The full PslistResult is now on disk; loading it gives back
        # the three records with their original fields.
        loaded_ref, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "windows.pslist.PsList"
        )
        assert loaded_ref.cached is True
        assert loaded_ref.runtime_seconds is None  # cache contract
        assert parsed["plugin_name"] == "windows.pslist.PsList"
        assert parsed["volatility_version"] == "2.27.0"
        assert parsed["evidence_id"] == VALID_EVIDENCE_ID
        assert parsed["runtime_seconds"] == 14.7
        assert parsed["command_executed"] == fake_command
        records = parsed["processes"]
        assert len(records) == 3
        assert records[0]["pid"] == 4
        assert records[0]["image_file_name"] == "System"
        assert records[1]["pid"] == 100
        assert records[1]["image_file_name"] == "Registry"
        assert records[2]["pid"] == 440
        assert records[2]["image_file_name"] == "smss.exe"

        # The runner was called with the pinned plugin name and the
        # translated VM path — not the host path.
        plugin_arg, vm_path_arg = mock_run.call_args.args[:2]
        assert plugin_arg == "windows.pslist.PsList"
        assert vm_path_arg == "/mnt/rocba/Rocba-Memory.raw"

        # Extractions chain line was created with matching hash.
        chain_path = case_dir / "extractions.jsonl"
        chain_lines = [
            json.loads(l) for l in chain_path.read_text().splitlines() if l.strip()
        ]
        assert len(chain_lines) == 1
        assert chain_lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert chain_lines[0]["plugin_name"] == "windows.pslist.PsList"
        assert chain_lines[0]["record_count"] == 3
        assert chain_lines[0]["extraction_sha256"] == ref.extraction_sha256


# ---------------------------------------------------------------------------
# per-record validation warnings
# ---------------------------------------------------------------------------


class TestVolPslistRecordWarnings:
    def test_one_bad_record_logged_as_warning_others_preserved(
        self, tmp_path: Path
    ):
        case_dir = _make_case_dir(tmp_path)
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(_bad_record_json(), "ssh ... vol ...", 1.0),
        ):
            summary = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # The summary's record_count reflects only the surviving rows;
        # PID -1 was dropped during validation.
        assert summary.extraction.record_count == 2

        # Stored extraction: the two valid records survived, the bad
        # row is gone, and the audited count matches.
        _, parsed = load_extraction(
            case_dir, VALID_EVIDENCE_ID, "windows.pslist.PsList"
        )
        records = parsed["processes"]
        assert len(records) == 2
        assert {r["pid"] for r in records} == {4, 100}
        assert all(r["pid"] != -1 for r in records)

        # Audit log: 1 warning entry + 1 main result entry, in that
        # order. The warning's tool_name names the failure mode so a
        # reader can grep for it.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [json.loads(l) for l in audit_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 2
        assert lines[0]["tool_name"] == "vol_pslist:record_validation_warning"
        assert lines[0]["evidence_id"] == VALID_EVIDENCE_ID
        assert lines[1]["tool_name"] == "vol_pslist"
        # Chain link: the main result line points at the warning line's
        # this_line_hash.
        assert lines[1]["prev_line_hash"] == lines[0]["this_line_hash"]


# ---------------------------------------------------------------------------
# audit-chain extension from the real on-disk chain
# ---------------------------------------------------------------------------


class TestVolPslistAuditLinePlumbing:
    def test_fresh_call_populates_audit_line_on_extraction_ref(
        self, tmp_path: Path
    ):
        """Fresh tier-1 call: ExtractionRef.audit_line equals the audit
        chain line where this very invocation was logged. Closes the
        v2 probe-finding pattern (failure mode #1 in
        docs/accuracy-report.md): the analyst has the audit_line
        directly off the return value."""
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PSLIST_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 12.3),
        ):
            summary = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # Fresh extraction: audit_line populated.
        assert summary.extraction.audit_line is not None
        # The success audit entry IS the line referenced — verify by
        # reading the audit chain.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        success_lines = [l for l in lines if l["tool_name"] == "vol_pslist"]
        assert len(success_lines) == 1
        assert summary.extraction.audit_line == success_lines[0]["line_number"]

    def test_cached_call_carries_original_invocation_audit_line(
        self, tmp_path: Path
    ):
        """Cached tier-1 call: ExtractionRef.audit_line is the ORIGINAL
        invocation's line number, not the cache-hit's audit line. The
        cache-hit is logged separately as `vol_pslist:cached`."""
        case_dir = _make_case_dir(tmp_path)
        fixture_stdout = PSLIST_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 12.3),
        ):
            first = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))
            original_audit_line = first.extraction.audit_line
            # Second call hits the cache.
            second = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        assert second.extraction.cached is True
        # The cache-hit audit line is NOT what's surfaced — the
        # original invocation's line is what stays in the ExtractionRef.
        assert second.extraction.audit_line == original_audit_line

        # The cache hit IS audited separately, just not as the
        # ExtractionRef's audit_line.
        audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
        lines = [
            json.loads(l)
            for l in audit_path.read_text().splitlines()
            if l.strip()
        ]
        cached_lines = [
            l for l in lines if l["tool_name"] == "vol_pslist:cached"
        ]
        assert len(cached_lines) == 1
        assert cached_lines[0]["line_number"] != original_audit_line


class TestAuditChain:
    def test_audit_chain_extends_from_existing_on_disk_chain(
        self, tmp_path: Path
    ):
        """Seed the tmp case dir from the real on-disk CASE.yaml + audit log
        and verify vol_pslist's new audit line links to the copied chain's
        last `this_line_hash`. The on-disk audit log is never written —
        verified at the end."""
        on_disk_audit_before = ON_DISK_AUDIT_LOG.read_bytes()

        case_dir = tmp_path / "case-data"
        (case_dir / "audit").mkdir(parents=True)
        (case_dir / "evidence").mkdir(parents=True)
        shutil.copy(ON_DISK_CASE_YAML, case_dir / "CASE.yaml")
        shutil.copy(
            ON_DISK_AUDIT_LOG, case_dir / "audit" / "sift-guard-mcp.jsonl"
        )

        # Find the Rocba entry, point its absolute_path at a tmp
        # stand-in inside this case_dir's evidence/ so path translation
        # can resolve it through the host prefix.
        case_yaml_path = case_dir / "CASE.yaml"
        doc = yaml.safe_load(case_yaml_path.read_text())
        rocba_entry = next(
            e for e in doc["evidence"]
            if e["original_filename"] == "Rocba-Memory.raw"
        )
        rocba_evidence_id = rocba_entry["evidence_id"]
        fake_rocba = case_dir / "evidence" / "Rocba-Memory.raw"
        fake_rocba.write_bytes(b"\x00" * 1024)
        rocba_entry["absolute_path"] = str(fake_rocba)
        case_yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False))

        # Capture the last this_line_hash from the seeded (on-disk
        # source) chain — this is what the next line's prev_line_hash
        # must equal.
        seeded_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        seeded_count = len(seeded_lines)
        assert seeded_count >= 2, (
            "expected the on-disk chain to have at least 2 lines "
            "(smoke test + Rocba registration)"
        )
        last_seeded = json.loads(seeded_lines[-1])
        expected_prev = last_seeded["this_line_hash"]

        fixture_stdout = PSLIST_FIXTURE.read_text(encoding="utf-8")
        with patch(
            "server.tools.memory.get_vol_version", return_value="2.27.0"
        ), patch(
            "server.tools.memory.run_vol_plugin",
            return_value=(fixture_stdout, "ssh ... vol ...", 12.3),
        ):
            vol_pslist(rocba_evidence_id, case_dir=str(case_dir))

        # The tmp chain grew by exactly one (no warnings — fixture is
        # all valid records).
        new_lines = (
            (case_dir / "audit" / "sift-guard-mcp.jsonl")
            .read_text()
            .splitlines()
        )
        assert len(new_lines) == seeded_count + 1
        new_entry = json.loads(new_lines[-1])
        assert new_entry["tool_name"] == "vol_pslist"
        assert new_entry["evidence_id"] == rocba_evidence_id
        assert new_entry["prev_line_hash"] == expected_prev, (
            "vol_pslist's audit line failed to link to the prior "
            "chain — chain is broken"
        )
        assert new_entry["line_number"] == seeded_count + 1

        # The on-disk audit log was never touched.
        assert ON_DISK_AUDIT_LOG.read_bytes() == on_disk_audit_before, (
            "on-disk audit log was modified by the test — isolation "
            "is broken"
        )
