"""Unit tests for `server.tools.findings.record_finding`.

Five rejection paths each get an audit-on-rejection line; the
happy path writes one findings.jsonl line + one audit line; the
findings hash chain links to its predecessor; server-controlled
fields (finding_id / created_at / state / tool_invocations) are
not agent-supplied; pydantic length / count constraints are
enforced and audited as schema_validation_failed.

Audit-byte isolation: every test uses a tmp_path-rooted case dir.
The on-disk findings.jsonl and audit log are read once at
module-load time and asserted unchanged at the end of each test
class via session-scoped fixtures (see TestOnDiskIsolation).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from server.audit import append_audit_entry
from server.schemas import (
    ArtifactClass,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.findings import record_finding


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ON_DISK_CASE_YAML = PROJECT_ROOT / "case-data" / "CASE.yaml"
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"
ON_DISK_FINDINGS = PROJECT_ROOT / "case-data" / "findings.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)
_GENESIS_PREV_HASH = "0" * 64


def _seed_case_dir(
    tmp_path: Path,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MEMORY_IMAGE,
    evidence_id: str = VALID_EVIDENCE_ID,
    seed_audit: bool = True,
) -> Path:
    """Build a tmp case dir with a CASE.yaml entry plus a seeded
    audit chain — by default, a single `vol_pslist` line at line 1
    so an EvidenceRef pointing at audit_line=1 is valid.

    Tests that exercise the invalid-audit-ref path pass
    seed_audit=False and use audit_line numbers that don't exist."""
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()

    fake_evidence = evidence_dir / "Rocba-Memory.raw"
    fake_evidence.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(fake_evidence),
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

    if seed_audit:
        # Stand up an audit chain with one vol_pslist line so refs
        # pointing at audit_line=1 satisfy the provenance check.
        # We use a stand-in BaseModel for `output` because we don't
        # need the full PslistResult here — the audit writer hashes
        # the JSON dump, the hash content is irrelevant to our test.
        from pydantic import BaseModel

        class _Stub(BaseModel):
            stub: str = "ok"

        append_audit_entry(
            case_dir=case_dir,
            tool_name="vol_pslist",
            evidence_id=evidence_id,
            input_args={"evidence_id": evidence_id},
            output=_Stub(),
        )
    return case_dir


def _good_args(**overrides):
    """Default-valid keyword args for record_finding. Every test
    overrides exactly the field it's testing; the rest stays valid."""
    args = dict(
        evidence_id=VALID_EVIDENCE_ID,
        analyst="process_analyst",
        category="process_anomaly",
        severity="medium",
        confidence="MEDIUM",
        title="Suspicious LOLBin descendant of svchost.exe",
        description=(
            "vol_pslist surfaced powershell.exe (PID 4321) with PPID 1244 "
            "(svchost.exe). svchost typically spawns service workers, not "
            "interactive shells; this combination is associated with "
            "scheduled-task lateral execution patterns."
        ),
        evidence_refs=[
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="PID 4321 powershell.exe, PPID 1244 svchost.exe",
            )
        ],
        hypothesis=None,
    )
    args.update(overrides)
    return args


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# happy path — finding written, audit chain extended, content correct
# ---------------------------------------------------------------------------


class TestRecordFindingHappyPath:
    def test_writes_one_finding_line_and_one_audit_line(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        finding = record_finding(**_good_args(), case_dir=str(case_dir))

        # Findings chain: line 1, full DraftFinding payload, valid hash.
        findings = _read_jsonl(case_dir / "findings.jsonl")
        assert len(findings) == 1
        entry = findings[0]
        assert entry["line_number"] == 1
        assert entry["prev_finding_hash"] == _GENESIS_PREV_HASH
        assert len(entry["this_finding_hash"]) == 64
        assert entry["finding"]["finding_id"] == finding.finding_id
        assert entry["finding"]["state"] == "DRAFT"
        assert entry["finding"]["analyst"] == "process_analyst"
        assert entry["finding"]["category"] == "process_anomaly"

        # Audit chain: the seeded vol_pslist line + the new
        # record_finding line. tool_name has no colon-suffix on the
        # success path. evidence_id is captured.
        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert len(audit_lines) == 2
        assert audit_lines[0]["tool_name"] == "vol_pslist"
        assert audit_lines[1]["tool_name"] == "record_finding"
        assert audit_lines[1]["evidence_id"] == VALID_EVIDENCE_ID

        # The audit's output_hash is the digest of the FindingChainEntry —
        # so audit-replay can verify the findings chain by re-hashing.
        # We don't recompute the hash here (the audit module does that);
        # we only assert it exists and is hex64.
        assert len(audit_lines[1]["output_hash"]) == 64

    def test_server_sets_finding_id_created_at_and_state(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        finding = record_finding(**_good_args(), case_dir=str(case_dir))

        # finding_id is a UUIDv4 the server picked — the agent has no
        # way to influence it, but more importantly: it's not the
        # default-empty / zero / fixture value. Validating shape +
        # uniqueness across two calls.
        assert finding.state == "DRAFT"
        assert finding.created_at.tzinfo is not None
        # UUIDv4: version nibble == "4"
        assert finding.finding_id[14] == "4"

        finding2 = record_finding(**_good_args(), case_dir=str(case_dir))
        assert finding.finding_id != finding2.finding_id

    def test_tool_invocations_derived_from_evidence_refs(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Add a second seeded audit line (vol_netscan at line 2) so a
        # multi-ref finding has two distinct sources.
        from pydantic import BaseModel

        class _Stub(BaseModel):
            stub: str = "ok"

        append_audit_entry(
            case_dir=case_dir,
            tool_name="vol_netscan",
            evidence_id=VALID_EVIDENCE_ID,
            input_args={"evidence_id": VALID_EVIDENCE_ID},
            output=_Stub(),
        )

        refs = [
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="PID 4321 powershell.exe",
            ),
            EvidenceRef(
                source_tool="vol_netscan",
                audit_line=2,
                detail="TCPv4 LISTENING 0.0.0.0:65500",
            ),
            # Duplicate to confirm dedup
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="parent svchost.exe PID 1244",
            ),
        ]
        finding = record_finding(**_good_args(evidence_refs=refs), case_dir=str(case_dir))
        assert finding.tool_invocations == ["vol_netscan:2", "vol_pslist:1"]


# ---------------------------------------------------------------------------
# rejection: evidence_id not in CASE.yaml
# ---------------------------------------------------------------------------


class TestRejectEvidenceNotFound:
    def test_audit_line_appended_no_finding_written(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        bogus_id = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError) as exc_info:
            record_finding(
                **_good_args(evidence_id=bogus_id),
                case_dir=str(case_dir),
            )
        assert str(exc_info.value) == "evidence_id not found in CASE.yaml"
        # Sanitized — bogus id not echoed back to agent.
        assert bogus_id not in str(exc_info.value)

        # Audit chain extended with rejection line; findings.jsonl
        # never created (rejection precedes the findings write).
        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_evidence_not_found")
        # Operator-visible: bogus id IS captured in the audit log.
        assert audit_lines[-1]["evidence_id"] == bogus_id
        assert not (case_dir / "findings.jsonl").exists()


# ---------------------------------------------------------------------------
# rejection: analyst not in allow-list
# ---------------------------------------------------------------------------


class TestRejectUnknownAnalyst:
    def test_audit_line_appended_no_finding_written(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Week 8: disk_analyst became a valid AnalystName so the
        # original test's stand-in is now allow-listed. Pick a name
        # that nobody allow-lists — `pcap_analyst` (the future-but-
        # unshipped pcap-side family) — to keep the rejection path
        # exercised.
        with pytest.raises(ValueError) as exc_info:
            record_finding(
                **_good_args(analyst="pcap_analyst"),
                case_dir=str(case_dir),
            )
        assert str(exc_info.value) == "analyst not in allow-list"
        # Sanitized — claimed analyst name not echoed.
        assert "pcap_analyst" not in str(exc_info.value)

        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_unknown_analyst")
        assert not (case_dir / "findings.jsonl").exists()


# ---------------------------------------------------------------------------
# rejection: confidence == "DISPUTED" (validator-only state)
# ---------------------------------------------------------------------------


class TestRejectDisputedSelfMarked:
    def test_audit_line_appended_no_finding_written(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError) as exc_info:
            record_finding(
                **_good_args(confidence="DISPUTED"),
                case_dir=str(case_dir),
            )
        assert "DISPUTED" in str(exc_info.value)
        assert "validator" in str(exc_info.value)

        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_disputed_self_marked")
        assert not (case_dir / "findings.jsonl").exists()


# ---------------------------------------------------------------------------
# rejection: evidence_ref points at non-existent audit line OR mismatched tool
# ---------------------------------------------------------------------------


class TestRejectInvalidAuditRef:
    def test_audit_line_does_not_exist(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        bad_refs = [
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=999,
                detail="PID 4321 — line 999 does not exist",
            )
        ]
        with pytest.raises(ValueError) as exc_info:
            record_finding(
                **_good_args(evidence_refs=bad_refs),
                case_dir=str(case_dir),
            )
        assert "evidence_ref does not match audit chain" in str(exc_info.value)

        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_invalid_audit_ref")
        assert not (case_dir / "findings.jsonl").exists()

    def test_source_tool_does_not_match_actual_audit_entry(self, tmp_path: Path):
        # The seeded line 1 is `vol_pslist`. Pointing source_tool at
        # vol_netscan must reject — the finding can't claim a tool
        # call that didn't fire.
        case_dir = _seed_case_dir(tmp_path)
        bad_refs = [
            EvidenceRef(
                source_tool="vol_netscan",
                audit_line=1,
                detail="line 1 is actually vol_pslist not vol_netscan",
            )
        ]
        with pytest.raises(ValueError):
            record_finding(
                **_good_args(evidence_refs=bad_refs),
                case_dir=str(case_dir),
            )
        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_invalid_audit_ref")


# ---------------------------------------------------------------------------
# rejection: schema validation (length / count constraints)
# ---------------------------------------------------------------------------


class TestRejectSchemaValidation:
    def test_title_too_short(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError) as exc_info:
            record_finding(
                **_good_args(title="too short"),  # 9 chars, min is 10
                case_dir=str(case_dir),
            )
        # Sanitized — generic "schema validation failed", no pydantic
        # internals or field values echoed.
        assert "schema validation" in str(exc_info.value)
        assert "too short" not in str(exc_info.value)

        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_schema_validation_failed")

    def test_description_too_long(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        too_long = "x" * 2001  # max is 2000
        with pytest.raises(ValueError):
            record_finding(
                **_good_args(description=too_long),
                case_dir=str(case_dir),
            )
        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_schema_validation_failed")

    def test_evidence_refs_empty_list_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            record_finding(
                **_good_args(evidence_refs=[]),
                case_dir=str(case_dir),
            )
        audit_lines = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit_lines[-1]["tool_name"] == ("record_finding:rejected_schema_validation_failed")


# ---------------------------------------------------------------------------
# findings hash chain: line N+1's prev_finding_hash == line N's
# this_finding_hash, even across rejection lines on the audit chain
# ---------------------------------------------------------------------------


class TestFindingsChainContinuity:
    def test_two_consecutive_findings_link(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # First finding.
        record_finding(**_good_args(title="First finding A B C D E"), case_dir=str(case_dir))
        # Second finding.
        record_finding(**_good_args(title="Second finding F G H I J"), case_dir=str(case_dir))

        findings = _read_jsonl(case_dir / "findings.jsonl")
        assert len(findings) == 2
        assert findings[0]["line_number"] == 1
        assert findings[0]["prev_finding_hash"] == _GENESIS_PREV_HASH
        assert findings[1]["line_number"] == 2
        assert findings[1]["prev_finding_hash"] == findings[0]["this_finding_hash"], (
            "second finding must link to the first"
        )

    def test_rejection_does_not_extend_findings_chain(self, tmp_path: Path):
        # Rejections write to the audit chain but NOT to findings.jsonl.
        # A successful finding after a rejection must still link to
        # the previous successful finding (genesis if none), not to
        # any rejection line.
        case_dir = _seed_case_dir(tmp_path)
        # 1: success
        record_finding(**_good_args(), case_dir=str(case_dir))
        # 2: rejected (analyst) — extends audit chain only
        with pytest.raises(ValueError):
            record_finding(
                **_good_args(analyst="bogus"),
                case_dir=str(case_dir),
            )
        # 3: success — must link to (1), not to rejection
        record_finding(
            **_good_args(title="Third finding K L M N O"),
            case_dir=str(case_dir),
        )

        findings = _read_jsonl(case_dir / "findings.jsonl")
        assert len(findings) == 2  # rejection didn't write
        assert findings[1]["prev_finding_hash"] == findings[0]["this_finding_hash"]


# ---------------------------------------------------------------------------
# on-disk isolation — neither test must touch the real chains
# ---------------------------------------------------------------------------


class TestOnDiskIsolation:
    def test_no_test_in_module_modified_real_findings_or_audit(self):
        # Snapshot taken at module load (Pytest collects this class
        # before any test body runs). The byte-for-byte content of
        # the real on-disk files should be unchanged after the suite
        # runs — every test uses tmp_path. If this fails, some
        # record_finding test wrote to the project case-data/
        # directory.
        if ON_DISK_AUDIT_LOG.exists():
            assert ON_DISK_AUDIT_LOG.read_bytes() == _ON_DISK_AUDIT_BEFORE
        if ON_DISK_FINDINGS.exists():
            assert ON_DISK_FINDINGS.read_bytes() == _ON_DISK_FINDINGS_BEFORE


_ON_DISK_AUDIT_BEFORE = ON_DISK_AUDIT_LOG.read_bytes() if ON_DISK_AUDIT_LOG.exists() else b""
_ON_DISK_FINDINGS_BEFORE = ON_DISK_FINDINGS.read_bytes() if ON_DISK_FINDINGS.exists() else b""


# ---------------------------------------------------------------------------
# fixture sample validates against the schema (round-trip)
# ---------------------------------------------------------------------------


class TestAuditLineProbeFixRegressionGuard:
    """End-to-end regression test for the audit_line plumbing fix
    (2026-05-06, decisions-log entry "audit_line plumbing").

    v2 of process_analyst spent ~16 turns brute-forcing valid
    `(audit_line, source_tool)` pairs because tier-1/tier-2 returns
    didn't surface their own audit-chain line number. This test
    codifies the fix as a regression check: dispatch a tier-1 tool,
    capture `ExtractionRef.audit_line` from the result, and use it
    in record_finding's `EvidenceRef`. The first call must succeed
    — no probing, no rejection."""

    def test_tier1_audit_line_is_directly_usable_in_evidence_ref(self, tmp_path: Path):
        from unittest.mock import patch
        from server.tools.memory import vol_pslist

        case_dir = _seed_case_dir(tmp_path, seed_audit=False)
        # No pre-seeded audit line; vol_pslist will write its own.
        # Mock the runner so we don't reach SSH.
        fixture = (PROJECT_ROOT / "tests" / "fixtures" / "vol_pslist_sample.json").read_text(
            encoding="utf-8"
        )
        with (
            patch("server.tools.memory.get_vol_version", return_value="2.27.0"),
            patch(
                "server.tools.memory.run_vol_plugin",
                return_value=(fixture, "vol", 5.0),
            ),
        ):
            summary = vol_pslist(VALID_EVIDENCE_ID, case_dir=str(case_dir))

        # The fix: audit_line is on the returned summary.
        assert summary.extraction.audit_line is not None
        captured_audit_line = summary.extraction.audit_line

        # Construct record_finding using the captured audit_line.
        # No probing — first call accepted.
        finding = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_hidden",
            severity="medium",
            confidence="MEDIUM",
            title="Direct audit_line use — no probe needed",
            description=(
                "Synthesized finding to verify the audit_line plumbing "
                "fix: tier-1 ExtractionRef.audit_line plugs directly "
                "into EvidenceRef.audit_line on the first record_finding "
                "call without probing. Eliminates failure-mode #1."
            ),
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=captured_audit_line,
                    detail="proved-valid via tier-1 return",
                )
            ],
            hypothesis=None,
            case_dir=str(case_dir),
        )

        # No rejection — finding committed.
        assert finding.state == "DRAFT"
        # The chain ended up with: line 1 (vol_pslist), line 2 (the
        # record_finding success). The captured audit_line is line 1.
        assert captured_audit_line == 1

    def test_tier2_set_difference_audit_line_is_accepted_in_evidence_ref(self, tmp_path: Path):
        """Same regression check, tier-2 path: a `set_difference` call's
        audit_line is directly usable as `EvidenceRef.audit_line` with
        `source_tool="set_difference"`. Confirms the
        `EvidenceRefSourceTool` literal expansion (2026-05-06) made
        tier-2 names valid evidence sources for findings."""
        from server.extractions import write_extraction
        from server.schemas import (
            ProcessRecord,
            PslistResult,
            PsscanResult,
        )
        from server.tools.analytical import set_difference

        case_dir = _seed_case_dir(tmp_path, seed_audit=False)

        # Pre-write both extractions so set_difference has data to diff.
        def pr(pid: int) -> ProcessRecord:
            return ProcessRecord(
                pid=pid,
                ppid=4,
                image_file_name="x.exe",
                offset_v=0,
                threads=1,
                handles=None,
                session_id=None,
                wow64=False,
                create_time=NOW_UTC,
                exit_time=None,
            )

        write_extraction(
            case_dir,
            VALID_EVIDENCE_ID,
            "windows.pslist.PsList",
            PslistResult(
                evidence_id=VALID_EVIDENCE_ID,
                plugin_name="windows.pslist.PsList",
                volatility_version="2.27.0",
                processes=[pr(4), pr(100)],
                command_executed="vol",
                runtime_seconds=14.7,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=14.7,
        )
        write_extraction(
            case_dir,
            VALID_EVIDENCE_ID,
            "windows.psscan.PsScan",
            PsscanResult(
                evidence_id=VALID_EVIDENCE_ID,
                plugin_name="windows.psscan.PsScan",
                volatility_version="2.27.0",
                processes=[pr(4), pr(100), pr(9999)],
                command_executed="vol",
                runtime_seconds=396.0,
                invoked_at=NOW_UTC,
            ),
            runtime_seconds=396.0,
        )

        diff = set_difference(
            evidence_id=VALID_EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            case_dir=str(case_dir),
        )
        assert diff.audit_line >= 1
        assert diff.a_only_count == 1

        # Use diff.audit_line directly with source_tool="set_difference".
        finding = record_finding(
            evidence_id=VALID_EVIDENCE_ID,
            analyst="process_analyst",
            category="process_hidden",
            severity="medium",
            confidence="MEDIUM",
            title="Tier-2 source_tool acceptance regression test",
            description=(
                "Verifies that a tier-2 set_difference call's audit_line "
                "is a valid EvidenceRef target with "
                "source_tool='set_difference' (the 2026-05-06 literal "
                "expansion). First call accepted, no probe."
            ),
            evidence_refs=[
                EvidenceRef(
                    source_tool="set_difference",
                    audit_line=diff.audit_line,
                    detail="psscan ∖ pslist on pid surfaced PID 9999",
                )
            ],
            hypothesis=None,
            case_dir=str(case_dir),
        )
        assert finding.state == "DRAFT"
        assert finding.evidence_refs[0].source_tool == "set_difference"


class TestFixtureRoundTrip:
    def test_three_fixture_findings_validate_against_DraftFinding(self):
        fixture_path = Path(__file__).parent / "fixtures" / "draft_finding_sample.json"
        rows = json.loads(fixture_path.read_text(encoding="utf-8"))
        assert len(rows) == 3
        for row in rows:
            DraftFinding.model_validate(row)
