"""Unit tests for `server.tools.correlations.record_correlation`.

Five rejection paths each get an audit-on-rejection line; the
happy path writes one correlations.jsonl line + one audit line; the
correlations hash chain links to its predecessor; server-controlled
fields (`correlation_id`, `created_at`, `audit_line`) are not
agent-supplied; pydantic Literal / length / required-field
constraints are enforced and audited as
`record_correlation:rejected_invalid_payload`.

Audit-byte isolation: every test uses a tmp_path-rooted case dir.
The on-disk correlations.jsonl, findings.jsonl, and audit log are
read once at module-load time and asserted unchanged at the end of
the suite.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel

from server.audit import append_audit_entry
from server.findings_log import append_finding_entry
from server.schemas import (
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.correlations import record_correlation


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"
ON_DISK_FINDINGS = PROJECT_ROOT / "case-data" / "findings.jsonl"
ON_DISK_CORRELATIONS = PROJECT_ROOT / "case-data" / "correlations.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
FID_A = "11111111-1111-4111-8111-111111111111"
FID_B = "22222222-2222-4222-8222-222222222222"


def _seed_case_dir(tmp_path: Path) -> Path:
    """Build a tmp case dir with CASE.yaml (case_id="case-rocba"),
    one DraftFinding (finding_id=FID_A), and a seeded audit chain.

    The audit chain after seeding has lines:
      1: vol_pslist (so a vol_pslist EvidenceRef at line 1 is valid)
      2: record_finding success (the seeded DraftFinding's audit line)

    Tests that need a second finding-id seed it via `_seed_finding`.
    """
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()

    fake_evidence = evidence_dir / "Rocba-Memory.raw"
    fake_evidence.write_bytes(b"\x00" * 1024)

    record = EvidenceRecord(
        evidence_id=VALID_EVIDENCE_ID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(fake_evidence),
        sha256=VALID_SHA256,
        size_bytes=1024,
        artifact_class="memory_image",
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": "case-rocba",
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))

    class _Stub(BaseModel):
        stub: str = "ok"

    # Line 1: vol_pslist
    append_audit_entry(
        case_dir=case_dir,
        tool_name="vol_pslist",
        evidence_id=VALID_EVIDENCE_ID,
        input_args={"evidence_id": VALID_EVIDENCE_ID},
        output=_Stub(),
    )

    # Seed one DraftFinding so target_finding_ids has something to
    # resolve against.
    finding = DraftFinding(
        finding_id=FID_A,
        evidence_id=VALID_EVIDENCE_ID,
        analyst="process_analyst",
        state="DRAFT",
        category="process_hidden",
        severity="medium",
        confidence="MEDIUM",
        title="Seeded finding for correlation tests",
        description=(
            "Synthetic DraftFinding seeded by the test fixture to "
            "support record_correlation tests. The actual finding "
            "content is irrelevant; the test only needs the id to "
            "exist in findings.jsonl."
        ),
        evidence_refs=[
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="seeded finding",
            )
        ],
        created_at=NOW_UTC,
        tool_invocations=["vol_pslist:1"],
    )
    append_finding_entry(case_dir, finding)
    # Line 2: synthetic record_finding audit so the chain mirrors
    # the live tool's audit trail.
    append_audit_entry(
        case_dir=case_dir,
        tool_name="record_finding",
        evidence_id=VALID_EVIDENCE_ID,
        input_args={"evidence_id": VALID_EVIDENCE_ID},
        output=_Stub(),
    )

    return case_dir


def _seed_finding(case_dir: Path, finding_id: str) -> None:
    finding = DraftFinding(
        finding_id=finding_id,
        evidence_id=VALID_EVIDENCE_ID,
        analyst="network_analyst",
        state="DRAFT",
        category="network_anomaly",
        severity="medium",
        confidence="MEDIUM",
        title="Second seeded finding ABCDEFG",
        description=(
            "Second synthetic DraftFinding for tests that need two "
            "finding-ids resolvable in findings.jsonl (e.g., the "
            "contradicts correlation needs finding_a_id + finding_b_id)."
        ),
        evidence_refs=[
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="second finding",
            )
        ],
        created_at=NOW_UTC,
        tool_invocations=["vol_pslist:1"],
    )
    append_finding_entry(case_dir, finding)


def _refs() -> list[EvidenceRef]:
    return [
        EvidenceRef(
            source_tool="vol_pslist",
            audit_line=1,
            detail="seed line for tests",
        )
    ]


def _good_corroborates(**overrides):
    args = dict(
        case_id="case-rocba",
        iteration_number=0,
        correlation_type="corroborates",
        evidence_refs=_refs(),
        hypothesis=(
            "Two analyst findings agree on the same target — this is "
            "the substantive cross-source pattern."
        ),
        target_finding_ids=[FID_A],
        strength="strong",
    )
    args.update(overrides)
    return args


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(l)
        for l in path.read_text().splitlines()
        if l.strip()
    ]


# ---------------------------------------------------------------------------
# Happy paths — one per correlation type
# ---------------------------------------------------------------------------


class TestRecordCorrelationHappyPaths:
    def test_corroborates_writes_chain_and_audit(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = record_correlation(
            **_good_corroborates(), case_dir=str(case_dir)
        )

        # Chain
        rows = _read_jsonl(case_dir / "correlations.jsonl")
        assert len(rows) == 1
        assert rows[0]["correlation"]["correlation_type"] == "corroborates"
        assert rows[0]["correlation"]["correlation_id"] == result.correlation_id
        assert rows[0]["correlation"]["target_finding_ids"] == [FID_A]
        assert rows[0]["correlation"]["strength"] == "strong"

        # Audit chain extended with success line
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "record_correlation"

    def test_contradicts_writes_correctly(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_finding(case_dir, FID_B)
        result = record_correlation(
            case_id="case-rocba",
            iteration_number=1,
            correlation_type="contradicts",
            evidence_refs=_refs(),
            hypothesis=(
                "Two analyst findings make incompatible claims about "
                "the same artifact — needs orchestrator resolution."
            ),
            finding_a_id=FID_A,
            finding_b_id=FID_B,
            severity="material",
            resolvable_by_followup=True,
            case_dir=str(case_dir),
        )
        assert result.correlation_type == "contradicts"
        assert result.severity == "material"

    def test_strengthens_writes_correctly(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = record_correlation(
            case_id="case-rocba",
            iteration_number=0,
            correlation_type="strengthens",
            evidence_refs=_refs(),
            hypothesis=(
                "One new tier-2 query shifts the existing finding's "
                "confidence upward without rising to the bar of "
                "corroborates."
            ),
            target_finding_id=FID_A,
            case_dir=str(case_dir),
        )
        assert result.correlation_type == "strengthens"
        assert result.target_finding_id == FID_A

    def test_weakens_writes_correctly(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = record_correlation(
            case_id="case-rocba",
            iteration_number=0,
            correlation_type="weakens",
            evidence_refs=_refs(),
            hypothesis=(
                "One new tier-2 query softens the existing finding's "
                "confidence without rising to the bar of contradicts."
            ),
            target_finding_id=FID_A,
            case_dir=str(case_dir),
        )
        assert result.correlation_type == "weakens"

    def test_request_followup_writes_correctly(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        result = record_correlation(
            case_id="case-rocba",
            iteration_number=1,
            correlation_type="request_followup",
            evidence_refs=_refs(),
            hypothesis=(
                "The existing finding needs handles + DLL coverage to "
                "promote; current pslist record alone is ambiguous."
            ),
            target_analyst="process_analyst",
            related_finding_ids=[FID_A],
            focus_context={"pids": [7900], "image_names": ["svchost.exe"]},
            rationale="Re-run process_analyst with focus on PID 7900 handles.",
            case_dir=str(case_dir),
        )
        assert result.correlation_type == "request_followup"
        assert result.target_analyst == "process_analyst"
        assert result.focus_context == {
            "pids": [7900],
            "image_names": ["svchost.exe"],
        }

    def test_evidence_ref_with_rag_query_source_tool_accepted(
        self, tmp_path: Path
    ):
        """Week 7 G-2 regression: a correlation citing a rag_query
        audit line in evidence_refs must validate. The validator
        runs rag_query to ground a hypothesis in a named MITRE
        technique, then references the call's audit_line in the
        correlation's EvidenceRef. The audit-chain validator
        requires the line's tool_name to match the ref's
        source_tool — adding "rag_query" to EvidenceRefSourceTool
        must cover the round-trip without further changes.
        """
        case_dir = _seed_case_dir(tmp_path)

        # Append a synthetic rag_query success line to the audit
        # chain. Live tests/test_rag_query.py exercise the real tool
        # against the FAISS index; here we only need a chain entry
        # whose tool_name is "rag_query" so the EvidenceRef
        # validator finds a match.
        class _Stub(BaseModel):
            stub: str = "ok"

        append_audit_entry(
            case_dir=case_dir,
            tool_name="rag_query",
            evidence_id=None,
            input_args={"technique_id": "T1055"},
            output=_Stub(),
        )
        # Chain after this append: line 1 vol_pslist, line 2
        # record_finding, line 3 rag_query.
        rag_audit_line = 3

        result = record_correlation(
            case_id="case-rocba",
            iteration_number=1,
            correlation_type="corroborates",
            evidence_refs=[
                EvidenceRef(
                    source_tool="vol_pslist",
                    audit_line=1,
                    detail="seeded process-side observation",
                ),
                EvidenceRef(
                    source_tool="rag_query",
                    audit_line=rag_audit_line,
                    detail=(
                        "T1055 (Process Injection) retrieved at "
                        "rank 1, similarity_score=1.0"
                    ),
                ),
            ],
            hypothesis=(
                "The process_hidden finding maps onto MITRE T1055 "
                "(Process Injection); the validator's independent "
                "rag_query lookup confirms the technique-id match."
            ),
            target_finding_ids=[FID_A],
            strength="moderate",
            case_dir=str(case_dir),
        )
        # The correlation lands in the chain; one of its
        # evidence_refs cites the rag_query audit line.
        assert result.correlation_type == "corroborates"
        ref_sources = {ref.source_tool for ref in result.evidence_refs}
        assert "rag_query" in ref_sources

        # Audit chain extends with the record_correlation success
        # line (the call validated and wrote).
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "record_correlation"


# ---------------------------------------------------------------------------
# Server-controlled fields are not agent-supplied
# ---------------------------------------------------------------------------


class TestServerControlledFields:
    def test_correlation_id_created_at_audit_line_set_by_server(
        self, tmp_path: Path
    ):
        case_dir = _seed_case_dir(tmp_path)
        before = datetime.now(tz=timezone.utc)
        result = record_correlation(
            **_good_corroborates(), case_dir=str(case_dir)
        )
        after = datetime.now(tz=timezone.utc)

        # UUIDv4 shape (version nibble == "4")
        assert result.correlation_id[14] == "4"
        # Timestamps are real, in-range, UTC.
        assert before <= result.created_at <= after
        # audit_line is the line of the SUCCESS audit entry; on a
        # fresh case dir the seed produced 4 audit lines (vol_pslist,
        # record_finding success, record_finding success-from-seed-call,
        # …) — the seed in _seed_case_dir produces 3: line 1
        # vol_pslist, line 2 from append_finding_entry's audit (no, the
        # seed test calls append_finding_entry which doesn't write
        # audit — we manually appended record_finding at line 2).
        # So this call's success lands at line 3.
        assert result.audit_line >= 3


# ---------------------------------------------------------------------------
# Rejection: unknown correlation_type
# ---------------------------------------------------------------------------


class TestRejectUnknownType:
    def test_audit_line_appended_no_chain_growth(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError) as exc:
            record_correlation(
                **_good_corroborates(correlation_type="bogus"),
                case_dir=str(case_dir),
            )
        assert "correlation_type" in str(exc.value)
        # Sanitized
        assert "bogus" not in str(exc.value)

        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_unknown_type"
        )
        assert not (case_dir / "correlations.jsonl").exists()


# ---------------------------------------------------------------------------
# Rejection: case_id mismatch
# ---------------------------------------------------------------------------


class TestRejectUnknownCaseId:
    def test_audit_line_appended_no_chain_growth(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(case_id="some-other-case"),
                case_dir=str(case_dir),
            )

        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_unknown_case_id"
        )
        assert not (case_dir / "correlations.jsonl").exists()


# ---------------------------------------------------------------------------
# Rejection: invalid evidence_ref (line not in audit chain or tool mismatch)
# ---------------------------------------------------------------------------


class TestRejectInvalidAuditRef:
    def test_audit_line_does_not_exist(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        bad = [
            EvidenceRef(
                source_tool="vol_pslist", audit_line=999,
                detail="line 999 doesn't exist",
            )
        ]
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(evidence_refs=bad),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_audit_ref"
        )

    def test_source_tool_does_not_match_audit_entry(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # Line 1 is vol_pslist; pointing source_tool="vol_netscan"
        # at line 1 must reject.
        bad = [
            EvidenceRef(
                source_tool="vol_netscan", audit_line=1,
                detail="line 1 is actually vol_pslist",
            )
        ]
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(evidence_refs=bad),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_audit_ref"
        )


# ---------------------------------------------------------------------------
# Rejection: invalid payload (per-type required-field check)
# ---------------------------------------------------------------------------


class TestRejectInvalidPayload:
    def test_corroborates_without_strength_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(strength=None),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_payload"
        )

    def test_contradicts_with_corroborates_field_rejected(
        self, tmp_path: Path
    ):
        # Cross-type field overflow: contradicts must not accept
        # target_finding_ids (corroborates' field).
        case_dir = _seed_case_dir(tmp_path)
        _seed_finding(case_dir, FID_B)
        with pytest.raises(ValueError):
            record_correlation(
                case_id="case-rocba",
                iteration_number=0,
                correlation_type="contradicts",
                evidence_refs=_refs(),
                hypothesis="Cross-type field overflow regression check.",
                target_finding_ids=[FID_A],  # belongs to corroborates only
                finding_a_id=FID_A,
                finding_b_id=FID_B,
                severity="minor",
                resolvable_by_followup=False,
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_payload"
        )

    def test_request_followup_without_rationale_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            record_correlation(
                case_id="case-rocba",
                iteration_number=1,
                correlation_type="request_followup",
                evidence_refs=_refs(),
                hypothesis="Test that rationale is required for request_followup.",
                target_analyst="process_analyst",
                related_finding_ids=[FID_A],
                focus_context={"pids": [7900]},
                # rationale=None — required, missing
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_payload"
        )

    def test_short_hypothesis_rejected(self, tmp_path: Path):
        # min_length on hypothesis is 50; pydantic ValidationError
        # surfaces as `:rejected_invalid_payload`.
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(hypothesis="too short"),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_invalid_payload"
        )


# ---------------------------------------------------------------------------
# Rejection: referenced finding_id not in findings.jsonl
# ---------------------------------------------------------------------------


class TestRejectUnknownFinding:
    def test_target_finding_id_not_in_chain(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        unknown = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError):
            record_correlation(
                **_good_corroborates(target_finding_ids=[unknown]),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "record_correlation:rejected_unknown_finding"
        )
        # Chain unchanged.
        assert not (case_dir / "correlations.jsonl").exists()


# ---------------------------------------------------------------------------
# Chain continuity across two consecutive successful calls
# ---------------------------------------------------------------------------


class TestChainContinuity:
    def test_two_consecutive_correlations_link(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        record_correlation(
            **_good_corroborates(), case_dir=str(case_dir)
        )
        record_correlation(
            **_good_corroborates(strength="moderate"), case_dir=str(case_dir)
        )
        rows = _read_jsonl(case_dir / "correlations.jsonl")
        assert len(rows) == 2
        assert rows[1]["prev_correlation_hash"] == rows[0]["this_correlation_hash"]


# ---------------------------------------------------------------------------
# On-disk byte isolation
# ---------------------------------------------------------------------------


class TestOnDiskIsolation:
    def test_real_chains_unchanged(self):
        if ON_DISK_AUDIT_LOG.exists():
            assert ON_DISK_AUDIT_LOG.read_bytes() == _ON_DISK_AUDIT_BEFORE
        if ON_DISK_FINDINGS.exists():
            assert ON_DISK_FINDINGS.read_bytes() == _ON_DISK_FINDINGS_BEFORE
        if ON_DISK_CORRELATIONS.exists():
            assert ON_DISK_CORRELATIONS.read_bytes() == _ON_DISK_CORRELATIONS_BEFORE


_ON_DISK_AUDIT_BEFORE = (
    ON_DISK_AUDIT_LOG.read_bytes() if ON_DISK_AUDIT_LOG.exists() else b""
)
_ON_DISK_FINDINGS_BEFORE = (
    ON_DISK_FINDINGS.read_bytes() if ON_DISK_FINDINGS.exists() else b""
)
_ON_DISK_CORRELATIONS_BEFORE = (
    ON_DISK_CORRELATIONS.read_bytes() if ON_DISK_CORRELATIONS.exists() else b""
)
