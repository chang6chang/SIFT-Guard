"""Unit tests for `server.tools.findings.update_finding`.

Five rejection paths each get an audit-on-rejection line; the
happy path writes one findings.jsonl UPDATE entry + one audit line;
the findings hash chain links to its predecessor (and the predecessor
might be a DRAFT or a prior UPDATE — both kinds participate in the
same chain); server-controlled fields (`update_id`, `created_at`,
`audit_line`, `previous_state`, `previous_confidence`) are not
agent-supplied.

State-transition rules:

  - DRAFT → DRAFT   allowed (re-iteration without promotion)
  - DRAFT → CONFIRMED  allowed (the canonical promotion)
  - CONFIRMED → CONFIRMED  allowed (re-confirmation, no-op-shaped)
  - CONFIRMED → DRAFT  REJECTED (orchestrator does not un-confirm)

Audit-byte isolation: every test uses a tmp_path-rooted case dir.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel

from server.audit import append_audit_entry
from server.correlations_log import append_correlation_entry
from server.findings_log import append_finding_entry
from server.schemas import (
    CorroboratesCorrelation,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
)
from server.tools.findings import update_finding


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"
ON_DISK_FINDINGS = PROJECT_ROOT / "case-data" / "findings.jsonl"
ON_DISK_CORRELATIONS = PROJECT_ROOT / "case-data" / "correlations.jsonl"

VALID_EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
VALID_SHA256 = "eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563"
NOW_UTC = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
FID = "11111111-1111-4111-8111-111111111111"
CID = "33333333-3333-4333-8333-333333333333"


def _seed_case_dir(
    tmp_path: Path, *, draft_confidence: str = "MEDIUM",
    draft_state: str = "DRAFT",
) -> Path:
    """Set up a case dir with one DraftFinding (FID), one
    CorroboratesCorrelation (CID), and a seeded audit chain."""
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

    # Audit line 1: vol_pslist
    append_audit_entry(
        case_dir=case_dir,
        tool_name="vol_pslist",
        evidence_id=VALID_EVIDENCE_ID,
        input_args={"evidence_id": VALID_EVIDENCE_ID},
        output=_Stub(),
    )

    # Findings line 1: a DraftFinding for this id
    finding = DraftFinding(
        finding_id=FID,
        evidence_id=VALID_EVIDENCE_ID,
        analyst="process_analyst",
        state=draft_state,  # type: ignore[arg-type]
        category="process_hidden",
        severity="medium",
        confidence=draft_confidence,  # type: ignore[arg-type]
        title="Seeded finding for update_finding tests",
        description=(
            "Synthetic DraftFinding seeded by the test fixture. The "
            "actual finding content is irrelevant; the test only "
            "needs the id + state + confidence to exist in "
            "findings.jsonl so update_finding can resolve them."
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

    # Correlations line 1: a CorroboratesCorrelation for this id
    corr = CorroboratesCorrelation(
        correlation_id=CID,
        case_id="case-rocba",
        iteration_number=0,
        created_at=NOW_UTC,
        audit_line=1,
        evidence_refs=[
            EvidenceRef(
                source_tool="vol_pslist",
                audit_line=1,
                detail="corroborating evidence",
            )
        ],
        hypothesis=(
            "Two analyst findings agree on the same target — this is "
            "a corroborated cluster the orchestrator can promote."
        ),
        target_finding_ids=[FID],
        strength="strong",
    )
    append_correlation_entry(case_dir, corr)

    return case_dir


def _good_args(**overrides):
    args = dict(
        finding_id=FID,
        iteration_number=1,
        new_state="CONFIRMED",
        new_confidence="HIGH",
        promotion_rule="R3",
        driving_correlation_ids=[CID],
        orchestrator_version="orchestrator-v0.1",
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
# Happy paths — one per promotion rule R1..R6
# ---------------------------------------------------------------------------


class TestUpdateFindingHappyPaths:
    @pytest.mark.parametrize("rule", ["R1", "R2", "R3", "R4", "R5", "R6"])
    def test_each_promotion_rule_succeeds(self, tmp_path: Path, rule: str):
        case_dir = _seed_case_dir(tmp_path)
        result = update_finding(
            **_good_args(promotion_rule=rule), case_dir=str(case_dir)
        )
        assert result.promotion_rule == rule
        assert result.previous_state == "DRAFT"
        assert result.previous_confidence == "MEDIUM"
        assert result.new_state == "CONFIRMED"
        assert result.new_confidence == "HIGH"

        # findings.jsonl now has DRAFT + UPDATE
        rows = _read_jsonl(case_dir / "findings.jsonl")
        assert len(rows) == 2
        assert rows[0]["finding"]["record_kind"] == "draft"
        assert rows[1]["finding"]["record_kind"] == "update"
        # Hash chain links across kinds
        assert rows[1]["prev_finding_hash"] == rows[0]["this_finding_hash"]

        # Audit chain extended with success line
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == "update_finding"


# ---------------------------------------------------------------------------
# Server-derived previous_state and previous_confidence
# ---------------------------------------------------------------------------


class TestServerDerivedPrevious:
    def test_previous_fields_from_chain_not_args(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path, draft_confidence="LOW")
        result = update_finding(
            **_good_args(new_confidence="MEDIUM"), case_dir=str(case_dir)
        )
        # previous_confidence is read from the seeded DRAFT (LOW),
        # not anything the caller supplied.
        assert result.previous_confidence == "LOW"
        assert result.new_confidence == "MEDIUM"

    def test_chained_updates_use_latest_prior_update(self, tmp_path: Path):
        # First update (DRAFT/MEDIUM) → DRAFT/HIGH (re-iteration without
        # promoting state).
        case_dir = _seed_case_dir(tmp_path)
        first = update_finding(
            **_good_args(
                new_state="DRAFT",
                new_confidence="HIGH",
                promotion_rule="R1",
            ),
            case_dir=str(case_dir),
        )
        assert first.previous_state == "DRAFT"
        assert first.previous_confidence == "MEDIUM"

        # Second update reads the FIRST update's new_* as the new
        # previous_*, not the original DRAFT's values.
        second = update_finding(
            **_good_args(
                new_state="CONFIRMED",
                new_confidence="HIGH",
                promotion_rule="R3",
            ),
            case_dir=str(case_dir),
        )
        assert second.previous_state == "DRAFT"
        assert second.previous_confidence == "HIGH"


# ---------------------------------------------------------------------------
# Rejection: unknown finding_id
# ---------------------------------------------------------------------------


class TestRejectUnknownFinding:
    def test_audit_line_appended_no_chain_growth(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        unknown = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError):
            update_finding(
                **_good_args(finding_id=unknown),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "update_finding:rejected_unknown_finding"
        )
        # findings.jsonl unchanged: still 1 entry (the seeded DRAFT).
        rows = _read_jsonl(case_dir / "findings.jsonl")
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Rejection: unknown correlation_id
# ---------------------------------------------------------------------------


class TestRejectUnknownCorrelation:
    def test_audit_line_appended_no_chain_growth(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        unknown = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError):
            update_finding(
                **_good_args(driving_correlation_ids=[unknown]),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "update_finding:rejected_unknown_correlation"
        )


# ---------------------------------------------------------------------------
# Rejection: unknown promotion_rule
# ---------------------------------------------------------------------------


class TestRejectUnknownRule:
    def test_audit_line_appended_no_chain_growth(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        with pytest.raises(ValueError):
            update_finding(
                **_good_args(promotion_rule="R7"),  # not in R1..R6
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "update_finding:rejected_unknown_rule"
        )


# ---------------------------------------------------------------------------
# Rejection: invalid state transition (CONFIRMED → DRAFT)
# ---------------------------------------------------------------------------


class TestRejectInvalidStateTransition:
    def test_confirmed_to_draft_rejected(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        # First, CONFIRM the finding.
        update_finding(
            **_good_args(new_state="CONFIRMED", new_confidence="HIGH"),
            case_dir=str(case_dir),
        )
        # Now try to walk it back to DRAFT — must reject.
        with pytest.raises(ValueError):
            update_finding(
                **_good_args(new_state="DRAFT", new_confidence="MEDIUM"),
                case_dir=str(case_dir),
            )
        audit = _read_jsonl(case_dir / "audit" / "sift-guard-mcp.jsonl")
        assert audit[-1]["tool_name"] == (
            "update_finding:rejected_invalid_state_transition"
        )
        # Chain didn't grow on the rejection (still has DRAFT + 1 UPDATE).
        rows = _read_jsonl(case_dir / "findings.jsonl")
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# Chain continuity in findings.jsonl across DRAFT + UPDATE entries
# ---------------------------------------------------------------------------


class TestChainContinuity:
    def test_draft_plus_two_updates_link_correctly(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        update_finding(
            **_good_args(new_state="DRAFT", new_confidence="HIGH",
                         promotion_rule="R1"),
            case_dir=str(case_dir),
        )
        update_finding(
            **_good_args(new_state="CONFIRMED", new_confidence="HIGH",
                         promotion_rule="R3"),
            case_dir=str(case_dir),
        )
        rows = _read_jsonl(case_dir / "findings.jsonl")
        assert len(rows) == 3
        assert rows[0]["finding"]["record_kind"] == "draft"
        assert rows[1]["finding"]["record_kind"] == "update"
        assert rows[2]["finding"]["record_kind"] == "update"
        # Hash chain links across all kinds.
        assert rows[1]["prev_finding_hash"] == rows[0]["this_finding_hash"]
        assert rows[2]["prev_finding_hash"] == rows[1]["this_finding_hash"]


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
