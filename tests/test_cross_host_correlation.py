"""Tests for the `cross_host` correlation type — schema-level
validation + the dispatcher wiring inside record_correlation."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from server.schemas import (
    CorrelationType,
    CrossHostCorrelation,
    EvidenceRef,
)
from server.tools.correlations import _build_payload


NOW_UTC = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)


def _refs() -> list[EvidenceRef]:
    return [
        EvidenceRef(
            source_tool="vol_netscan",
            audit_line=1,
            detail="pid 7900 holds 10.3.58.42:443",
        )
    ]


class TestCrossHostSchema:
    def test_correlation_type_enum_includes_cross_host(self):
        assert CorrelationType.CROSS_HOST.value == "cross_host"

    def test_minimum_two_host_ids_required(self):
        with pytest.raises(Exception):
            CrossHostCorrelation(
                correlation_id=str(uuid4()),
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis=(
                    "Two findings on different hosts share the same "
                    "outbound IP — multi-host indicator."
                ),
                target_finding_ids=[str(uuid4()), str(uuid4())],
                host_ids=["nfury"],  # only one host — schema rejects
                shared_indicator={"type": "ip", "value": "10.3.58.42"},
                strength="strong",
            )

    def test_distinct_host_invariant(self):
        # Two host_ids but same value → not actually cross-host.
        with pytest.raises(Exception):
            CrossHostCorrelation(
                correlation_id=str(uuid4()),
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis=(
                    "Two findings on different hosts share the same "
                    "outbound IP — multi-host indicator."
                ),
                target_finding_ids=[str(uuid4()), str(uuid4())],
                host_ids=["nfury", "nfury"],  # not distinct
                shared_indicator={"type": "ip", "value": "10.3.58.42"},
                strength="strong",
            )

    def test_target_finding_ids_must_be_uuid_v4(self):
        with pytest.raises(Exception):
            CrossHostCorrelation(
                correlation_id=str(uuid4()),
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis=(
                    "Two findings on different hosts share the same "
                    "outbound IP — multi-host indicator."
                ),
                target_finding_ids=["not-a-uuid", str(uuid4())],
                host_ids=["nfury", "controller"],
                shared_indicator={"type": "ip", "value": "10.3.58.42"},
                strength="strong",
            )

    def test_minimum_two_target_finding_ids_required(self):
        with pytest.raises(Exception):
            CrossHostCorrelation(
                correlation_id=str(uuid4()),
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis=(
                    "Two findings on different hosts share the same "
                    "outbound IP — multi-host indicator."
                ),
                target_finding_ids=[str(uuid4())],  # only one
                host_ids=["nfury", "controller"],
                shared_indicator={"type": "ip", "value": "10.3.58.42"},
                strength="strong",
            )

    def test_happy_path_round_trips_via_json(self):
        c = CrossHostCorrelation(
            correlation_id=str(uuid4()),
            case_id="case-data",
            iteration_number=1,
            created_at=NOW_UTC,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Two findings on different hosts share the same outbound "
                "IP 10.3.58.42 — RDP-style lateral movement indicator."
            ),
            target_finding_ids=[str(uuid4()), str(uuid4())],
            host_ids=["nfury", "controller"],
            shared_indicator={"type": "ip", "value": "10.3.58.42"},
            strength="strong",
        )
        blob = c.model_dump_json()
        c2 = CrossHostCorrelation.model_validate_json(blob)
        assert c2.correlation_type == "cross_host"
        assert sorted(c2.host_ids) == ["controller", "nfury"]
        assert c2.shared_indicator["value"] == "10.3.58.42"


class TestBuildPayloadDispatch:
    def test_cross_host_branch_constructs_correlation(self):
        f1 = str(uuid4())
        f2 = str(uuid4())
        payload = _build_payload(
            correlation_id=str(uuid4()),
            correlation_type="cross_host",
            case_id="case-data",
            iteration_number=1,
            created_at=NOW_UTC,
            audit_line=1,
            evidence_refs=_refs(),
            hypothesis=(
                "Two findings on different hosts share the same outbound "
                "IP 10.3.58.42 — multi-host indicator."
            ),
            target_finding_ids=[f1, f2],
            finding_a_id=None,
            finding_b_id=None,
            target_finding_id=None,
            strength="strong",
            severity=None,
            resolvable_by_followup=None,
            target_analyst=None,
            related_finding_ids=None,
            focus_context=None,
            rationale=None,
            host_ids=["nfury", "controller"],
            shared_indicator={"type": "ip", "value": "10.3.58.42"},
        )
        assert isinstance(payload, CrossHostCorrelation)
        assert payload.target_finding_ids == [f1, f2]
        assert payload.host_ids == ["nfury", "controller"]

    def test_cross_host_rejects_extra_fields(self):
        with pytest.raises(ValueError):
            _build_payload(
                correlation_id=str(uuid4()),
                correlation_type="cross_host",
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis="x" * 60,
                target_finding_ids=[str(uuid4()), str(uuid4())],
                finding_a_id=str(uuid4()),  # not allowed for cross_host
                finding_b_id=None,
                target_finding_id=None,
                strength="strong",
                severity=None,
                resolvable_by_followup=None,
                target_analyst=None,
                related_finding_ids=None,
                focus_context=None,
                rationale=None,
                host_ids=["nfury", "controller"],
                shared_indicator=None,
            )

    def test_cross_host_requires_host_ids_and_strength(self):
        with pytest.raises(ValueError):
            _build_payload(
                correlation_id=str(uuid4()),
                correlation_type="cross_host",
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis="x" * 60,
                target_finding_ids=[str(uuid4()), str(uuid4())],
                finding_a_id=None,
                finding_b_id=None,
                target_finding_id=None,
                strength=None,  # missing
                severity=None,
                resolvable_by_followup=None,
                target_analyst=None,
                related_finding_ids=None,
                focus_context=None,
                rationale=None,
                host_ids=["nfury", "controller"],
                shared_indicator=None,
            )

    def test_corroborates_rejects_host_ids(self):
        # Existing types must reject the new fields — the per-type
        # extra-field check is what enforces this.
        with pytest.raises(ValueError):
            _build_payload(
                correlation_id=str(uuid4()),
                correlation_type="corroborates",
                case_id="case-data",
                iteration_number=1,
                created_at=NOW_UTC,
                audit_line=1,
                evidence_refs=_refs(),
                hypothesis="x" * 60,
                target_finding_ids=[str(uuid4())],
                finding_a_id=None,
                finding_b_id=None,
                target_finding_id=None,
                strength="strong",
                severity=None,
                resolvable_by_followup=None,
                target_analyst=None,
                related_finding_ids=None,
                focus_context=None,
                rationale=None,
                host_ids=["nfury", "controller"],  # not allowed
                shared_indicator=None,
            )
