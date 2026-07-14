"""SIFT_GUARD_ROLE — server-side role gates on the write/RAG tools.

Frontmatter tool allow-lists restrict what each subagent can call at
the harness layer; these gates make the restriction architectural
(CLAUDE.md Hard Rule #2). Fail-open when the env var is unset —
same convention as SIFT_GUARD_HOST_ID."""

from __future__ import annotations

import pytest

from server.tools.correlations import record_correlation
from server.tools.findings import record_finding, update_finding
from server.tools.rag import rag_query

_ROLE = "SIFT_GUARD_ROLE"


def _record_finding(case_dir, analyst="disk_analyst"):
    return record_finding(
        evidence_id="11111111-1111-4111-8111-111111111111",
        analyst=analyst,
        category="persistence",
        severity="high",
        confidence="HIGH",
        title="t",
        description="d",
        evidence_refs=[],
        case_dir=str(case_dir),
    )


class TestRecordFindingRole:
    def test_role_mismatch_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "network_analyst")
        with pytest.raises(ValueError, match="role"):
            _record_finding(tmp_path, analyst="disk_analyst")

    def test_role_match_passes_gate(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "disk_analyst")
        # Role gate passes; the call then fails downstream on the
        # unregistered evidence_id — proving the gate did not fire.
        with pytest.raises(ValueError, match="evidence_id"):
            _record_finding(tmp_path, analyst="disk_analyst")

    def test_unset_env_is_fail_open(self, tmp_path, monkeypatch):
        monkeypatch.delenv(_ROLE, raising=False)
        with pytest.raises(ValueError, match="evidence_id"):
            _record_finding(tmp_path)

    def test_rejection_is_audited(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "network_analyst")
        with pytest.raises(ValueError):
            _record_finding(tmp_path, analyst="disk_analyst")
        audit = tmp_path / "audit" / "sift-guard-mcp.jsonl"
        assert "record_finding:rejected_role_not_permitted" in audit.read_text()


class TestRecordCorrelationRole:
    def test_non_validator_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "disk_analyst")
        with pytest.raises(ValueError, match="role"):
            record_correlation(
                case_id="c",
                iteration_number=1,
                correlation_type="corroborates",
                evidence_refs=[],
                hypothesis="h",
                case_dir=str(tmp_path),
            )

    def test_validator_passes_gate(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "validator")
        with pytest.raises(ValueError) as exc_info:
            record_correlation(
                case_id="c",
                iteration_number=1,
                correlation_type="corroborates",
                evidence_refs=[],
                hypothesis="h",
                case_dir=str(tmp_path),
            )
        assert "role" not in str(exc_info.value)

    def test_rejection_is_audited(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "process_analyst")
        with pytest.raises(ValueError):
            record_correlation(
                case_id="c",
                iteration_number=1,
                correlation_type="corroborates",
                evidence_refs=[],
                hypothesis="h",
                case_dir=str(tmp_path),
            )
        audit = tmp_path / "audit" / "sift-guard-mcp.jsonl"
        assert "record_correlation:rejected_role_not_permitted" in audit.read_text()


class TestUpdateFindingRole:
    def test_non_orchestrator_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "validator")
        with pytest.raises(ValueError, match="role"):
            update_finding(
                finding_id="f",
                iteration_number=1,
                new_state="CONFIRMED",
                new_confidence="HIGH",
                promotion_rule="R3",
                driving_correlation_ids=["c"],
                orchestrator_version="v",
                case_dir=str(tmp_path),
            )

    def test_orchestrator_passes_gate(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "orchestrator")
        with pytest.raises(ValueError) as exc_info:
            update_finding(
                finding_id="f",
                iteration_number=1,
                new_state="CONFIRMED",
                new_confidence="HIGH",
                promotion_rule="R3",
                driving_correlation_ids=["c"],
                orchestrator_version="v",
                case_dir=str(tmp_path),
            )
        assert "role" not in str(exc_info.value)


class TestRagQueryRole:
    def test_non_validator_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ROLE, "process_analyst")
        with pytest.raises(ValueError, match="role"):
            rag_query(technique_id="T1055", case_dir=str(tmp_path))

    def test_unset_env_is_fail_open(self, tmp_path, monkeypatch):
        monkeypatch.delenv(_ROLE, raising=False)
        # Gate open; fails later (or succeeds) depending on corpus
        # availability — either way, never a role error.
        try:
            rag_query(technique_id="T9999", case_dir=str(tmp_path))
        except Exception as exc:
            assert "role" not in str(exc)
