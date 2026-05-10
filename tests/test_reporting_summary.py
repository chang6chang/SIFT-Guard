"""Smoke tests for `reporting.summary`.

Builds a minimal synthetic case directory with three findings on
two hosts and verifies the summary builder handles host grouping,
confidence counts, iteration parsing, and the markdown / JSON
renderers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from reporting.summary import build_summary, render_json, render_markdown, write_reports


_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


def _hash_payload(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _make_draft(
    *,
    finding_id: str,
    host_id: str | None,
    analyst: str,
    title: str,
    confidence: str,
    severity: str = "high",
    state: str = "DRAFT",
) -> dict:
    return {
        "record_kind": "draft",
        "finding_id": finding_id,
        "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
        "analyst": analyst,
        "state": state,
        "category": "process_hidden",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": "A finding description that is long enough to satisfy the schema validator.",
        "evidence_refs": [
            {
                "source_tool": "vol_pslist",
                "audit_line": 1,
                "detail": "PID 1234 absent from psscan",
            }
        ],
        "hypothesis": "DKOM unlinking pattern.",
        "created_at": _NOW.isoformat(),
        "tool_invocations": ["vol_pslist:1"],
        "host_id": host_id,
    }


def _findings_chain_entry(
    payload: dict,
    line_number: int = 1,
    prev_hash: str = "0" * 64,
) -> dict:
    this_hash = _hash_payload(payload)
    return {
        "line_number": line_number,
        "timestamp": _NOW.isoformat(),
        "finding": payload,
        "prev_finding_hash": prev_hash,
        "this_finding_hash": this_hash,
    }


def _make_iteration_entry(
    iteration_number: int,
    *,
    new_findings: list[str],
    new_correlations: list[str],
    promotions_applied: int,
    termination_decision: str = "continue",
    termination_reasons: dict[str, bool] | None = None,
) -> dict:
    flags = {
        "R_a_zero_unresolved": False,
        "R_b_disputed_set_unchanged": False,
        "R_c_token_budget_exceeded": False,
        "max_iterations_reached": False,
    }
    if termination_reasons:
        flags.update(termination_reasons)
    return {
        "iteration": {
            "iteration_number": iteration_number,
            "started_at": _NOW.isoformat(),
            "completed_at": _NOW.isoformat(),
            "analysts_dispatched": ["process_analyst", "network_analyst"],
            "analyst_findings_added": new_findings,
            "validator_correlations_added": new_correlations,
            "promotions_made": [
                {"finding_id": fid, "applied": True} for fid in new_findings[:promotions_applied]
            ]
            + [
                {"finding_id": fid, "applied": False}
                for fid in new_findings[promotions_applied:]
            ],
            "followup_requests_consumed": [],
            "tokens_used_uncached": 12345,
            "cumulative_tokens_uncached": 12345 * iteration_number,
            "termination_check": {**flags, "decision": termination_decision},
        },
        "prev_iteration_hash": "0" * 64,
        "this_iteration_hash": "f" * 64,
    }


def test_build_summary_empty_case_dir(tmp_path: Path):
    case_dir = tmp_path / "empty"
    case_dir.mkdir()
    summary = build_summary(case_dir)
    assert summary.findings_by_host == {}
    assert summary.confidence_counts == {}
    assert summary.iterations == []
    assert summary.cross_host_correlations == []


def test_build_summary_groups_findings_by_host(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "case_id: synthetic-case\nevidence: []\n", encoding="utf-8"
    )

    fid_a = str(uuid.uuid4())
    fid_b = str(uuid.uuid4())
    fid_c = str(uuid.uuid4())
    chain = [
        _findings_chain_entry(
            _make_draft(
                finding_id=fid_a,
                host_id="hostA",
                analyst="process_analyst",
                title="hostA hidden process",
                confidence="HIGH",
            ),
            line_number=1,
        ),
        _findings_chain_entry(
            _make_draft(
                finding_id=fid_b,
                host_id="hostA",
                analyst="network_analyst",
                title="hostA suspicious outbound",
                confidence="MEDIUM",
                severity="medium",
            ),
            line_number=2,
        ),
        _findings_chain_entry(
            _make_draft(
                finding_id=fid_c,
                host_id="hostB",
                analyst="process_analyst",
                title="hostB injected svchost",
                confidence="LOW",
                severity="low",
            ),
            line_number=3,
        ),
    ]
    (case_dir / "findings.jsonl").write_text(
        "\n".join(json.dumps(e) for e in chain) + "\n", encoding="utf-8"
    )

    iterations = [
        _make_iteration_entry(
            1,
            new_findings=[fid_a, fid_b, fid_c],
            new_correlations=[],
            promotions_applied=2,
        ),
        _make_iteration_entry(
            2,
            new_findings=[],
            new_correlations=[],
            promotions_applied=0,
            termination_decision="terminate",
            termination_reasons={"R_a_zero_unresolved": True},
        ),
    ]
    (case_dir / "iterations.jsonl").write_text(
        "\n".join(json.dumps(e) for e in iterations) + "\n", encoding="utf-8"
    )

    summary = build_summary(case_dir)
    assert summary.case_id == "synthetic-case"
    assert set(summary.findings_by_host) == {"hostA", "hostB"}
    assert summary.confidence_counts == {"HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert summary.state_counts == {"DRAFT": 3}
    assert len(summary.iterations) == 2
    assert summary.termination_reason == "R_a_zero_unresolved"

    # HIGH-confidence finding sorts first within hostA bucket.
    hostA_findings = summary.findings_by_host["hostA"]
    assert hostA_findings[0].confidence == "HIGH"
    assert hostA_findings[1].confidence == "MEDIUM"

    md = render_markdown(summary)
    assert "synthetic-case" in md
    assert "Host: hostA" in md
    assert "Host: hostB" in md
    assert "hostA hidden process" in md
    assert "Iteration summary" in md

    js = json.loads(render_json(summary))
    assert js["case_id"] == "synthetic-case"
    assert js["confidence_counts"]["HIGH"] == 1


def test_write_reports_creates_both_files(tmp_path: Path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "case_id: smoke-case\nevidence: []\n", encoding="utf-8"
    )
    written = write_reports(case_dir)
    assert written.markdown_path is not None and written.markdown_path.exists()
    assert written.json_path is not None and written.json_path.exists()
    md = written.markdown_path.read_text(encoding="utf-8")
    assert "smoke-case" in md
    js = json.loads(written.json_path.read_text(encoding="utf-8"))
    assert js["case_id"] == "smoke-case"
