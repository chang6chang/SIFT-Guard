"""Smoke tests for sift_guard.display + the loop's `on_progress` hook.

Verifies:

  - `ProgressDisplay.on_event` formats every documented event without
    raising, even when the orchestrator emits it from a worker
    thread.
  - The audit-tail thread reads new lines as they appear and renders
    a subset of MCP tool calls.
  - The loop's `on_progress` callback fires with the expected event
    sequence for a synthetic single-iteration multi-host run.
  - The summary renderer produces the expected line shape.
"""

from __future__ import annotations

import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from orchestrator.dispatch import DispatchResult
from orchestrator.loop import run_loop_multi_host
from orchestrator.manifest import (
    CaseManifest,
    EvidenceFile,
    HostEvidence,
)
from sift_guard.display import ProgressDisplay


_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


def _stream_lines(buf: io.StringIO) -> list[str]:
    return [line for line in buf.getvalue().splitlines() if line.strip()]


def test_progress_display_handles_full_event_sequence(tmp_path: Path):
    buf = io.StringIO()
    display = ProgressDisplay(tmp_path, stream=buf)

    events = [
        ("iteration_start", {"iteration": 1, "max_iterations": 6, "pending_host_ids": None}),
        ("analyze_start", {"host_label": "nfury", "analyst": "process_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "nfury",
                "analyst": "process_analyst",
                "findings_added": 5,
                "tokens_uncached": 38_000,
                "duration_ms": 75_000,
                "succeeded": True,
            },
        ),
        ("correlate_start", {"draft_findings": 5, "host_count": 1}),
        (
            "correlate_done",
            {
                "correlations_added": 2,
                "cross_host": 0,
                "tokens_uncached": 12_000,
                "duration_ms": 30_000,
                "succeeded": True,
            },
        ),
        ("promote", {"rule_counts": {"R1": 2, "R3": 3}, "applied": 5, "total": 5}),
        ("plan", {"decision": "terminate", "next_host_ids": [], "followups_consumed": 0}),
        (
            "iteration_done",
            {
                "iteration": 1,
                "tokens_uncached": 50_000,
                "cumulative_tokens_uncached": 50_000,
                "findings_added": 5,
                "correlations_added": 2,
                "promotions_applied": 5,
            },
        ),
        ("terminate", {"reason": "R_a_zero_unresolved"}),
        # Unknown event should not raise; it's ignored unless verbose.
        ("phantom_event", {"x": 1}),
    ]
    for ev, payload in events:
        display.on_event(ev, payload)

    out = buf.getvalue()
    assert "Iteration 1/6" in out
    assert "ANALYZE" in out and "process_analyst" in out
    assert "CORRELATE" in out
    assert "PROMOTE" in out and "R1 × 2, R3 × 3" in out
    assert "TERMINATE" in out and "R_a_zero_unresolved" in out


def test_progress_display_audit_tail_renders_new_lines(tmp_path: Path):
    case_dir = tmp_path / "case-data"
    audit_dir = case_dir / "audit"
    audit_dir.mkdir(parents=True)
    audit_path = audit_dir / "sift-guard-mcp.jsonl"
    audit_path.write_text("", encoding="utf-8")

    buf = io.StringIO()
    display = ProgressDisplay(case_dir, stream=buf)
    display.start_audit_tail()
    try:
        # Simulate the MCP server appending two interesting lines.
        new_entries = [
            {
                "tool_name": "vol_pslist",
                "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
                "input_args": {"evidence_id": "..."},
                "line_number": 1,
            },
            {
                "tool_name": "rag_query",
                "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
                "input_args": {"semantic_query": "T1014 rootkit"},
                "output": {"hits": [{"technique_id": "T1014"}]},
                "line_number": 2,
            },
        ]
        with audit_path.open("a", encoding="utf-8") as f:
            for e in new_entries:
                f.write(json.dumps(e) + "\n")
                f.flush()
        # Give the tail thread a chance to pick up the writes.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if "vol_pslist" in buf.getvalue() and "rag_query" in buf.getvalue():
                break
            time.sleep(0.1)
    finally:
        display.stop_audit_tail()

    out = buf.getvalue()
    assert "vol_pslist" in out
    assert "rag_query" in out
    assert "T1014" in out


def test_loop_emits_expected_event_sequence(tmp_path: Path):
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    (case_dir / "audit").mkdir()
    case_yaml = (
        "case_id: test-case\n"
        "evidence:\n"
        "  - evidence_id: 550e8400-e29b-41d4-a716-446655440000\n"
        "    original_filename: a.raw\n"
        "    absolute_path: " + str(case_dir / "evidence" / "a.raw") + "\n"
        "    sha256: " + ("a" * 64) + "\n"
        "    size_bytes: 1024\n"
        "    artifact_class: memory_image\n"
        "    registered_at: " + _NOW.isoformat() + "\n"
        "    file_mode_after_registration: '0o444'\n"
    )
    (case_dir / "CASE.yaml").write_text(case_yaml, encoding="utf-8")

    manifest = CaseManifest(
        case_id="test-case",
        hosts=[
            HostEvidence(
                host_id="hostA",
                host_label="hostA",
                evidence_files=[
                    EvidenceFile(
                        evidence_id="550e8400-e29b-41d4-a716-446655440000",
                        file_path=str(case_dir / "evidence" / "a.raw"),
                        evidence_type="memory",
                        os_guess=None,
                        file_size_bytes=1024,
                    )
                ],
            )
        ],
        created_at=_NOW,
    )

    def _fake_dispatch_analyst(**kwargs):
        return DispatchResult(
            agent=kwargs["agent"],
            session_id="s",
            stop_reason="end_turn",
            num_turns=1,
            duration_ms=5000,
            duration_api_ms=4500,
            total_cost_usd=0.0,
            input_tokens=100,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
            output_tokens=50,
            tokens_uncached=150,
            final_text="",
            raw_events=[],
        )

    def _fake_dispatch_validator(**kwargs):
        return DispatchResult(
            agent="validator",
            session_id="s",
            stop_reason="end_turn",
            num_turns=1,
            duration_ms=3000,
            duration_api_ms=2500,
            total_cost_usd=0.0,
            input_tokens=200,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
            output_tokens=100,
            tokens_uncached=300,
            final_text="",
            raw_events=[],
        )

    captured: list[tuple[str, dict]] = []

    def on_progress(event: str, payload: dict) -> None:
        captured.append((event, payload))

    # update_finding shouldn't try to spawn a real MCP subprocess in
    # this synthetic run.
    with patch("orchestrator.loop._call_update_finding", return_value={}):
        run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=_fake_dispatch_analyst,
            dispatch_validator_fn=_fake_dispatch_validator,
            on_progress=on_progress,
        )

    event_names = [name for name, _ in captured]
    assert event_names[0] == "iteration_start"
    assert "analyze_start" in event_names
    assert "analyze_done" in event_names
    # No DRAFT findings produced (the dispatch is mocked), so
    # correlate_skip fires instead of correlate_start/done.
    assert "correlate_skip" in event_names or "correlate_start" in event_names
    assert "promote" in event_names
    # max_iterations=1 → terminate event at the end
    assert event_names[-1] == "terminate"


def test_render_summary_includes_expected_fields(tmp_path: Path):
    buf = io.StringIO()
    display = ProgressDisplay(tmp_path, stream=buf)
    display.render_summary(
        host_count=4,
        confidence_counts={"HIGH": 22, "MEDIUM": 9, "LOW": 6, "DISPUTED": 8},
        cross_host_count=10,
        iteration_count=2,
        termination_reason="R_b_disputed_set_unchanged",
        runtime_seconds=1499.0,
        report_paths=[tmp_path / "report.md", tmp_path / "report.json"],
    )
    out = buf.getvalue()
    assert "Hosts analyzed:     4" in out
    assert "22 HIGH" in out
    assert "Cross-host:         10 correlation(s)" in out
    assert "Termination:        R_b_disputed_set_unchanged" in out
    assert "Runtime:            24m 59s" in out
    assert "report.md" in out
    assert "report.json" in out
