"""``sift-guard`` — turnkey one-command forensic-analysis CLI.

Default workflow::

    sift-guard analyze /path/to/evidence/folder --output-dir ./results

What this does, in order:

  1. Resolve the case directory (``--output-dir`` or
     ``./results-<UTC-timestamp>``). Evidence is COPIED into
     ``<case_dir>/evidence/<host>/`` (read-only after registration);
     the originals are never modified.
  2. Scan the evidence directory, group by host using filename
     heuristics, and print the manifest table.
  3. Wait 5 s for operator review (``--yes`` to skip).
  4. ``register_evidence`` each file (chmod 444, SHA-256, audit).
  5. Pre-flight: probe each registered memory image's OS and
     symbol-pack availability via local ``vol windows.info.Info`` /
     ``linux.info.Info``.
  6. Drive ``run_loop_multi_host`` with a real-time progress
     display. The orchestrator dispatches Claude Code subagents
     (``claude -p --agent <name>``) — authentication is handled by
     ``claude login``; no ANTHROPIC_API_KEY is required when
     running with a Max subscription.
  7. Generate ``<case_dir>/report.md`` and ``report.json``.
  8. Print summary to stdout.

Exit codes:
  0   success
  2   usage error
  3   no evidence found / registered
  4   Claude Code not on PATH (for ``analyze``; warning for
      ``mock-run`` / ``--scan-only``)
  5   loop crashed
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.inventory import format_inventory_table, scan_evidence_directory
from orchestrator.loop import _default_multi_host_token_budget, run_loop_multi_host
from orchestrator.manifest import (
    CaseManifest,
    EvidenceFile,
    HostEvidence,
    write_manifest,
)
from reporting.summary import build_summary, write_reports
from server.tools.evidence import register_evidence
from sift_guard.display import ProgressDisplay, replay_events
from sift_guard.preflight import preflight_check_image


logger = logging.getLogger(__name__)


_DEFAULT_MAX_ITERATIONS = 6
_DEFAULT_TOKEN_BUDGET = 2_000_000
_DEFAULT_REVIEW_WAIT_SECONDS = 5


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-guard",
        description=(
            "Turnkey forensic-analysis CLI on top of Claude Code. "
            "One command: `sift-guard analyze <evidence-dir>`. "
            "Authentication via `claude login`; no API key needed "
            "for Max subscription users."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logger level for the orchestrator and MCP server. The "
        "real-time progress display is independent of this — it's "
        "always on for `analyze`.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    analyze = sub.add_parser(
        "analyze",
        help=(
            "Analyze every evidence file in a directory. Scans, "
            "registers, runs the multi-host self-correction loop "
            "with real-time progress, and writes report.md / "
            "report.json."
        ),
    )
    analyze.add_argument(
        "evidence_dir",
        type=Path,
        help="Directory containing evidence files (any mix of .raw, "
        ".mem, .vmem, .lime, .001, .E01, .dd, .vhdx, .img, .aff4).",
    )
    analyze.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Where to put the case directory. Default: "
        "./results-<UTC-timestamp>/. Evidence files are COPIED here "
        "and chmod 444'd; originals are never modified.",
    )
    analyze.add_argument(
        "--max-iterations",
        type=int,
        default=_DEFAULT_MAX_ITERATIONS,
        help=f"Hard cap on loop iterations. Default: {_DEFAULT_MAX_ITERATIONS}.",
    )
    analyze.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Override the multi-host token budget heuristic "
        "(500K base + 250K per host, capped at 5M).",
    )
    analyze.add_argument(
        "--yes",
        action="store_true",
        help=f"Skip the {_DEFAULT_REVIEW_WAIT_SECONDS}-second manifest "
        "review pause before registration.",
    )
    analyze.add_argument(
        "--scan-only",
        action="store_true",
        help="Print the manifest table and stop. Useful for "
        "previewing how filenames will be grouped into hosts.",
    )
    analyze.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the per-image OS + symbol-pack pre-flight probe.",
    )
    analyze.add_argument(
        "--no-report",
        action="store_true",
        help="Do not generate report.md / report.json after the loop.",
    )
    analyze.add_argument(
        "--verbose",
        action="store_true",
        help="Emit every MCP tool call to the live display, including "
        "the per-iteration footer. Default: filtered for legibility.",
    )

    mock = sub.add_parser(
        "mock-run",
        help="Replay a synthetic event sequence to demonstrate the "
        "real-time progress display. No subagents dispatched.",
    )
    mock.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Seconds to sleep between events (default: 0 — instant).",
    )

    return parser


def _resolve_case_dir(cli_output_dir: Path | None) -> Path:
    if cli_output_dir is not None:
        return cli_output_dir.resolve()
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (Path.cwd() / f"results-{timestamp}").resolve()


def _stage_evidence(evidence_dir: Path, case_dir: Path) -> int:
    """Copy recognized evidence files into ``case_dir/evidence/<host>/``.

    Re-running with the same evidence_dir is idempotent: existing
    identical files at the destination (size + name match) are left
    alone.
    """
    triples = scan_evidence_directory(evidence_dir)
    target_root = case_dir / "evidence"
    target_root.mkdir(parents=True, exist_ok=True)

    staged = 0
    for host_id, _label, files in triples:
        host_dir = target_root / host_id
        host_dir.mkdir(parents=True, exist_ok=True)
        for path, _evtype, size in files:
            dest = host_dir / path.name
            if dest.exists() and dest.stat().st_size == size:
                staged += 1
                continue
            shutil.copy2(path, dest)
            staged += 1
    return staged


def _build_manifest_from_case_dir(case_dir: Path) -> CaseManifest:
    """Re-scan the staged evidence under case_dir/evidence/ and
    register each file."""
    grouped = scan_evidence_directory(case_dir / "evidence")
    case_id = case_dir.name

    hosts: list[HostEvidence] = []
    for host_id, host_label, files in grouped:
        evidence_files: list[EvidenceFile] = []
        for path, evtype, size in files:
            try:
                record = register_evidence(str(path), case_dir=str(case_dir))
            except (FileNotFoundError, ValueError, PermissionError, OSError) as exc:
                logger.warning("register_evidence failed for %s: %s", path.name, exc)
                continue
            evidence_files.append(
                EvidenceFile(
                    evidence_id=record.evidence_id,
                    file_path=record.absolute_path,
                    evidence_type=evtype,
                    os_guess=None,
                    file_size_bytes=size,
                )
            )
        if evidence_files:
            hosts.append(
                HostEvidence(
                    host_id=host_id,
                    host_label=host_label,
                    evidence_files=evidence_files,
                )
            )

    return CaseManifest(
        case_id=case_id,
        hosts=hosts,
        created_at=datetime.now(tz=timezone.utc),
    )


def _decorate_manifest_with_os_guess(
    manifest: CaseManifest,
    *,
    timestamp_fn=lambda: datetime.now().strftime("%H:%M:%S"),
) -> tuple[CaseManifest, list[str]]:
    """Run the OS pre-flight against every memory image and patch
    the manifest's ``os_guess`` fields. Streams progress to stdout."""
    remediations: list[str] = []
    new_hosts: list[HostEvidence] = []
    for host in manifest.hosts:
        new_files: list[EvidenceFile] = []
        for ef in host.evidence_files:
            if ef.evidence_type != "memory":
                new_files.append(ef)
                continue
            print(
                f"[{timestamp_fn()}] PREFLIGHT │ probing "
                f"{Path(ef.file_path).name}…",
                flush=True,
            )
            result = preflight_check_image(ef.file_path)
            os_guess = result.os_version
            mark = "✓" if result.success else "✗"
            host_label = host.host_label
            if result.success:
                print(
                    f"[{timestamp_fn()}] PREFLIGHT │ "
                    f"{host_label:<14} → {os_guess} {mark}"
                )
            else:
                print(
                    f"[{timestamp_fn()}] PREFLIGHT │ "
                    f"{host_label:<14} → {result.error_message or 'failed'} {mark}"
                )
                if result.remediation:
                    remediations.append(
                        f"{Path(ef.file_path).name}: {result.remediation}"
                    )
            new_files.append(ef.model_copy(update={"os_guess": os_guess}))
        new_hosts.append(host.model_copy(update={"evidence_files": new_files}))
    decorated = manifest.model_copy(update={"hosts": new_hosts})
    return decorated, remediations


def _check_claude_cli_available() -> bool:
    """Return True when `claude` is on PATH."""
    return shutil.which("claude") is not None


def _hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _cmd_analyze(args: argparse.Namespace) -> int:
    evidence_dir = args.evidence_dir.resolve()
    if not evidence_dir.is_dir():
        print(f"error: evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 2

    if not _check_claude_cli_available() and not args.scan_only:
        print(
            "error: `claude` CLI not on PATH. Install Claude Code and run "
            "`claude login`. See https://docs.anthropic.com/en/docs/claude-code "
            "for installation. (Use --scan-only to preview the manifest "
            "without dispatching analysts.)",
            file=sys.stderr,
        )
        return 4

    case_dir = _resolve_case_dir(args.output_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    print(f"[{_hms()}] case directory: {case_dir}")

    print(f"[{_hms()}] Scanning {evidence_dir}…", flush=True)
    staged = _stage_evidence(evidence_dir, case_dir)
    if staged == 0:
        print(
            f"error: no recognized evidence files found under {evidence_dir}",
            file=sys.stderr,
        )
        return 3

    preview_groups = scan_evidence_directory(case_dir / "evidence")
    if not preview_groups:
        print("error: scan turned up no evidence after staging", file=sys.stderr)
        return 3
    preview_hosts = [
        HostEvidence(
            host_id=host_id,
            host_label=host_label,
            evidence_files=[
                EvidenceFile(
                    evidence_id="00000000-0000-4000-8000-000000000000",
                    file_path=str(p),
                    evidence_type=evtype,
                    os_guess=None,
                    file_size_bytes=size,
                )
                for p, evtype, size in files
            ],
        )
        for host_id, host_label, files in preview_groups
    ]
    table = format_inventory_table(preview_hosts)
    if table:
        print()
        print(table)
        print()
    total_files = sum(len(h.evidence_files) for h in preview_hosts)
    print(
        f"[{_hms()}] manifest preview: {len(preview_hosts)} host(s), "
        f"{total_files} file(s)"
    )

    if args.scan_only:
        print("(--scan-only set; not driving the loop)")
        return 0

    if not args.yes:
        print(
            f"[{_hms()}] continuing in {_DEFAULT_REVIEW_WAIT_SECONDS} seconds — "
            "Ctrl-C to abort, --yes to skip this pause"
        )
        time.sleep(_DEFAULT_REVIEW_WAIT_SECONDS)

    print(f"[{_hms()}] Registering evidence (sha256 + chmod 444 + audit chain)…")
    manifest = _build_manifest_from_case_dir(case_dir)
    if not manifest.hosts:
        print("error: no evidence registered successfully", file=sys.stderr)
        return 3
    total_registered = sum(len(h.evidence_files) for h in manifest.hosts)
    print(
        f"[{_hms()}] Registering evidence… {total_registered}/{total_registered} "
        "✓ (SHA-256 verified)"
    )

    if not args.no_preflight:
        manifest, remediations = _decorate_manifest_with_os_guess(manifest)
        if remediations:
            print()
            print("pre-flight diagnostics:")
            for line in remediations:
                print(f"  ! {line}")
            print()

    write_manifest(manifest, case_dir)
    decorated_table = format_inventory_table(manifest.hosts)
    if decorated_table:
        print()
        print(decorated_table)
        print()

    token_budget = args.token_budget
    if token_budget is None:
        token_budget = _default_multi_host_token_budget(len(manifest.hosts))
    print(
        f"[{_hms()}] driving multi-host loop: "
        f"max_iterations={args.max_iterations}, token_budget={token_budget:,}"
    )

    display = ProgressDisplay(case_dir, verbose=args.verbose)
    display.start_audit_tail()
    started_at = time.monotonic()
    try:
        outcome = run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=args.max_iterations,
            token_budget=token_budget,
            on_progress=display.on_event,
        )
    except Exception:
        logger.exception("loop crashed")
        display.stop_audit_tail()
        return 5
    finally:
        # Give the audit tail a tick to flush whatever was just
        # written, then shut it down.
        time.sleep(0.5)
        display.stop_audit_tail()
    runtime_seconds = time.monotonic() - started_at

    report_paths: list[Path] = []
    if not args.no_report:
        written = write_reports(case_dir, formats=("markdown", "json"))
        if written.markdown_path:
            report_paths.append(written.markdown_path)
        if written.json_path:
            report_paths.append(written.json_path)

    summary = build_summary(case_dir)
    display.render_summary(
        host_count=len(summary.findings_by_host),
        confidence_counts=summary.confidence_counts,
        cross_host_count=len(summary.cross_host_correlations),
        iteration_count=len(outcome.iterations),
        termination_reason=outcome.termination_reason,
        runtime_seconds=runtime_seconds,
        report_paths=report_paths,
    )
    print("Done. Hash chain verified ✓")
    return 0


def _cmd_mock_run(args: argparse.Namespace) -> int:
    """Replay a synthetic event sequence so operators can preview
    what real-time output looks like without burning tokens."""

    sample = _sample_events()
    replay_events(sample, delay_seconds=args.delay)
    return 0


def _sample_events() -> list[tuple[str, dict]]:
    """A representative event sequence covering iter-1 → iter-2 →
    R_b convergence on a 4-host case. Used by ``mock-run``."""
    return [
        (
            "iteration_start",
            {"iteration": 1, "max_iterations": 6, "pending_host_ids": None},
        ),
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
        ("analyze_start", {"host_label": "nfury", "analyst": "network_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "nfury",
                "analyst": "network_analyst",
                "findings_added": 3,
                "tokens_uncached": 22_000,
                "duration_ms": 70_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "nromanoff", "analyst": "process_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "nromanoff",
                "analyst": "process_analyst",
                "findings_added": 4,
                "tokens_uncached": 31_000,
                "duration_ms": 68_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "nromanoff", "analyst": "network_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "nromanoff",
                "analyst": "network_analyst",
                "findings_added": 2,
                "tokens_uncached": 19_000,
                "duration_ms": 55_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "controller", "analyst": "process_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "controller",
                "analyst": "process_analyst",
                "findings_added": 6,
                "tokens_uncached": 41_000,
                "duration_ms": 84_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "controller", "analyst": "network_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "controller",
                "analyst": "network_analyst",
                "findings_added": 4,
                "tokens_uncached": 25_000,
                "duration_ms": 60_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "xp-tdungan", "analyst": "process_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "xp-tdungan",
                "analyst": "process_analyst",
                "findings_added": 3,
                "tokens_uncached": 26_000,
                "duration_ms": 58_000,
                "succeeded": True,
            },
        ),
        ("analyze_start", {"host_label": "xp-tdungan", "analyst": "network_analyst"}),
        (
            "analyze_done",
            {
                "host_label": "xp-tdungan",
                "analyst": "network_analyst",
                "findings_added": 2,
                "tokens_uncached": 18_000,
                "duration_ms": 52_000,
                "succeeded": True,
            },
        ),
        ("correlate_start", {"draft_findings": 29, "host_count": 4}),
        (
            "correlate_done",
            {
                "correlations_added": 15,
                "cross_host": 4,
                "tokens_uncached": 90_000,
                "duration_ms": 120_000,
                "succeeded": True,
            },
        ),
        (
            "promote",
            {"rule_counts": {"R1": 5, "R3": 10, "R4": 3, "R6": 11}, "applied": 18, "total": 29},
        ),
        ("plan", {"decision": "continue", "next_host_ids": ["nfury"], "followups_consumed": 1}),
        (
            "iteration_done",
            {
                "iteration": 1,
                "tokens_uncached": 410_000,
                "cumulative_tokens_uncached": 410_000,
                "findings_added": 29,
                "correlations_added": 15,
                "promotions_applied": 18,
            },
        ),
        (
            "iteration_start",
            {
                "iteration": 2,
                "max_iterations": 6,
                "pending_host_ids": ["nfury"],
            },
        ),
        (
            "analyze_start",
            {
                "host_label": "nfury",
                "analyst": "process_analyst",
                "focused": True,
            },
        ),
        (
            "analyze_done",
            {
                "host_label": "nfury",
                "analyst": "process_analyst",
                "findings_added": 1,
                "tokens_uncached": 18_000,
                "duration_ms": 45_000,
                "succeeded": True,
            },
        ),
        ("correlate_start", {"draft_findings": 12, "host_count": 1}),
        (
            "correlate_done",
            {
                "correlations_added": 3,
                "cross_host": 0,
                "tokens_uncached": 28_000,
                "duration_ms": 40_000,
                "succeeded": True,
            },
        ),
        (
            "promote",
            {"rule_counts": {"R5": 2, "R6": 10}, "applied": 2, "total": 12},
        ),
        ("plan", {"decision": "terminate", "next_host_ids": [], "followups_consumed": 0}),
        (
            "iteration_done",
            {
                "iteration": 2,
                "tokens_uncached": 46_000,
                "cumulative_tokens_uncached": 456_000,
                "findings_added": 1,
                "correlations_added": 3,
                "promotions_applied": 2,
            },
        ),
        ("terminate", {"reason": "R_b_disputed_set_unchanged"}),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.subcommand == "analyze":
        return _cmd_analyze(args)
    if args.subcommand == "mock-run":
        return _cmd_mock_run(args)
    parser.error(f"unknown subcommand {args.subcommand!r}")
    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
