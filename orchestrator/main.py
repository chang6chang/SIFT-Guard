"""CLI entrypoint with subcommand routing.

Two subcommands:

    python -m orchestrator.main run --evidence-id <uuid>
    python -m orchestrator.main run-case --evidence-dir <path>

Subcommand summaries
--------------------

`run` — single-evidence orchestration. Drives the original 5-step
self-correction loop against one registered `evidence_id`. The
findings written by analysts in this mode have `host_id=None`. This
is the unchanged contract from week 6.

`run-case` — multi-evidence orchestration. Scans an evidence
directory, registers each found file via `register_evidence`,
auto-groups files by host using filename heuristics + magic-byte
detection, persists a `manifest.json` next to `CASE.yaml`, prints
a summary table, and drives `run_loop_multi_host` over the resulting
`CaseManifest`. Findings written by analysts in this mode carry the
host_id the orchestrator injected via the dispatch prompt.

Token budget defaults differ between modes:
  - run        — 500K (the existing R_c threshold)
  - run-case   — 500K + 250K × host_count (capped at 5M); override
                 with `--token-budget`.

Per CLAUDE.md "Hard Rule" #3, `register_evidence` requires the
candidate path live under `<case_dir>/evidence/`. `run-case` does
not bypass this — files outside that tree are rejected with a
sanitized error from the registration tool. The recommended layout
is `<case_dir>/evidence/<host>/<file>` so `--evidence-dir` is the
case-specific subdirectory the operator wants the loop to run
against.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.inventory import (
    format_inventory_table,
    scan_evidence_directory,
)
from orchestrator.loop import (
    LoopOutcome,
    _default_multi_host_token_budget,
    run_loop,
    run_loop_multi_host,
)
from orchestrator.manifest import (
    CaseManifest,
    EvidenceFile,
    HostEvidence,
    write_manifest,
)
from server.tools.evidence import register_evidence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orchestrator.main",
        description=(
            "SIFT-Guard self-correction-loop CLI. Two subcommands: "
            "`run` (single-evidence) and `run-case` (multi-evidence)."
        ),
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # --- run ---
    run_p = sub.add_parser(
        "run",
        help="Drive the loop against one registered evidence_id.",
    )
    run_p.add_argument(
        "--case-dir",
        type=Path,
        default=Path("case-data"),
        help="Path to the case directory (contains CASE.yaml, "
        "evidence/, extractions/, findings.jsonl, "
        "correlations.jsonl, audit/).",
    )
    run_p.add_argument(
        "--evidence-id",
        required=True,
        help="UUIDv4 of the registered evidence to drive the loop against.",
    )
    run_p.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Hard cap on loop iterations (safety net).",
    )
    run_p.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Override the default 500K-token uncached budget for R_c.",
    )
    run_p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    # --- run-case ---
    runcase_p = sub.add_parser(
        "run-case",
        help="Multi-evidence orchestration. Scans a directory, "
        "registers each evidence file, builds a manifest, and "
        "drives the multi-host loop.",
    )
    runcase_p.add_argument(
        "--case-dir",
        type=Path,
        default=Path("case-data"),
    )
    runcase_p.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="Directory to scan for evidence files (recursive). "
        "Must live under <case_dir>/evidence/ for register_evidence "
        "to accept the candidates.",
    )
    runcase_p.add_argument(
        "--max-iterations",
        type=int,
        default=10,
    )
    runcase_p.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Override the default multi-host budget (500K + 250K × host_count, capped at 5M).",
    )
    runcase_p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    runcase_p.add_argument(
        "--scan-only",
        action="store_true",
        help="Run the scan + register + manifest write pass and "
        "stop without driving the loop. Useful for previewing the "
        "host grouping before committing to a full run.",
    )

    return parser


def _print_summary(outcome: LoopOutcome) -> None:
    print()
    print("=" * 68)
    print(f"  termination_reason: {outcome.termination_reason}")
    print(f"  iterations:         {len(outcome.iterations)}")
    print(f"  cumulative_tokens:  {outcome.cumulative_tokens_uncached:,}")
    print("=" * 68)
    for entry in outcome.iterations:
        it = entry.iteration
        print(
            f"  iter {it.iteration_number:>2}: "
            f"analysts={','.join(it.analysts_dispatched) or '-'} "
            f"new_findings={len(it.analyst_findings_added)} "
            f"new_correlations={len(it.validator_correlations_added)} "
            f"promotions={sum(1 for p in it.promotions_made if p.applied)}"
            f" / {len(it.promotions_made)} "
            f"tokens={it.tokens_used_uncached:,}"
        )
        for prom in it.promotions_made:
            applied_tag = "*" if prom.applied else " "
            print(
                f"      {applied_tag} {prom.promotion_rule}: "
                f"{prom.finding_id[:8]} → {prom.new_state}/{prom.new_confidence}"
            )
    print()


def _cmd_run(args: argparse.Namespace) -> int:
    """Single-evidence subcommand. Mirrors the legacy entrypoint
    exactly — adding subcommand routing here did not change the
    inner contract."""
    case_dir = args.case_dir.resolve()
    if not (case_dir / "CASE.yaml").exists():
        print(
            f"error: CASE.yaml not found under {case_dir}",
            file=sys.stderr,
        )
        return 2

    kwargs = dict(
        case_dir=case_dir,
        evidence_id=args.evidence_id,
        max_iterations=args.max_iterations,
    )
    if args.token_budget is not None:
        kwargs["token_budget"] = args.token_budget

    outcome = run_loop(**kwargs)
    _print_summary(outcome)
    return 0


def _build_manifest_from_scan(
    *,
    case_dir: Path,
    evidence_dir: Path,
) -> CaseManifest:
    """Scan `evidence_dir`, register each found file, return a
    populated `CaseManifest`. Files that fail registration are
    surfaced as warnings on stderr and skipped (the operator's
    intent in run-case mode is best-effort onboarding).

    `case_id` follows the existing convention: the basename of
    `case_dir`.
    """
    grouped = scan_evidence_directory(evidence_dir)
    case_id = case_dir.name

    hosts: list[HostEvidence] = []
    for host_id, host_label, files in grouped:
        evidence_files: list[EvidenceFile] = []
        for path, evtype, size in files:
            try:
                record = register_evidence(str(path), case_dir=str(case_dir))
            except (
                FileNotFoundError,
                ValueError,
                PermissionError,
                OSError,
            ) as exc:
                print(
                    f"warning: register_evidence failed for {path.name}: {exc}",
                    file=sys.stderr,
                )
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


def _cmd_run_case(args: argparse.Namespace) -> int:
    """Multi-evidence subcommand. Five steps:

    1. Scan the evidence directory.
    2. register_evidence each found file (skip + warn on
       per-file failures; CLAUDE.md path confinement applies).
    3. Build + persist the manifest.
    4. Print the summary table to stdout for operator review.
    5. Drive `run_loop_multi_host` (unless --scan-only).
    """
    case_dir = args.case_dir.resolve()
    evidence_dir = args.evidence_dir.resolve()
    if not case_dir.exists():
        print(f"error: case_dir does not exist: {case_dir}", file=sys.stderr)
        return 2
    if not evidence_dir.exists():
        print(
            f"error: evidence_dir does not exist: {evidence_dir}",
            file=sys.stderr,
        )
        return 2

    manifest = _build_manifest_from_scan(case_dir=case_dir, evidence_dir=evidence_dir)
    if not manifest.hosts:
        print(
            f"error: no evidence files found / registered under {evidence_dir}",
            file=sys.stderr,
        )
        return 3

    write_manifest(manifest, case_dir)

    table = format_inventory_table(manifest.hosts)
    if table:
        print(table)
        print()
    print(f"manifest: {len(manifest.hosts)} host(s), {manifest.evidence_count} evidence file(s)")

    if args.scan_only:
        print("(--scan-only set; not driving the loop)")
        return 0

    kwargs = dict(
        case_dir=case_dir,
        manifest=manifest,
        max_iterations=args.max_iterations,
    )
    if args.token_budget is not None:
        kwargs["token_budget"] = args.token_budget
    else:
        kwargs["token_budget"] = _default_multi_host_token_budget(len(manifest.hosts))

    outcome = run_loop_multi_host(**kwargs)
    _print_summary(outcome)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.subcommand == "run":
        return _cmd_run(args)
    if args.subcommand == "run-case":
        return _cmd_run_case(args)
    parser.error(f"unknown subcommand {args.subcommand!r}")
    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
