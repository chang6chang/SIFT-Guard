"""``sift-guard`` — single-command turnkey CLI.

Default workflow::

    sift-guard analyze /path/to/evidence/folder

What this does, in order:

  1. Load ``sift-guard.yaml`` (CLI ``--config`` > auto-discover).
     CLI flags always win over config values.
  2. Set up the case directory (``--output-dir`` or
     ``$PWD/results-<timestamp>``). Evidence is COPIED into
     ``<case_dir>/evidence/`` (read-only after registration);
     the originals are never modified.
  3. Scan the evidence directory, group by host using filename
     heuristics, and print the manifest table.
  4. Wait 5 s for operator review (skipped with ``--yes``).
  5. ``register_evidence`` each file (chmod 444, SHA-256, audit).
  6. Pre-flight: probe each registered memory image's OS and
     symbol-pack availability, decorate the manifest.
  7. Drive ``run_loop_multi_host``.
  8. Generate ``<case_dir>/report.md`` and ``report.json``.
  9. Print summary to stdout.

Exit codes:
  0   success
  2   usage error (missing args, bad paths)
  3   no evidence found / registered
  4   pre-flight failed (missing symbols / vol not installed)
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
from reporting.summary import write_reports
from server.tools.evidence import register_evidence
from sift_guard.config import Config, apply_to_environment, load_config
from sift_guard.preflight import preflight_check_image


logger = logging.getLogger(__name__)


_DEFAULT_MAX_ITERATIONS = 6
_DEFAULT_REVIEW_WAIT_SECONDS = 5


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-guard",
        description=(
            "Turnkey forensic-analysis appliance over the SIFT-Guard "
            "MCP server. One command: `sift-guard analyze "
            "<evidence-dir>`. Findings + audit chains land under "
            "the output directory."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Explicit path to a sift-guard.yaml file. "
        "Without this flag, sift-guard auto-discovers ./sift-guard.yaml, "
        "~/.config/sift-guard.yaml, /etc/sift-guard.yaml in that order.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    analyze = sub.add_parser(
        "analyze",
        help=(
            "Analyze every evidence file in a directory. Scans, "
            "registers, runs the multi-host self-correction loop, "
            "and writes report.md / report.json."
        ),
    )
    analyze.add_argument(
        "evidence_dir",
        type=Path,
        help="Directory containing evidence files (any mix of .raw, "
        ".mem, .vmem, .lime, .001, .E01, .dd, .vhdx, .vhd, .img, "
        ".vmdk, .qcow2, .vdi).",
    )
    analyze.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Where to put the case directory. Default: "
        "./results-<timestamp>/. The evidence files are COPIED into "
        "<output-dir>/evidence/ and chmod 444'd; the originals are "
        "never modified.",
    )
    analyze.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help=f"Hard cap on loop iterations. Default: {_DEFAULT_MAX_ITERATIONS}.",
    )
    analyze.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Override the default multi-host token budget "
        "(500K base + 250K per host, capped at 5M).",
    )
    analyze.add_argument(
        "--model",
        default=None,
        help="Override the Claude model used by the analyst / "
        "validator subagents (sets ANTHROPIC_MODEL).",
    )
    analyze.add_argument(
        "--yes",
        action="store_true",
        help="Skip the 5-second manifest review pause and proceed "
        "directly to registration + analysis.",
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

    return parser


def _resolve_output_dir(
    cli_output_dir: Path | None, config: Config
) -> Path:
    if cli_output_dir is not None:
        return cli_output_dir.resolve()
    if config.output.dir:
        return Path(config.output.dir).resolve()
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (Path.cwd() / f"results-{timestamp}").resolve()


def _stage_evidence(
    evidence_dir: Path,
    case_dir: Path,
) -> int:
    """Copy evidence_dir's recognized files into case_dir/evidence/.

    Returns the number of files staged. Re-running with the same
    evidence_dir is idempotent: existing identical files at the
    destination are left alone (size + name match).

    The scanner is single-source-of-truth on what counts as a
    recognized evidence file, so we re-use it here rather than
    inventing a parallel rule.
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
    register each file. Mirrors orchestrator.main._build_manifest_from_scan
    but always operates on the staged copies under <case_dir>/evidence/.
    """
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


def _decorate_manifest_with_os_guess(manifest: CaseManifest) -> tuple[CaseManifest, list[str]]:
    """Run the OS preflight against every memory image and patch
    the manifest's `os_guess` fields in place. Returns the updated
    manifest plus a list of remediation strings for any image that
    failed (caller decides whether to abort)."""
    remediations: list[str] = []
    new_hosts: list[HostEvidence] = []
    for host in manifest.hosts:
        new_files: list[EvidenceFile] = []
        for ef in host.evidence_files:
            if ef.evidence_type != "memory":
                new_files.append(ef)
                continue
            print(f"  preflight: probing {Path(ef.file_path).name} ...", flush=True)
            result = preflight_check_image(ef.file_path)
            os_guess = result.os_version
            if not result.success and result.remediation:
                remediations.append(f"{Path(ef.file_path).name}: {result.remediation}")
            new_files.append(ef.model_copy(update={"os_guess": os_guess}))
        new_hosts.append(host.model_copy(update={"evidence_files": new_files}))
    decorated = manifest.model_copy(update={"hosts": new_hosts})
    return decorated, remediations


def _print_post_run_summary(case_dir: Path, generate_report: bool) -> None:
    if generate_report:
        from reporting.summary import build_summary

        summary = build_summary(case_dir)
        print()
        print("=" * 68)
        print(f"  case:       {summary.case_id}")
        print(f"  hosts:      {len(summary.findings_by_host)}")
        total = sum(summary.confidence_counts.values())
        high = summary.confidence_counts.get("HIGH", 0)
        med = summary.confidence_counts.get("MEDIUM", 0)
        low = summary.confidence_counts.get("LOW", 0)
        disp = summary.confidence_counts.get("DISPUTED", 0)
        print(f"  findings:   {total} (HIGH={high}, MEDIUM={med}, LOW={low}, DISPUTED={disp})")
        print(f"  iterations: {len(summary.iterations)}")
        if summary.termination_reason:
            print(f"  end:        {summary.termination_reason}")
        if summary.cross_host_correlations:
            print(f"  cross-host: {len(summary.cross_host_correlations)} correlation(s)")
        print(f"  output:     {case_dir}")
        print("=" * 68)


def _cmd_analyze(args: argparse.Namespace, config: Config) -> int:
    evidence_dir = args.evidence_dir.resolve()
    if not evidence_dir.is_dir():
        print(f"error: evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 2

    case_dir = _resolve_output_dir(args.output_dir, config)
    case_dir.mkdir(parents=True, exist_ok=True)
    print(f"case directory: {case_dir}")

    print(f"staging evidence from {evidence_dir} ...")
    staged = _stage_evidence(evidence_dir, case_dir)
    if staged == 0:
        print(
            f"error: no recognized evidence files found under {evidence_dir}",
            file=sys.stderr,
        )
        return 3

    # Preview manifest before registration so the operator can ctrl-C
    # if the host grouping looks wrong.
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
    print(f"manifest preview: {len(preview_hosts)} host(s), {total_files} file(s)")

    if args.scan_only:
        print("(--scan-only set; not driving the loop)")
        return 0

    if not args.yes:
        print(
            f"continuing in {_DEFAULT_REVIEW_WAIT_SECONDS} seconds — "
            "Ctrl-C to abort, --yes to skip this pause"
        )
        time.sleep(_DEFAULT_REVIEW_WAIT_SECONDS)

    print("registering evidence (sha256 + chmod 444 + audit chain) ...")
    manifest = _build_manifest_from_case_dir(case_dir)
    if not manifest.hosts:
        print("error: no evidence registered successfully", file=sys.stderr)
        return 3

    if not args.no_preflight:
        print("running per-image pre-flight probe ...")
        manifest, remediations = _decorate_manifest_with_os_guess(manifest)
        if remediations:
            print("\npre-flight diagnostics:")
            for line in remediations:
                print(f"  ! {line}")

    write_manifest(manifest, case_dir)
    decorated_table = format_inventory_table(manifest.hosts)
    if decorated_table:
        print()
        print(decorated_table)
        print()

    max_iterations = (
        args.max_iterations
        or config.analysis.max_iterations
        or _DEFAULT_MAX_ITERATIONS
    )
    token_budget = (
        args.token_budget
        or config.analysis.token_budget
        or _default_multi_host_token_budget(len(manifest.hosts))
    )

    print(
        f"driving multi-host loop: max_iterations={max_iterations}, "
        f"token_budget={token_budget:,}"
    )
    try:
        outcome = run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=max_iterations,
            token_budget=token_budget,
        )
    except Exception:
        logger.exception("loop crashed")
        return 5

    print(
        f"loop terminated: {outcome.termination_reason} "
        f"({len(outcome.iterations)} iterations, "
        f"{outcome.cumulative_tokens_uncached:,} tokens)"
    )

    generate_report = (
        config.output.generate_report and not args.no_report
    )
    if generate_report:
        formats = config.report_formats()
        written = write_reports(case_dir, formats=formats)
        if written.markdown_path:
            print(f"report:     {written.markdown_path}")
        if written.json_path:
            print(f"report:     {written.json_path}")

    _print_post_run_summary(case_dir, generate_report=generate_report)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # CLI flags layer on top of config; apply config-derived env vars
    # before any subcommand consults them.
    apply_to_environment(config)
    if args.subcommand == "analyze" and args.model:
        # CLI override of analysis.model.
        import os as _os

        _os.environ["ANTHROPIC_MODEL"] = args.model

    if args.subcommand == "analyze":
        return _cmd_analyze(args, config)
    parser.error(f"unknown subcommand {args.subcommand!r}")
    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
