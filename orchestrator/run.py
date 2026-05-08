"""Legacy single-evidence CLI entrypoint.

Backward-compat shim for week 6 / 7 invocations:

    python -m orchestrator.run \\
        --case-dir case-data \\
        --evidence-id 6770da81-f562-4643-b1d2-69d78104fb70

Equivalent to the new subcommand form
``python -m orchestrator.main run --evidence-id ...``. New work
should prefer the subcommand form so the multi-evidence
``run-case`` path is one CLI away.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from orchestrator.loop import LoopOutcome, run_loop


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orchestrator.run",
        description="Drive the SIFT-Guard 5-step self-correction loop.",
    )
    p.add_argument(
        "--case-dir",
        type=Path,
        default=Path("case-data"),
        help="Path to the case directory (contains CASE.yaml, evidence/, "
        "extractions/, findings.jsonl, correlations.jsonl, audit/).",
    )
    p.add_argument(
        "--evidence-id",
        required=True,
        help="UUIDv4 of the registered evidence to drive the loop against.",
    )
    p.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Hard cap on loop iterations (safety net).",
    )
    p.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Override the default 500K-token uncached budget for R_c.",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p


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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    case_dir = args.case_dir.resolve()
    if not (case_dir / "CASE.yaml").exists():
        print(
            f"error: CASE.yaml not found under {case_dir}", file=sys.stderr
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


if __name__ == "__main__":
    raise SystemExit(main())
