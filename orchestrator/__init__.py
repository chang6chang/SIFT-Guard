"""SIFT-Guard orchestrator package.

The orchestrator is plain Python — not a Claude Code subagent. It
drives the 5-step self-correction loop on a registered case:

  1. ANALYZE   — dispatch analyst subagents (process, network, ...)
  2. CORRELATE — dispatch the validator subagent
  3. PROMOTE   — apply R1-R6 promotion rules per DRAFT finding
  4. PLAN      — compute termination flags
  5. WRITE     — append IterationRecord to iterations.jsonl

The orchestrator NEVER calls vol_* / tier-2 / record_finding /
record_correlation directly. It dispatches subagents (which call those
tools) and calls only `update_finding` itself, the orchestrator-only
chain writer.

See `docs/loop-design.md` for the design rationale.
"""

ORCHESTRATOR_VERSION = "1.0.0"

__all__ = ["ORCHESTRATOR_VERSION"]
