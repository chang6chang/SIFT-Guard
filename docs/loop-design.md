# Self-correction loop — design

The orchestrator's job is to drive a 5-step loop over the case until
one of three termination flags fires (or a hard `max_iterations` cap
trips the safety net). The loop is plain Python — not a Claude Code
subagent. It runs as a single process, dispatches subagents
sequentially via `claude -p --agent <name>`, and writes
`iterations.jsonl` after every iteration.

This document describes what the loop does, why each step exists,
and the architectural constraints that shape the implementation.

## Three writers, four chains

The substrate from week 6 day 1 ships three writers writing to three
hash-chained files:

  | Chain                | Writer                              | Schema  |
  | -------------------- | ----------------------------------- | ------- |
  | `audit.jsonl`        | every MCP tool (success + reject)   | `AuditLogEntry`         |
  | `findings.jsonl`     | analysts (DRAFT) + orchestrator (UPDATE) | `FindingChainEntry` |
  | `correlations.jsonl` | validator only                      | `CorrelationChainEntry` |

Week 6 day 2 adds a fourth chain:

  | `iterations.jsonl`   | orchestrator only                   | `IterationChainEntry` |

Distinct hash field names per chain prevent a line read out of
context from being silently misinterpreted. The orchestrator never
calls `record_finding` or `record_correlation` — those tools are not
in its surface. The orchestrator's only direct MCP call is
`update_finding`. Everything else flows through subagent dispatch.

## The 5 steps

### 1. ANALYZE

Dispatch the analyst subagents the iteration needs.

- **Iteration 1**: dispatch every analyst whose `artifact_class`
  matches a registered piece of evidence. For Rocba (memory_image
  only): `process_analyst` + `network_analyst`. The
  `ARTIFACT_TO_ANALYSTS` map in `orchestrator/loop.py` is the
  authority.

- **Iteration ≥ 2**: dispatch only the analysts named in the
  prior iteration's `RequestFollowupCorrelation` outputs, passing
  each named analyst its `focus_context` dict (PIDs, image_names,
  addresses). The orchestrator records the consumed
  `correlation_id`s in the iteration's
  `followup_requests_consumed` field.

The orchestrator snapshots the set of `finding_id`s on disk before
dispatch and after, deriving the iteration's
`analyst_findings_added` from the delta.

#### Sequential, not parallel

The substrate's chain writers (`server/audit.py`,
`server/findings_log.py`, `server/correlations_log.py`,
`orchestrator/iterations_log.py`) all carry the same docstring
note: *single-process; no file lock*. Dispatching two subagents in
parallel would spawn two MCP-server subprocesses, both writing to
the same audit chain, racing on the hash linkage.

Until per-process file locking lands (out of scope for week 6),
analyst dispatch is sequential. Each iteration's wall time on
Rocba is roughly the sum of each analyst's runtime plus the
validator's runtime. The architecture supports parallel dispatch
the moment the substrate gains locking — the loop's
`_step_analyze` change to `asyncio.gather` is local.

### 2. CORRELATE

Build `findings_summary` from the current findings chain, filtered
to entries whose latest state is DRAFT (CONFIRMED findings are out
of scope per the validator's contract). Dispatch `validator` with:

  evidence_id, case_id, iteration_number, findings_summary

The validator examines the findings, runs whichever tier-1 / tier-2
queries it needs, and emits 0..N correlations via
`record_correlation`. The orchestrator snapshots correlation ids
before and after, deriving `validator_correlations_added`.

### 3. PROMOTE

For each finding whose latest state is DRAFT, gather the
correlations referencing that finding (target_finding_id,
target_finding_ids, finding_a_id/finding_b_id, related_finding_ids)
and call `orchestrator.promotion.promote()`. The pure-function rule
engine returns one `PromotionDecision`:

| Rule | Condition                                              | Output                              |
| ---- | ------------------------------------------------------ | ----------------------------------- |
| R1   | any contradicts severity ∈ {material, fundamental}     | DRAFT/DISPUTED                      |
| R2   | F.confidence == HIGH AND any weakens                   | CONFIRMED/MEDIUM (HIGH demoted)     |
| R3   | any corroborates strength == strong                    | CONFIRMED/HIGH                      |
| R4   | any corroborates strength == moderate                  | CONFIRMED/max(F.confidence, MEDIUM) |
| R5   | iters_so_far >= 2 AND no correlations                  | CONFIRMED at F.confidence           |
| R6   | default                                                | DRAFT/F.confidence (no change)      |

For every non-R6 decision with a non-empty `driving_correlation_ids`
set, the orchestrator calls `update_finding` via its MCP client.
R6 and R5-with-no-correlations decisions are recorded in the
iteration log but not persisted to `findings.jsonl` (no-op).

Findings whose latest state is already CONFIRMED are skipped —
re-promotion is not allowed by the substrate (`update_finding`
rejects CONFIRMED → DRAFT transitions, and CONFIRMED → CONFIRMED
no-ops are an audit-noise problem we avoid here).

### 4. PLAN

Compute three independent termination flags:

| Flag                          | Condition                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------- |
| `R_a_zero_unresolved`         | count of (DRAFT or DISPUTED) findings == 0                                       |
| `R_b_disputed_set_unchanged`  | iter > 1 AND prior iteration's DISPUTED set == current DISPUTED set (non-empty)  |
| `R_c_token_budget_exceeded`   | cumulative_tokens_uncached >= TOKEN_BUDGET_UNCACHED (500K default)               |

Plus the safety-net `max_iterations_reached`. Decision is
"terminate" if any flag is true, "continue" otherwise.

Token usage: the loop sums every dispatch's `tokens_uncached`
(input_tokens + cache_creation_input_tokens + output_tokens — the
cache-read fraction does not count, since it didn't hit the model
fresh). The 500K default is calibrated for a memory-only case; a
multi-artifact case will need a higher budget.

### 5. WRITE

Build an `IterationPayload` capturing:

- timing (`started_at` / `completed_at`)
- `analysts_dispatched` (in order)
- `analyst_findings_added` (UUID list)
- `validator_correlations_added`
- `promotions_made` (one `RecordedPromotion` per finding considered,
  with `applied: bool` distinguishing on-disk updates from in-memory
  R6 / no-driving-correlations decisions)
- `followup_requests_consumed` (drove the *next* iteration's
  ANALYZE step; recorded against the iteration that consumed them)
- `tokens_used_uncached` and `cumulative_tokens_uncached`
- `termination_check`

Append to `iterations.jsonl` via the hash-chained writer. The
orchestrator continues to the next iteration unless
`termination_check.decision == "terminate"`.

## Focus context flow

`RequestFollowupCorrelation.focus_context` is a structured dict the
validator emits, e.g. `{"pids": [7900], "image_names": ["svchost.exe"]}`.
The orchestrator's `_next_iter_dispatch_plan` extracts every
followup correlation in the just-completed iteration's correlation
delta, groups by `target_analyst`, and stages
`(analyst → focus_context)` for the next iteration.

When the next ANALYZE step dispatches a focused analyst, the
focus_context lands in the analyst's user prompt:

  evidence_id: <uuid>
  case_id: <case-id>
  iteration_number: 2
  focus_context: {"pids": [7900]}

The analyst's prompt has a `# Focus context (optional)` section
explaining V5c-1 semantics: focus biases attention but does not
constrain scope. The analyst still does its normal analysis AND
pays extra attention to the focused entities.

If multiple followup correlations target the same analyst with
different focus contexts, the *last* one in the iteration wins for
the orchestrator's next dispatch. A future enhancement could merge
them by union or pick the highest-rationale one.

## Re-dispatch on iteration 1

The orchestrator always dispatches all matching analysts on
iteration 1, even if the case directory already has DRAFT findings
from prior runs. Rationale:

- The append-only chains tolerate idempotent re-dispatch — every
  new finding is its own UUID, and the substrate computes the
  evidence integrity per-line.
- Cache hits on tier-1 plugins make re-dispatch cheap (vol_*
  serves the stored extraction without re-running Volatility).
- Detecting "this case has already been analyzed by analyst X" is
  brittle: an analyst may have run with an earlier prompt or a
  smaller tool surface, and skipping it would leave that gap
  invisible.

The cost: each loop run grows `findings.jsonl` by the analysts'
output, even if the new findings duplicate prior ones. The
validator's `findings_summary` deduplicates by `finding_id` (which
is unique per record, not per logical observation), so the summary
grows correspondingly. For Rocba's iteration 1, this means the
validator sees 18+ findings to correlate, not 2.

## Termination semantics

The three flags terminate for different reasons:

- **R_a (zero unresolved)** is the desirable outcome: every
  DRAFT/DISPUTED finding has been promoted or disputed and there's
  nothing left to look at. The loop succeeded.

- **R_b (disputed set unchanged)** is a stalemate: two iterations
  in a row produced the exact same DISPUTED set. The validator can
  see contradictions but neither side is gaining ground; further
  iteration would just repeat the same observations. The contested
  findings get flagged for human review.

- **R_c (token budget)** is the cost ceiling: the cumulative
  uncached token cost has hit the budget. Defensive — without it,
  a runaway validator could spend the entire account budget on
  redundant analysis.

- **max_iterations_reached** is the safety net: even if no other
  flag fires, the loop stops at `max_iterations`. Default 10.

The loop's outcome record names the rule that fired in the
`termination_reason` field, surfaced in the CLI summary and the
demo screencast.

## What the loop does NOT do

- It does NOT call `vol_*` / tier-2 / `record_finding` /
  `record_correlation` directly. Subagents own all that.
- It does NOT modify the audit / findings / correlations chains in
  place. The chains are append-only.
- It does NOT decide which findings to promote — `promote()` does,
  driven by the validator's correlations.
- It does NOT retry failed dispatches. A subagent that returns
  without a `result` event logs a warning and the loop proceeds —
  a structural problem trips the user-driven STOP rather than
  defensive retries.
- It does NOT inspect `docs/` (per CLAUDE.md ground-truth
  isolation rule).
