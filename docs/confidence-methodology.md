# Confidence methodology

> Required Devpost deliverable per CLAUDE.md hackathon rubric
> (criteria #2 IR Accuracy and #5 Audit Trail).
> The implementation is the authoritative source; this document
> explains what the implementation does and why. If a discrepancy
> appears between text and code, the code wins and a
> `decisions-log.md` entry is filed for triage.

## Overview

Findings are written DRAFT by analyst subagents, then promoted by
the orchestrator based on validator-emitted correlations. Promotion
is rule-based, deterministic, and append-only: every state change
is a new hash-chained line in `case-data/findings.jsonl` carrying
a discriminated `record_kind = "update"` payload. Last-write-wins
over the chain reconstructs every finding's current state.
`orchestrator/promotion.py:promote()` is a pure function — same
inputs → same `PromotionDecision`, no I/O.

## Confidence levels

Four levels, schema-pinned in `server/schemas.py:599`
(`FindingConfidence = Literal["LOW", "MEDIUM", "HIGH", "DISPUTED"]`):

- **HIGH** — multiple independent corroborating observations
  agreeing on the same target (cross-plugin, cross-source, or
  cross-artifact, depending on what's registered), OR a single
  high-fidelity observation that the validator returns a
  `corroborates(strength=strong)` correlation against. Example:
  `set_difference(psscan ∖ pslist, key=pid)` returns a hidden
  PID candidate that a fresh `query_records` independently
  reproduces — a strong corroboration of the analyst's
  process_hidden draft.
- **MEDIUM** — single source, artifact type reasonably reliable
  for the finding category. Example: psscan finds a process
  pslist doesn't, but no second observation strengthens or
  weakens the claim.
- **LOW** — single low-fidelity observation, OR a single
  observation whose contradiction was already resolved.
- **DISPUTED** — contradiction unresolved at termination. The
  finding includes both sides of the disagreement and the
  validator's hypothesis. Set ONLY by the orchestrator via R1.
  Analysts cannot self-mark DISPUTED — `record_finding` rejects
  the call with `record_finding:rejected_disputed_self_marked`
  (`server/tools/findings.py:260-268`).

## Who can write what — the architectural surface

Three writers, three roles, one shared findings chain:

| Writer | Tool | What it produces | Allowed confidences on write |
|---|---|---|---|
| Analyst subagents (`process_analyst`, `network_analyst`) | `record_finding` | `DraftFinding` (`record_kind="draft"`) | LOW, MEDIUM, HIGH (DISPUTED rejected) |
| Validator subagent | `record_correlation` | one of five correlation types into `correlations.jsonl` | (cannot mutate findings) |
| Orchestrator (Python, not an LLM) | `update_finding` | `FindingUpdate` (`record_kind="update"`) | LOW, MEDIUM, HIGH, **DISPUTED** |

State transitions on `update_finding` are one-directional: DRAFT
may go to DRAFT (with a confidence change) or CONFIRMED;
CONFIRMED stays CONFIRMED. CONFIRMED → DRAFT is rejected with
`update_finding:rejected_invalid_state_transition`
(`server/tools/findings.py:493-499`).

Defense-in-depth note: the `AnalystName` Literal
(`server/schemas.py:605`) and `ALLOWED_ANALYSTS` runtime set
(`server/tools/findings.py:65-67`) both include "validator" so
the schema admits any of the three writers, but the validator's
tool frontmatter (`.claude/agents/validator.md`) does not list
`record_finding` — the agent surface forbids what the schema
permits, and any direct invocation would still be audited.

## Correlation types

Five types, discriminated on `correlation_type`
(`server/schemas.py:1411` and surrounding union definition).
For each, what it means and
which rule(s) it can drive:

| Type | Required fields beyond the base | Drives |
|---|---|---|
| `corroborates` | `target_finding_ids: list[str] (≥1)`, `strength ∈ {weak, moderate, strong}` | R3 (strong), R4 (moderate). **Weak does not promote.** |
| `contradicts` | `finding_a_id`, `finding_b_id`, `severity ∈ {minor, material, fundamental}`, `resolvable_by_followup: bool` | R1 (material or fundamental). **Minor does not promote.** |
| `strengthens` | `target_finding_id` | (none — supplementary evidence only) |
| `weakens` | `target_finding_id` | R2 (HIGH-confidence demotion to MEDIUM) |
| `request_followup` | `target_analyst`, `related_finding_ids: list[str] (≥1)`, `focus_context: dict`, `rationale` | (none — drives the next iteration's ANALYZE step, not a promotion) |

Weak corroboration, minor contradiction, and `strengthens` are
emitted-but-non-promoting in the current ruleset. They are
recorded for audit-chain provenance and could drive future
rules. The rule set is intentionally small.

## Promotion rules

Six rules, evaluated in fixed order
(`orchestrator/promotion.py:130-219`). First match wins.

| Rule | Trigger | New state | New confidence | Driving correlation |
|---|---|---|---|---|
| **R1** Contradiction wins | any `contradicts` with severity ∈ {material, fundamental} | DRAFT | DISPUTED | the contradicts ids |
| **R2** Demote HIGH on weakens | `F.confidence == HIGH` AND any `weakens` | CONFIRMED | MEDIUM | the weakens ids |
| **R3** Strong corroboration | any `corroborates(strength=strong)` | CONFIRMED | HIGH | the strong-corroborates ids |
| **R4** Moderate corroboration | any `corroborates(strength=moderate)` | CONFIRMED | `max(F.confidence, MEDIUM)` | the moderate-corroborates ids |
| **R5** Quiet stabilization | `iterations_so_far ≥ 2` AND `correlations_for_finding == []` | CONFIRMED | `F.confidence` (or MEDIUM if currently DISPUTED) | (empty list) |
| **R6** Default | none of the above | DRAFT | unchanged | (empty list — no chain write) |

### Order rationale

R1 first because contradictions outrank corroboration: a
contradicted finding cannot be confirmed without resolution. R2
second so a HIGH-then-weakened finding gets the demotion
treatment even if a corroboration also exists. R3 / R4 follow
(strong outranks moderate). R5 only fires after every
correlation-driven path has been exhausted; quiescence is the
weakest signal we promote on. R6 catches everything else.

### R5 implementation notes

R5 is the only rule whose decision carries an empty
`driving_correlation_ids` list. As of the 2026-05-07 hotfix
(`docs/decisions-log.md` "R5 persistence"), `FindingUpdate`'s
schema permits the empty list exclusively when
`promotion_rule == "R5"` (model_validator at
`server/schemas.py:768-785`); every other rule rejects the
empty case at the tool layer with
`update_finding:rejected_empty_correlations_for_non_R5`.

**Known limitation:** `iterations_so_far` is per-run, not
cumulative across the case's history. Findings silent across
multiple short orchestrator runs accumulate no R5 credit;
R5-promotion requires a single invocation running ≥ 3
iterations on the finding. Deferred to week 7. Defense-in-depth
in `promote()`: a DISPUTED finding reaching R5 (improbable,
since the contradicts correlation persists in the chain) commits
at MEDIUM, not DISPUTED (`orchestrator/promotion.py:197-202`).

### R6 is intentionally chain-silent

R6 decisions are recorded in `iterations.jsonl`'s
`promotions_made` entries with `applied=False` but produce no
`update_finding` write — there is no state change to record
(`orchestrator/loop.py:418-430`). The chain stays compact;
re-running the loop on a finding still in R6 territory is a
true no-op.

## Worked examples from the live chains

**R3 strong corroboration — Rocba `3d84cd31` (svchost.exe
PID 7900).** Process_analyst writes DRAFT/MEDIUM at
`findings.jsonl` line 9 ("svchost.exe PID 7900 visible only in
psscan with duplicate pool-tag entry; absent from pslist").
Validator emits `corroborates(strength=strong)` at
`correlations.jsonl` line 1, hypothesis: *"PID 7900 svchost.exe
corroborated as a hidden / DKOM candidate…"*. Orchestrator's R3
fires; `findings.jsonl` line 19 is the matching UPDATE
(`record_kind=update`, `previous_state=DRAFT`,
`new_state=CONFIRMED`, `previous_confidence=MEDIUM`,
`new_confidence=HIGH`, `promotion_rule=R3`,
`driving_correlation_ids=[4e449810…]`).

**R1 material contradiction — synthetic-image `af50f96c`
(PID 29664 SearchProtocolHost).** Process_analyst writes
DRAFT/LOW at `findings.jsonl` line 12 claiming PID 29664 is
present in pslist but absent from psscan. The validator's
independent re-query disagrees and emits
`contradicts(severity=material)` at `correlations.jsonl`
line 18 against finding `f192e0fb` (which made the opposite
claim). R1 fires on both findings; `findings.jsonl` line 73 is
the UPDATE for `af50f96c` (`previous_state=DRAFT`,
`new_state=DRAFT`, `previous_confidence=LOW`,
`new_confidence=DISPUTED`, `promotion_rule=R1`).

**R5 quiet stabilization — fixture-based.** The Rocba and
synthetic-image runs both terminated before any single
invocation reached iter 3, so the live chains contain zero R5
promotions. R5's chain-write path is exercised in
`tests/test_loop.py::TestR5PersistsToChain::test_three_silent_drafts_reach_confirmed_via_r5`
(three DRAFT findings with zero correlations across two
`_step_promote` calls; the second call's R5 decisions reach
`findings.jsonl` and `R_a` fires on `_step_plan`). The fix
landed in commit `3739565`.

## What this methodology does NOT yet do

Honest disclosure of design choices not in the current
implementation:

- **No RAG-grounded promotion.** The CLAUDE.md HIGH definition
  mentions "technique matches a RAG-retrieved MITRE TTP" as a
  criterion. The current rules consult only correlation type +
  strength + contradiction severity. The RAG (`rag/retriever.py`)
  is available to subagents in their hypothesis prose, but
  mechanical promotion is correlation-driven only.
- **No confidence math.** Rules are ordinal, not numeric. We do
  not average strengths, weight corroborations by source
  diversity, or score on a continuous scale. Small ordinal
  rules are testable; numeric confidence is harder to validate.
- **No multi-finding consistency check beyond pairwise
  contradictions.** `ContradictsCorrelation` operates on two
  findings (`finding_a_id` / `finding_b_id`); we do not check
  three-way consistency.
- **R5 is per-run, not cumulative.** Documented above and in
  `decisions-log.md`. Deferred to week 7.
- **Weak corroboration, minor contradiction, and `strengthens`
  do not promote.** They are recorded for chain provenance and
  could drive a future R7+ ruleset.
- **No automatic re-classification of category.** If an analyst
  writes `process_anomaly` and the validator believes
  `process_hidden` is more accurate, the validator can record a
  `strengthens` / `contradicts`; it cannot re-categorize.
  Re-categorization is a human-reviewer call.

## Reproducibility

Every promotion is reproducible from the chains. Given a
`finding_id`: walk `findings.jsonl` for every matching entry
(the per-finding DRAFT-then-UPDATE timeline); for each UPDATE,
look up its `driving_correlation_ids` in `correlations.jsonl`;
read `iterations.jsonl` for the iteration's `promotions_made`
list, which records which rule fired and whether it was
applied (`applied=True` for R1-R5, `applied=False` for R6 and
unapplied R5-pre-hotfix in-memory no-ops). All four chains
(`audit/sift-guard-mcp.jsonl`, `findings.jsonl`,
`correlations.jsonl`, `iterations.jsonl`) carry `prev_*_hash`
and `this_*_hash` fields so tampering is detectable. `promote()`
is pure — replaying it against the same inputs always yields
the same `PromotionDecision`.

## Versioning

`orchestrator.ORCHESTRATOR_VERSION` is recorded on every
`FindingUpdate` (`server/schemas.py:766`,
`orchestrator/__init__.py:21`). When the promotion rules
change, the version bumps and the chain records which
ruleset produced each update. Old findings remain auditable
under the ruleset that produced them.

**Current version: `1.0.0`.**
