# Validator subagent — design

The validator is the third subagent role in SIFT-Guard, after
`process_analyst` and `network_analyst`. Its purpose is to examine
DRAFT findings against independent evidence and emit typed
correlations describing what it observed across them. The validator
does NOT create or promote findings — those are the analysts' and
orchestrator's roles, respectively.

## Architectural choices

### V-C hybrid (validator subagent + Python orchestrator)

| Option | Validator | Promotion logic | Why we picked this |
| ------ | --------- | --------------- | ------------------ |
| V-A    | LLM full reasoning | LLM full reasoning | Promotion logic must be auditable; opaque LLM judgment fails the rubric criterion 5 |
| V-B    | Python rule engine | Python rule engine | Validator's job is *judgment over evidence* (e.g. "is this corroborating or coincidental?") — not reducible to a rule |
| **V-C**| LLM with restricted tool surface | Python rule engine over LLM-emitted correlations | Best of both: LLM judgment where it adds value, deterministic auditable rules where it matters |

The architecture splits the question into two:

1. **What does the evidence show about the relationships between
   these findings?** — that's a judgment task, suited to an LLM with
   the same tier-1/tier-2 tool surface the analysts have.
2. **Given those observations, should this finding be promoted?** —
   that's a deterministic policy question, suited to a Python rule
   engine.

The validator's output is *typed correlations*, not free-form prose.
Five concrete types (corroborates / contradicts / strengthens /
weakens / request_followup) cover the observable relationships. Each
maps unambiguously to the orchestrator's R1-R6 rule engine.

### V2-C: validator can re-run plugins, not just read the chain

The validator's tool surface includes the four `vol_*` plugins plus
the four tier-2 analytical tools. Most calls hit cache (the analysts
already populated the extractions) and return instantly, so the cost
is small. The benefit is that the validator can:

- Re-issue a `set_difference` between psscan and pslist if a finding
  claims process hiding, even if the analyst didn't.
- Run a `subtree` query the analyst skipped to corroborate a parent-
  child claim.
- Pull a focused `query_records` on the IP / PID a finding cites.

A read-only "look at the existing audit chain" surface (V2-A) was
considered and rejected. Cache-hit cost is near-zero, and the
validator gains independent observation power that strengthens the
"two analyses agreed" pattern.

### V3-B: validator sees only DRAFT findings, no ground truth

The validator receives `findings_summary` containing only entries
whose latest state is DRAFT. CONFIRMED findings are filtered out by
the orchestrator before dispatch — they have been promoted by a
prior iteration and are out of scope.

The validator does NOT receive:

- The case scenario / ROCBA-BACKGROUND.pptx content
- The expected attack chain
- Confidence labels other than what's in `findings_summary`
- Any `docs/` content (CLAUDE.md ground-truth isolation rule)

The autonomy criterion (criterion 1, the rubric tiebreaker) collapses
the moment the validator can lean on a curated answer. It analyzes
what the evidence shows.

### V4-A: focus_context as structured dict, not free-form text

`RequestFollowupCorrelation.focus_context` is a typed
`dict[str, Any]` (e.g. `{"pids": [7900], "image_names": ["svchost.exe"]}`).
The orchestrator passes this dict through the analyst's prompt
verbatim. The analyst doesn't need to parse a paragraph — the
relevant fields are already structured.

A free-form `focus_text: str` field was considered. Rejected for
two reasons:

1. The analyst's prompt-parsing reliability would become a load-
   bearing component of the loop. Every analyst version would
   have to handle every possible phrasing.
2. The orchestrator can't reason against the focus content (e.g.
   "did iter 2's analyst actually look at the focused PIDs?")
   without parsing it back out of free-form text.

Structured dict means: validator emits typed data, orchestrator
passes typed data through, analyst reads typed data. Three steps,
one shape.

## R1-R6 promotion rules

Pure-function `orchestrator.promotion.promote()` applies in order;
the first matching rule wins.

```
R1 — Disputed
   Any contradicts correlation with severity ∈ {material, fundamental}
   → DRAFT / DISPUTED
   Disputes outrank corroboration. A fundamental contradiction means
   we cannot confirm even if other evidence supports the finding.

R2 — Demote on weakening
   F.confidence == HIGH AND any weakens correlation present
   → CONFIRMED / MEDIUM
   We commit to the finding (CONFIRMED) but back off the confidence
   one notch. Only HIGH gets demoted; MEDIUM and LOW already have
   room.

R3 — Strong corroboration
   Any corroborates correlation with strength == strong
   → CONFIRMED / HIGH
   The flagship promotion. Triggered by the validator observing
   multiple independent pieces of evidence supporting the finding.

R4 — Moderate corroboration
   Any corroborates correlation with strength == moderate
   → CONFIRMED / max(F.confidence, MEDIUM)
   We confirm but pin the confidence to at least MEDIUM. A LOW
   finding gets promoted to CONFIRMED/MEDIUM; a HIGH finding
   stays at CONFIRMED/HIGH.

R5 — Quiet stabilization
   iterations_so_far >= 2 AND no correlations on F
   → CONFIRMED at F.confidence
   After two completed iterations with nothing new said about F,
   treat the silence as agreement and commit. (R5 outputs a
   recorded promotion without an on-disk update_finding call,
   since update_finding requires driving_correlation_ids.)

R6 — Default
   No matching rule
   → DRAFT / F.confidence (no change)
   Idempotent no-op; the orchestrator skips writing an
   update_finding for R6 outcomes.
```

Rule ordering matters: R1 beats R2 beats R3 beats R4. The rule
engine is exhaustive — every (finding, correlations, iter_count)
input matches exactly one rule.

Confidence ordering for R4's `max()`: LOW < MEDIUM < HIGH. DISPUTED
is *not* in the order — it is only ever an output of R1, never an
input the rules reason against. If a finding is currently DISPUTED
(set by a prior iteration's R1) and a new strong corroboration
arrives, R3 still fires and overrides the DISPUTED state. This lets
the loop recover from a transient disagreement.

### Why six rules, not three or twelve

Three rules (corroborate / contradict / no-op) would not capture
the demotion case (R2) or the time-decay confirmation (R5). Twelve
rules would cross the boundary where the rule engine becomes
opaque to operators. Six is the minimum that:

- Models the substantive promotion patterns we see across forensic
  cases (corroboration, contradiction, demotion, time-decay).
- Stays small enough that an analyst can verify by inspection
  which rule fired against any finding.
- Maps unambiguously from each correlation type to at most one or
  two rules, keeping the rule-driven audit story clear.

## Output contract

The validator's only output is correlation entries on
`correlations.jsonl`, written via `record_correlation`. The
substrate validates each correlation's shape (per-type required
fields), evidence_refs against the audit chain, and finding_ids
against the findings chain. Rejections are audited as
`record_correlation:rejected_*`.

The validator cannot:

- Write findings (no `record_finding` in its tool surface).
- Promote / demote findings (no `update_finding`).
- Investigate evidence outside the registered case.
- Reach `docs/` content (architectural ground-truth isolation).
- Construct file paths (the substrate's `evidence_id` discipline
  applies — the validator names a registered piece of evidence,
  the substrate resolves the path).

## Stop semantics

The validator stops when it has either (a) emitted at least one
correlation covering every DRAFT finding in `findings_summary`,
OR (b) used its tier-1/tier-2 tools enough to conclude no further
corroborations or contradictions exist among the current set.
Strengthens, weakens, and no-correlation outcomes are valid
results — not every finding will yield a corroboration or
contradiction in every iteration.

The validator does NOT keep iterating after every finding has been
addressed. The orchestrator's PLAN step, not the validator, decides
whether the next iteration runs.
