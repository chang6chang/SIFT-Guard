# orchestrator loop v1 — Rocba run results

End-to-end run of the SIFT-Guard 5-step self-correction loop on the
Rocba memory image. Validator subagent + Python orchestrator. The
flagship demo of the V-C hybrid architecture: validator emits typed
correlations, orchestrator applies R1-R6 deterministically.

This document captures TWO runs:
- **Run 1** (failure mode): the validator subagent's v1 prompt
  produced 11 consecutive `:rejected_invalid_payload` rejections.
  Zero correlations landed, zero promotions applied. Loop completed
  end-to-end via the architectural guardrails — every malformed
  correlation was rejected and audited, the loop applied R6
  (no-change) to every DRAFT finding, and `iterations.jsonl` line 1
  recorded the failure honestly.
- **Run 2** (success): with the validator prompt revised to enumerate
  the per-type allowed-fields and call out common rejection reasons
  explicitly, the validator emitted 11 valid corroborations on its
  next run. The orchestrator's PROMOTE step applied R3 to 27 DRAFT
  findings, writing 27 `update_finding` entries to `findings.jsonl`
  via the MCP client. `iterations.jsonl` line 2.

Both records remain on disk, hash-chained.

## Setup

| | |
| --- | --- |
| Date | 2026-05-06 |
| Evidence | `Rocba-Memory.raw` (sha256 `eb33bd…0563`, registered as `6770da81-f562-4643-b1d2-69d78104fb70`) |
| Orchestrator | `orchestrator/` package, version 1.0.0 |
| Validator | `.claude/agents/validator.md` (run 1 = v1, run 2 = v2 with explicit per-type field shapes) |
| Analysts | `process_analyst` v2, `network_analyst` v1 (both with new `# Focus context (optional)` section) |
| CLI | `python -m orchestrator.run --case-dir case-data --evidence-id 6770da81-f562-4643-b1d2-69d78104fb70 --max-iterations 2 --token-budget 800000` |
| Pre-run state | findings.jsonl line 19 (18 DRAFT + 1 UPDATE), audit line 116, correlations.jsonl line 1 |

## Run 1 — failure mode

| | |
| --- | --- |
| Started | 2026-05-06 19:37:36Z |
| Completed | 2026-05-06 19:48:58Z |
| Wall clock | 11m 22s |
| Tokens (uncached) | 213,622 |
| Analysts dispatched | process_analyst, network_analyst |
| New findings written | 11 (process: 5, network: 6) |
| Validator dispatch | success — but 11 `record_correlation` attempts all rejected |
| New correlations | 0 |
| Rejections | 11× `record_correlation:rejected_invalid_payload` |
| Promotions applied | 0 / 28 considered (all R6) |
| Termination reason | `no_followup_pending` (iter 2 had no work) |
| iterations.jsonl line | 1 |

**Diagnosis.** The validator's v1 prompt described the conceptual
shape of each correlation type but did not state explicitly that
fields belonging to *other* types must be left unset. The substrate's
`_build_payload` rejects any call where (e.g.) `correlation_type =
"corroborates"` is paired with `severity` or `target_finding_id` set.
Eleven attempts in a row, all the same shape error.

**What worked even in the failure mode.** Every rejection was
captured in the audit chain with a typed reason
(`record_correlation:rejected_invalid_payload`). The orchestrator's
PROMOTE step correctly observed zero correlations referencing any
finding, applied R6 to every DRAFT finding (idempotent no-op, no
on-disk update), wrote `iterations.jsonl` line 1, and the loop
terminated cleanly via `no_followup_pending`. **Architectural
guardrails > prompt guardrails** held: a malformed validator did not
corrupt the chain, did not promote anything spuriously, and did not
hang the loop.

## Validator prompt fix

`.claude/agents/validator.md` gained a new section before "Common
rejection reasons":

> # record_correlation: exact call shapes
>
> Five correlation types map to five exact tool-call shapes. Pass
> ONLY the parameters listed for the shape you choose. Do not pass
> extras (e.g., do not set `severity` on a corroborates call, do
> not set `target_finding_id` on a contradicts call). The substrate
> rejects calls with mixed-type fields as
> `:rejected_invalid_payload`.

…followed by an explicit allowed-fields list per type and a
"Common rejection reasons" checklist. This is the single change
between run 1 and run 2.

## Run 2 — success

| | |
| --- | --- |
| Started | 2026-05-06 19:50:56Z |
| Completed | 2026-05-06 20:00:36Z |
| Wall clock | 9m 40s |
| Tokens (uncached) | 159,875 |
| Analysts dispatched | process_analyst, network_analyst (re-dispatched; cache hits on tier-1) |
| New findings written | 9 (process: 4, network: 5) |
| Validator dispatch | success — emitted 11 valid correlations |
| New correlations | 11 (10 corroborates + 1 corroborates targeting two findings) |
| Rejections | 0 from this run (run 1's 11 still in the chain) |
| Promotions applied | 27 / 37 considered |
| Termination reason | `no_followup_pending` (iter 2 had no work — no request_followup correlations were emitted) |
| iterations.jsonl line | 2 |

**Promotion-rule distribution this iteration:**

| Rule | Count applied | Count considered |
| ---- | ------------- | ---------------- |
| R3 (corroborates strong → CONFIRMED/HIGH) | 27 | 27 |
| R6 (no-change) | 0 | 10 |

The 10 R6 outcomes are legacy "probe" findings from the week-5
process_analyst v1 experiment which the validator chose not to
correlate (they were tooling probes, not substantive). They remain
DRAFT.

**Termination.** R_a (zero unresolved) did not fire because the 10
probe findings stayed DRAFT. R_b (disputed unchanged) did not fire
(no DISPUTED set). R_c (token budget) did not fire. The loop's iter
1 PLAN said "continue", iter 2's ANALYZE saw no
`request_followup` correlations from the validator → no analysts to
dispatch → exit `no_followup_pending`. This is the intended
behavior when the loop has nothing more to do without a fresh
followup request.

## Most-promoted finding chain (PID 7900 hidden process)

The clearest demo chain in the run. PID 7900 was the
substrate-verification PID from week 6 day 1 (already CONFIRMED on
the chain via the manual update_finding from PR-A). The week-6 day
2 loop independently re-discovered and corroborated it.

```
DRAFT  finding_id=13939aab… (process_analyst, this iter)
       title: "svchost.exe PID 7900 visible only via pool-tag
                scan, with duplicate _EPROCESS allocation"
       evidence: set_difference (line 120), query_records (line 129)
       state: DRAFT/MEDIUM

CORR   correlation_id=c64c2595…
       type: corroborates strong
       targets: [13939aab…, ac43422c…]   (PID 7900 from THIS run AND
                                          a prior process_analyst run
                                          — two independent
                                          observations)
       evidence: 4 refs spanning two set_difference + two
                 query_records calls

UPDATE update_id=…  (one of 27 R3 promotions)
       finding_id: 13939aab…
       rule: R3
       transition: DRAFT/MEDIUM → CONFIRMED/HIGH
       driving correlation: c64c2595…
```

The autonomous self-correction loop in action: an analyst flagged
PID 7900, the validator noticed two independent process-analyst
runs reached the same conclusion, the orchestrator promoted via R3
to CONFIRMED/HIGH. No human in the loop after `python -m
orchestrator.run`.

## Final on-disk state (post-run-2)

| Chain | Lines | Net growth |
| ----- | ----- | ---------- |
| `audit/sift-guard-mcp.jsonl` | 246 | +130 since pre-run |
| `findings.jsonl` | 66 | +47 (20 DRAFT analyst writes + 27 UPDATE orchestrator writes) |
| `correlations.jsonl` | 12 | +11 (validator emits) |
| `iterations.jsonl` | 2 | +2 (one per run) |

All four chains valid: every line N+1's `prev_*_hash` matches line
N's `this_*_hash`. Append-only — no prior line modified.

## Architectural validation

What the runs prove:

1. **V-C hybrid in production**: validator subagent emitted typed
   correlations; Python R1-R6 rule engine applied them
   deterministically. Promotion decisions are auditable: every
   `update_finding` line in `findings.jsonl` names the rule that
   fired and the correlations that drove it.

2. **Three-writer architectural separation**: analysts only called
   `record_finding` (frontmatter restriction), validator only called
   `record_correlation`, orchestrator only called `update_finding`.
   Verified by the audit chain showing every (tool, role) pair the
   runs produced.

3. **Four-chain hash-chained integrity**: audit, findings,
   correlations, iterations all chain forward. The orchestrator-
   driven updates land in the SAME findings chain as analyst
   DRAFTs, distinguished by `record_kind`.

4. **Append-only across all four chains**: no retroactive mutation
   of any prior line. Pre-run findings.jsonl bytes (lines 1-19)
   are byte-exactly preserved in the post-run file.

5. **Architectural guardrails > prompt guardrails**: run 1's
   malformed validator output produced zero spurious promotions.
   The substrate rejected, audited, and the loop continued as
   designed. Fixing the prompt was a one-file edit; no substrate
   change was required.

6. **Sequential dispatch under no-locking constraint**: each run's
   subagents ran one-at-a-time. No audit-chain races, no hash-link
   breaks. Total wall time = sum of dispatches; cost is real but
   the chain integrity guarantee is preserved.

## Files produced this run

- `orchestrator/` package — promotion, dispatch, loop, iterations_log, run
- `.claude/agents/validator.md` (v1 → v2 between runs)
- `.claude/agents/process_analyst.md` (added focus_context section)
- `.claude/agents/network_analyst.md` (added focus_context section)
- `case-data/audit/sift-guard-mcp.jsonl` lines 117-246 — 130 audit
  entries across both runs
- `case-data/findings.jsonl` lines 20-66 — 20 new analyst DRAFT
  findings + 27 orchestrator UPDATE entries
- `case-data/correlations.jsonl` lines 2-12 — 11 validator
  correlations from run 2
- `case-data/iterations.jsonl` lines 1-2 — one IterationChainEntry
  per run
- `case-data/orchestrator-run-1.log` — run 1 stdout
- `case-data/orchestrator-run-2.log` — run 2 stdout
- `docs/loop-design.md` — 5-step design doc
- `docs/validator-design.md` — V-C / V2-C / V3-B / V4-A + R1-R6
- `docs/orchestrator-rocba-run-1-results.md` — this document
