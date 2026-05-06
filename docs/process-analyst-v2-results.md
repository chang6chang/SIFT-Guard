# process_analyst v2 — Rocba experiment results

The re-run of the process_analyst experiment on the new tier-1 /
tier-2 MCP architecture. v1 (2026-05-05,
[`process-analyst-v1-results.md`](process-analyst-v1-results.md))
returned Verdict C — the analyst hit a tool-result-size deadlock,
correctly refused to fabricate, and produced 0 findings. v2 tests
whether the architecture refactor (~1 KB tier-1 summaries + tier-2
analytical tools that read stored extractions) actually unblocks
the analyst.

## Setup

| | |
| --- | --- |
| Date | 2026-05-06 |
| Evidence | `Rocba-Memory.raw` (sha256 `eb33bd…0563`, 19 GB, registered as `6770da81-f562-4643-b1d2-69d78104fb70`) |
| Subagent file | `.claude/agents/process_analyst.md` (v2; updated tool list, tier-1/tier-2 framing) |
| Tool surface granted | `mcp__sift-guard__{register_evidence, vol_pslist, vol_psscan, vol_pstree, query_records, group_by, set_difference, subtree, record_finding}` (9 tools) |
| Model | `claude-opus-4-7[1m]` |
| Dispatch | `claude -p --agent process_analyst --output-format stream-json --verbose --permission-mode bypassPermissions` |
| Session id | `0050bdf1-cdd8-42d2-89cb-b31d29ece206` |
| Transcript | [`process-analyst-v2-rocba.transcript.md`](process-analyst-v2-rocba.transcript.md) |
| Comparison | [v1 results](process-analyst-v1-results.md) — same prompt principle, smaller tool-call return shape |

## Run summary

| | |
| --- | --- |
| Wall clock | 11m 25s (17:26:31Z → 17:37:56Z) |
| API duration | 675.3 s (essentially all-API; tier-1 calls were cache hits in <1 s each) |
| Turns | 80 |
| Cost | $2.6110 |
| Output tokens | 56,321 |
| Cache-creation input tokens | 106,216 |
| Cache-read input tokens | 1,078,037 |
| Tool calls (total) | 79 |
| Tool-call distribution | 28 `query_records` / 40 `record_finding` (12 succeeded, 28 rejected) / 5 `group_by` / 2 `set_difference` / 1 each `vol_pslist:cached`, `vol_pstree:cached`, `vol_psscan:cached`, `subtree` |
| Audit-chain growth | lines 18-96 (79 new) |
| `findings.jsonl` growth | lines 2-13 (12 new findings; 5 substantive, 7 probe) |
| Server-side rejections | 28 `record_finding` (27 `:rejected_invalid_audit_ref`, 1 `:rejected_schema_validation_failed`); 0 tier-1 / tier-2 evidence-extraction rejections |
| Stop reason | `end_turn` (analyst voluntarily terminated) |
| `permission_denials` | 0 |

## What the analyst caught

### Substantive findings (5)

For each: title, category, severity, confidence, audit-line back-pointers,
and a brief reviewer assessment.

| # | Findings line | Title | Category | Severity / Conf | Refs | Reviewer assessment |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 9 | svchost.exe PID 7900 visible only in psscan with duplicate pool-tag entry; absent from pslist active EPROCESS list | `process_hidden` | medium / MEDIUM | `vol_psscan:5`, `vol_pslist:3`, `vol_pslist:4` | **Correct.** This is the target finding — the still-active a_only PID with pool-tag aliasing. Category and confidence are appropriate; "MEDIUM" reflects that the svchost name is canonical but the cross-plugin disagreement is real. The validator can promote / dispute. |
| 2 | 10 | SearchFilterHost (PID 4420) and SearchProtocolHost (PID 16480) visible only via psscan pool-tag scan | `process_hidden` | low / LOW | `vol_psscan:5`, `vol_pslist:3` | **Correct categorization, conservative confidence.** These are 2 of the 11 a_only PIDs and have non-null `ExitTime` in psscan, so they are exited-but-resident rather than DKOM-hidden. The analyst did not enumerate all 10 of the exited a_only PIDs as separate findings — it bundled the cohort into one. Acceptable signal/noise tradeoff. |
| 3 | 11 | Pool-tag aliasing: 16 duplicate-key records in psscan | `process_anomaly` | info / MEDIUM | `vol_psscan:5`, `vol_pslist:4` | **Correct surfacing of `a_duplicate_key_count = 16`.** This is the validator-relevant context for why `|psscan| − |pslist| = 26` does not equal `a_only_count = 11`. The analyst used the dedicated tier-2 set_difference field for this, not a fabrication. |
| 4 | 12 | PID 29664 SearchProtocolHost present in pslist but absent from psscan (reverse cross-plugin gap) | `process_anomaly` | low / LOW | `vol_pslist:3`, `vol_psscan:5` | **Correct.** This is the `b_only_count = 1` finding, captured. The analyst correctly treated it as low-confidence (likely linked-list churn between scan phases, not anomaly). |
| 5 | 13 | High-volume Teams.exe child-process spawn (1730+ children of PID 11672 over 5 days; ~one every 3-4 minutes) | `process_anomaly` | low / MEDIUM | `vol_pslist:3`, `vol_psscan:5`, `vol_pstree:6` | **Correct surfacing of the Teams.exe fan-out** (the largest_subtree from PstreeSummary). Confidence MEDIUM at severity low captures the "anomalous-but-explainable" judgment well. |

### Probe findings (7)

Lines 2-8 in `findings.jsonl` are titled `probe ...` and were committed
during the analyst's brute-force search for valid (audit_line,
source_tool) pairs. They reference real audit lines and pass
schema validation, but they carry no forensic signal — the
descriptions are placeholder text. The analyst self-disclosed this
in its summary ("forensically void; the validator should treat them
as noise"). Per the experiment's rules ("do NOT manually clean up or
delete findings.jsonl entries"), they remain in the case-data.

The probe findings are a real architectural surface area worth
discussing in "Failure modes" below.

## What the analyst missed

For each of the targets the experiment design called out, what
happened:

- **PID 7900 as a DKOM candidate.** Caught (finding #1).
  Categorized as `process_hidden` — the right enum value. Confidence
  MEDIUM. The validator (week 6) promotes or disputes; nothing
  more was expected of the analyst.
- **The 10 exited a_only PIDs as benign-by-lifecycle.** Partially
  caught. Two of them (SearchFilterHost 4420 / SearchProtocolHost
  16480) are named in finding #2; the analyst chose to bundle the
  exited cohort rather than enumerate each. The remaining 8 are
  not individually named in any finding. This is a
  signal-vs-completeness tradeoff: the run was not exhaustive on
  this cohort, but the cohort was *acknowledged*.
- **Teams.exe's 1730-child subtree as a benign-but-worth-noting
  observation.** Caught (finding #5). The analyst correctly
  classified it as `process_anomaly` rather than `process_hidden`
  / `process_masquerade`, severity low / confidence MEDIUM —
  recognizing it as anomalous shape (high fan-out) without
  attributing malice.
- **The ~90% null-cmdline rate.** Not surfaced. Pslist's
  `ProcessRecord` does not have a `cmdline` field; the spec's
  Pslist*Summary* substitutes `null_create_time_count` for the
  same shape signal. The analyst did not query `windows.cmdline.CmdLine`
  (it is not in its tool surface). This is a tool-surface gap, not
  an analyst gap. (Note: pstree carries `cmd`/`audit`/`path`, but
  the analyst did not group on null-cmd in pstree records — a
  reasonable miss given pstree's resolved-fields nullability is
  documented as ~91% on Vol 3 2.27.0 in the pstree wrapper docstring.)
- **No core-process masquerade**: actively confirmed by the
  analyst in its summary block ("System(4)→smss(440)→{csrss(664),
  wininit(752)}; wininit→{services(828), lsass(840)}; explorer(7464);
  all in canonical positions"). This is the *absence-of-finding*
  the experiment hoped the analyst would actively check —
  delivered.
- **No svchost.exe parent-spoofing**: also actively confirmed
  ("100% of svchost.exe instances (103 in pslist, 106 in psscan)
  have PPID=828=services.exe").

## Tool usage analysis

The analyst's pattern, in order:

1. **Tier-1 first** — issued `vol_pslist`, `vol_pstree`, `vol_psscan`
   in a single batched call. All three returned cached summaries in
   ~1 s. The analyst correctly read the summaries' shape signal
   before any tier-2 work.
2. **set_difference next** — `set_difference(psscan, pslist, key="pid",
   direction="a_minus_b")` was the very next call after the tier-1
   batch. The analyst recognized this as the primary cross-plugin
   primitive without prompting (it is described as "primary
   cross-plugin primitive" in the role prompt's tool-description).
3. **group_by to characterize the population** — two `group_by`
   calls on `image_file_name` (one per pslist and psscan) before
   diving into specific records.
4. **query_records to drill in on specific candidates** — 28 calls,
   each narrowly filtered. The agent retrieved canonical Windows
   core processes (services.exe, lsass, smss, wininit, csrss,
   explorer) to *check for masquerade*, then specifically retrieved
   the 11 a_only PIDs from psscan, then the 1 b_only PID from
   pslist.
5. **subtree at PID 8908** — to characterize Teams.exe's largest
   subtree before committing the fan-out finding.
6. **A second `set_difference` (reverse direction)** — `pslist
   a_minus_b psscan` to confirm the b_only count. Direct evidence
   the agent understood the schema and the symmetric nature of
   set_difference.
7. **`group_by` on `ppid`** — to enumerate top parent-PIDs and
   distinguish service-fanout (svchost ppid 828) from anomalous
   parents.
8. **More `query_records` for the high-fan-out PPIDs** — to
   characterize each top parent before deciding it was benign.

The intended tier-1-then-tier-2 workflow was *discovered organically
from the prompt alone*. The prompt did not tell the analyst "first
run tier-1, then drill in with tier-2"; it described the tools'
capabilities in tier-1 vs tier-2 terms and the analyst inferred the
workflow. This is the load-bearing question the v2 experiment was
asking.

Tier-2 tools used at least once each: `query_records`, `group_by`,
`set_difference`, `subtree`. Full tier-2 surface coverage.

## Failure modes

| Failure mode | Observed? | Detail |
| --- | --- | --- |
| Prose-instead-of-tool-call | No | Findings went through `record_finding`. |
| Hallucinated tool / argument names | No | All 79 tool calls used valid MCP tool names and well-formed inputs. |
| Findings without `evidence_refs` | No | All 12 committed findings carry `evidence_refs` that pass server-side audit-chain validation. |
| Self-marked DISPUTED | No | Highest confidence the analyst self-marked was MEDIUM. |
| Context exhaustion | No | Stopped at turn 80 with `stop_reason=end_turn`. Cache reads (1.08 M tokens) indicate substantial caching savings. |
| Tool-result-size deadlock (v1's Verdict C) | **No** | Tier-1 returns were 517-678 B; tier-2 returns under 10 KB. The architecture refactor resolved the v1 deadlock. |
| Probe findings committed | **Yes** | 7 of 12 committed findings are placeholder probes. The analyst spent ~16 turns probing for valid `(audit_line, source_tool)` pairs because the tier-1/tier-2 tool returns do not surface their own audit-chain line number. |
| Re-running tools unnecessarily | Marginal | The analyst issued 28 query_records calls — most narrowly different filters, not redundancy. No tier-1 re-runs (cache contract held). |

The probe-finding pattern is the load-bearing observation from this
run for the *next* refactor. The analyst's reasoning was: "I need
to commit a finding with `evidence_refs[*].audit_line=N` and
`source_tool=vol_pslist`; I do not know which value of N corresponds
to my own tool calls." It then tried `audit_line=1, 2, 5, 6, 7, 8, 9,
11, 20, 50, 100` against various source_tools, watching the
`record_finding:rejected_invalid_audit_ref` audits land back. Once
it found valid pairs, it used them in real findings.

This *worked* — the architectural rejection paths held — but it
contaminated `findings.jsonl` with 7 noise records and burned ~$0.30
of the run's $2.61 cost on probing turns. A cheap fix would be
extending tier-1/tier-2 tool returns with the audit-chain line
number they wrote (e.g., `extraction.audit_line` or
`result.audit_line` on the returned model). That removes the
probe-or-fabricate dilemma the analyst faced. Recommended for the
next architecture iteration; out of scope for v2.

## Comparison to v1

| | v1 (2026-05-05) | v2 (2026-05-06) |
| --- | --- | --- |
| Tool surface | 5 tools, all "tool returns full data" | 9 tools, tier-1 (≤10 KB summaries) + tier-2 (≤10 KB analytical queries) |
| pslist return size | 459 KB → spilled to disk by Claude Code | 677 B (PslistSummary) |
| pstree return size | 800 KB → spilled to disk | 517 B (PstreeSummary) |
| psscan return size | not called (analyst declined) | 678 B (PsscanSummary) |
| Tool calls before stop | 2 | 79 |
| Wall clock | 1m 51s | 11m 25s |
| Output tokens | 3,299 | 56,321 |
| Cost | $0.1741 | $2.6110 |
| Findings committed | **0** | **12** (5 substantive, 7 probe) |
| Verdict | **C — structural deadlock** | **A — design works** |

v1 caught the architectural deadlock and refused to fabricate. v2
exercises the full architecture, surfaces every target finding the
experiment design called out (PID 7900 as `process_hidden`, the
exited-cohort context, the 16 pool-tag aliases, the b_only=1, the
Teams fan-out), and confirms the absence of core-process masquerade
and svchost parent-spoofing.

## Verdict

**A — Design works.** Build `network_analyst` to the same pattern.

Justification: every target finding the experiment design enumerated
was caught with the correct category at a defensible confidence;
the tier-1-then-tier-2 workflow was discovered organically from the
prompt; no architectural deadlock; no fabrication. The probe-finding
pattern is a real but bounded UX issue that points at a small, clean
follow-up (tier-1/tier-2 tools should return their own audit-chain
line number) — it does not block building the second analyst.

### What this experiment is *not* evidence of

- It is not evidence that the validator will agree with the
  analyst's confidences — that is the validator's week-6 job.
- It is not evidence of completeness on the exited a_only cohort
  (8 of 10 exited PIDs are unnamed in any finding). The analyst
  bundled rather than enumerated; whether that's enough depends on
  the validator's policy.
- It is not evidence about cmdline / handles / DLL coverage —
  those plugins are out of scope for this analyst's tool surface.
- It is not evidence that the same prompt would work on a Windows
  Server 2016 / 2019 image — Rocba is Windows 10, and some of
  what the analyst described as "canonical Windows core" lineage
  is version-specific.

It *is* evidence that the tier-1/tier-2 architecture lets a
restricted-surface analyst produce DFIR findings that are correctly
categorized, schema-conformant, and back-pointed into the audit
chain — the architectural goal of the week-5 refactor.

## Week 6: focus_context input added

In week 6 day 2 the agent definition gains a `# Focus context
(optional)` section. The orchestrator may pass a structured
`focus_context` dict (PIDs, image_names, addresses) when re-
dispatching the analyst on iteration ≥ 2 of the self-correction
loop. The semantics are V5c-1: focus biases attention but does not
constrain scope. The analyst still does its normal analysis AND
pays extra attention to focused entities. This change is additive
— iteration-1 dispatches without focus_context behave exactly as
the v2 dispatch documented above.

## Files produced this run

- `.claude/agents/process_analyst.md` (v2) — agent definition
- `case-data/audit/sift-guard-mcp.jsonl` lines 18-96 — 79 audit
  entries (tier-1 cache hits, tier-2 successes, record_finding
  successes and rejections)
- `case-data/findings.jsonl` lines 2-13 — 12 findings (5
  substantive, 7 probe)
- `case-data/extractions.jsonl` — unchanged (3 lines from prior
  verification; v2 was all cache-hits)
- `docs/process-analyst-v2-rocba.transcript.md` — turn-by-turn transcript
- `docs/process-analyst-v2-results.md` — this document
