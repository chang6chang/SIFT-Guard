# process_analyst v1 — Rocba experiment results

The first end-to-end test of a tool-restricted analyst subagent
against the Rocba memory image. Single goal: learn whether the
typed-tool architecture (restricted MCP surface, minimal-methodology
system prompt, schema-validated `record_finding`) is sufficient on
its own to elicit useful DFIR analysis. Per the experiment design
the deliverable is the result, not a successful run.

## Setup

| | |
| --- | --- |
| Date | 2026-05-05 |
| Evidence | `Rocba-Memory.raw` (sha256 `eb33bd…0563`, 19 GB, registered as `6770da81-f562-4643-b1d2-69d78104fb70`) |
| Subagent file | `.claude/agents/process_analyst.md` |
| Tool surface granted | `mcp__sift-guard__{register_evidence, vol_pslist, vol_psscan, vol_pstree, record_finding}` |
| Model | `claude-opus-4-7[1m]` |
| Dispatch | `claude -p --agent process_analyst --output-format stream-json --verbose --permission-mode bypassPermissions` |
| Session id | `cf0442de-493e-425e-ab0c-85b2e448b872` |
| Transcript | [`process-analyst-v1-rocba.transcript.md`](process-analyst-v1-rocba.transcript.md) |

## Run summary

| | |
| --- | --- |
| Wall clock | 1m 51s (23:19:53Z → 23:21:44Z) |
| API duration | 91.9 s (52.2 s in Anthropic API; balance in MCP/SSH round-trips) |
| Turns | 3 |
| Cost | $0.1741 |
| Output tokens | 3,299 |
| Cache-creation tokens | 13,686 (CLAUDE.md + agent prompt + tool schemas materialized into the cache) |
| Cache-read tokens | 12,204 |
| Tool calls (in order) | `vol_pslist` → `vol_pstree` (issued in parallel as a single batch) |
| Audit-chain growth | lines 9–10 |
| `findings.jsonl` growth | none (still at line 1, the genesis) |
| Findings committed | **0** |
| Tool-call rejections (server-side) | 0 |
| `permission_denials` | 0 |
| Stop reason | `end_turn` (analyst voluntarily terminated) |

The analyst issued one batched parallel call to `vol_pslist` and
`vol_pstree`, evaluated the returns, and stopped. It did **not**
call `vol_psscan`. It did **not** call `register_evidence`. The
single-batch parallel dispatch is sensible — both plugins are
read-only over the same image and can run concurrently.

## What the analyst caught

Nothing was committed as a finding, so this section is empty.

## What the analyst missed

The analyst missed everything by construction (zero findings
committed). Whether the underlying anomalies *exist* in the Rocba
image is not what this experiment measured — it measured whether
the analyst could surface them given the tool surface it had. It
could not.

For a record of what was on the table, the saved tool-result files
that the analyst could not read contain the raw evidence:

- `vol_pslist` output: 459 KB / 2,186 process records (every entry the
  active EPROCESS-list walk surfaced; this includes entries from a
  long-running session, not just live processes).
- `vol_pstree` output: 800 KB / 58 root nodes (recursive children
  inflate the byte count — the deeper subtrees plus per-node `audit`,
  `cmd`, and `path` resolved fields are the size driver).

The 800 KB pstree result is roughly 200 K tokens at 1:1 — well over
any reasonable per-call budget. This is not a Rocba peculiarity; any
modern Windows host with a long uptime would produce a similarly
sized pstree.

## Failure modes (per the experiment checklist)

| Failure mode | Observed? | Detail |
| --- | --- | --- |
| Prose findings instead of `record_finding` | No | The analyst wrote prose explaining *why* it could not commit findings, but it did not attempt to substitute prose for structured findings. |
| Hallucinated tool / argument names | No | Both calls used the exact MCP names with the documented `evidence_id` argument. |
| Unnecessary tool re-runs | No | One call per tool, parallelized. |
| Findings without `evidence_refs` | No | No findings written. |
| Self-marked DISPUTED | No | No findings written. |
| Out of context | No | Stopped at turn 3 with abundant context budget remaining. |

The analyst did exactly the thing the architecture is designed to
elicit: it refused to invent. It read the wrapped tool-result stub,
recognized the deadlock, named it accurately ("the wrapper saved the
results to disk and instructed me to read them via offset/limit/jq…
my role-defined toolset only exposes the five SIFT-Guard MCP
tools"), and stopped without fabricating PIDs, process names, or
parent-child claims.

## What actually happened

The MCP server's audit chain shows both calls succeeded:

```
line 9   tool=vol_pslist   ts=2026-05-05T23:20:11Z   evidence_id=6770da81-…
line 10  tool=vol_pstree   ts=2026-05-05T23:20:39Z   evidence_id=6770da81-…
```

Server-side runtimes were within the docstring-stated bands
(pslist ≈ 18 s, pstree ≈ 28 s). The full JSON payloads were returned
to Claude Code's MCP transport.

Claude Code's client-side tool-result handler then intercepted both
results because they exceeded the per-call token budget. For each,
it wrote the full payload to a file under
`/home/galvarino/.claude/projects/.../tool-results/` and substituted
a stub of this shape into the agent's tool-result message:

> Error: result (459,592 characters) exceeds maximum allowed tokens.
> Output has been saved to … Use `offset` and `limit` parameters to
> read specific portions of the file, search within it for specific
> content, and `jq` to make structured queries.

The stub assumes the agent has a `Read` tool that accepts
`offset`/`limit` and a shell to run `jq`. Both assumptions are false
for `process_analyst`: its frontmatter restricts it to the five
SIFT-Guard MCP tools and nothing else. The agent therefore had no
way to consume its own tool outputs.

Faced with this, the analyst (a) decided not to call `vol_psscan`
because it would produce a similarly unreadable result at ten-minute
cost, and (b) declined to commit findings on the grounds that doing
so without seeing the records would amount to fabrication. Both
decisions are correct under the role definition.

## Verdict

**C — Design has a structural problem.**

The structural problem is **a tool-result-size deadlock** between two
correct-in-isolation design decisions: the architectural restriction
of the analyst tool surface to typed MCP tools, and Claude Code's
handling of oversized tool returns by spilling to disk and demanding
the agent use `Read`/`jq`. Either decision alone is fine; in
combination they make a tool-restricted analyst unable to consume
the very results it requested.

Concretely: do **not** build `network_analyst` (or
`injection_analyst`) to the same v1 pattern. `vol_netscan` will hit
the same wall — the four-tool memory analyst surface that CLAUDE.md
sketches collapses on contact with realistic Windows memory images.
The constraint is also not soluble at the prompt-engineering level
("be more selective", "summarize before recording"), because the
agent never sees the records to be selective about.

### Remediation options, briefly

These are next-step candidates, not commitments. Naming the criterion
each one serves per the hackathon rubric.

1. **Server-side filter / projection parameters** on the existing
   tools. `vol_pslist(evidence_id, name_regex=…, pid_in=…,
   ppid_in=…, max_rows=…)`, `vol_pstree(evidence_id, root_pid=…,
   include_resolved=False)`, `vol_psscan(evidence_id,
   only_unlinked_from_pslist=True)`. The agent narrows iteratively;
   each call's output is bounded. Serves *Constraint Implementation*
   (architectural, not prompt-level) and *IR Accuracy* (less data,
   tighter focus). Cost: small surface expansion per tool, plus a
   schema-introspection update so `tests/test_no_path_fields.py`
   keeps holding the line on free-form input. Risk: the analyst now
   has to *plan* its filters, which raises the bar on autonomous
   reasoning.

2. **Server-side anomaly tools.** Move the cross-plugin diff and
   masquerading checks into the MCP server as
   `vol_process_anomalies(evidence_id)` returning ≤100 KB of
   structured anomaly records: `pslist∖psscan`, `psscan∖pslist`,
   parent-child mismatches against a known-good Windows lineage map,
   typo-squat candidates, suspicious-depth chains. The analyst
   becomes a thin orchestrator. Serves *Autonomous Execution Quality*
   (the structural validator now lives outside the prompt) and
   *Audit Trail Quality* (each anomaly record has fixed
   provenance). Cost: nontrivial server-side logic, plus we'd need
   to be careful that the validator-style tool doesn't swallow the
   evidence the validator subagent is supposed to weigh — a separate
   architectural question.

3. **A scoped Read tool.** Add `Read` to `process_analyst`'s
   frontmatter, restricted to the `tool-results/` directory of the
   current session. This is the smallest patch but it directly
   contradicts CLAUDE.md's Hard Rule #2 ("Architectural guardrails
   beat prompt guardrails") — the whole point of the typed-tool
   surface is that the agent cannot construct paths or do free-form
   reads. Adding `Read`, even scoped, dilutes the architectural
   claim and complicates the audit story (the audit chain no longer
   sees what the agent looked at). Listed for completeness; we
   should not pick this.

The recommendation is option 1 first — narrow the existing tools so
they can return small enough results to be read directly — and then
re-run the experiment without otherwise changing the agent prompt.
That run is the actual test of whether the restricted-surface design
can elicit useful analysis once the deadlock is removed. If the
re-run still produces zero findings or only prose, that's a stronger
Verdict B/C and pushes us toward option 2.

### What this experiment is *not* evidence of

- It is not evidence that an LLM cannot do this analysis. The
  analyst never saw the data.
- It is not evidence that the `record_finding` schema is wrong. It
  was never exercised.
- It is not evidence that the audit chain works end-to-end with a
  recorded finding. The genesis line is still the only one in
  `findings.jsonl`.
- It is not evidence that subagent dispatch is broken. The agent
  loaded, the tool surface was correctly restricted, and the
  termination was clean.

It *is* evidence that the four-memory-tool surface plus
unbounded-output wrappers is not a viable production architecture
for a Windows memory image of realistic size, and that the
analyst-side guardrail against fabrication holds.

## Files produced this run

- `.claude/agents/process_analyst.md` — agent definition (this file
  is what the experiment tested)
- `case-data/audit/sift-guard-mcp.jsonl` lines 9–10 — server-side
  audit of the two tool calls
- `docs/process-analyst-v1-rocba.transcript.md` — reconstructed
  turn-by-turn transcript
- `docs/process-analyst-v1-results.md` — this document

The saved tool-result files
(`/home/galvarino/.claude/projects/.../tool-results/mcp-sift-guard-vol_*-*.txt`)
are session-scoped and live outside the project tree; they are the
data the analyst could not consume.
