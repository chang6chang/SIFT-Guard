# Agent harness decision — Claude Code subagents over a custom Python orchestrator

Permanent record of the decision to use Claude Code subagents as the
primary execution harness for SIFT-Guard's analyst orchestration, the
empirical evidence behind the decision, and the constraints that
decision creates for downstream weeks.

Date: 2026-05-05.

## 1. Question

CLAUDE.md's Week-5 plan named two candidate harnesses for the analyst
fan-out at the heart of the 5-step self-correction loop:

- **Primary:** Claude Code subagents defined in `.claude/agents/*.md`,
  dispatched by the parent session.
- **Fallback:** a thin Python orchestrator built directly on the
  Anthropic Messages API, using `asyncio.gather` for parallel analyst
  dispatch.

The choice is load-bearing: the Triage step (step 1 of the loop)
requires that the orchestrator can fan out to every active analyst in
a single turn and collect their results in roughly the time of the
slowest analyst, not the sum of all analysts. We needed to know
whether Claude Code's subagent surface delivered that property
architecturally or only in marketing.

Three sub-questions had to be answered before committing:

1. Can the parent **force-dispatch a subagent by name** (deterministic
   roster), or is dispatch only triggered by description-matching
   heuristics (non-deterministic, unsuitable for an audited pipeline)?
2. Do multiple subagent dispatches in a single parent turn run **in
   parallel**, or are they serialized by the harness?
3. Is the `tools:` frontmatter allowlist enforced **architecturally**
   by the harness (a tool not in the allowlist literally cannot be
   called), or is it a system-prompt-level instruction the model can
   violate? This is the rubric question — Constraint Implementation
   ranks "architectural guardrails > prompt guardrails."

The published Claude Code documentation (per the project knowledge
agent's research, also dated 2026-05-05) was not conclusive on
question 2. It pointed parallel use cases at a separate experimental
"agent teams" feature and said "subagents are not for parallel
execution." That contradicted the in-prompt guidance shipped with the
`Agent` tool itself, which states the opposite. We chose to settle
the disagreement empirically rather than reason from documentation
alone.

## 2. Method

A three-test hello-world experiment under
`.claude/agents/hello_alpha.md`, `hello_beta.md`,
`hello_restricted.md`. The test files were intentionally minimal: each
defined only a name, a description, a `tools:` allowlist, and a
single-line task. The three tests were:

| # | Subagent | Body | Question answered |
|---|---|---|---|
| 1 | `hello_alpha`, `tools: [Bash]` | `sleep 5 && date +%s.%N`, return as `ALPHA_DONE_AT=<ts>` | Forced-by-name dispatch works |
| 2 | `hello_alpha` + `hello_beta` in one parent turn | identical sleep+timestamp; compare delta | Real parallelism vs. serialization |
| 3 | `hello_restricted`, `tools: []` | "Attempt to read `CLAUDE.md` and report what happens" | Tool restriction is architectural |

Tests 1 and 3 were single dispatches; Test 2 was two `Agent` tool
calls issued in the same assistant turn. The session was restarted
between writing the subagent files and dispatching them — required,
because subagent definitions are loaded at session start (see §5).

## 3. Results

| Test | Result | Implication |
|---|---|---|
| **1. Forced dispatch by name** | **PASS.** `Agent(subagent_type="hello_alpha", ...)` accepted by harness. Subagent ran. Returned `ALPHA_DONE_AT=1777963553.879070819` as the last line of its assistant message. Parent saw only that final line — no `Bash` tool-call transcript, no intermediate text. `duration_ms: 10856`, `tool_uses: 1`. | Forced-by-name dispatch is real and schema-validated. The harness rejects unknown subagent names. Final-message-only output is confirmed — analysts must use a structured return contract because the validator only sees the analyst's final message. |
| **2. Parallelism** | **PARALLEL.** Two `Agent` calls in a single assistant turn. `ALPHA_DONE_AT = 1777963569.670748434`, `BETA_DONE_AT = 1777963570.354407318`. **Delta = 0.684 s.** Each subagent slept 5 s; serial execution would have produced ≥5 s delta. Both subagents reported `duration_ms` of 9.2–9.5 s, consistent with concurrent start. | The 5-step loop's Triage step can use Claude Code subagents directly. The published-docs claim that "subagents are not for parallel execution, use agent teams instead" is wrong for the `Agent`-tool path in the Claude Code version we are targeting. |
| **3. Tool restriction** | **BLOCK CONFIRMED, narration UNRELIABLE.** Subagent's frontmatter `tools: []`. It claimed it attempted Read and was blocked by a `PreToolUse:Read` hook. Response usage was `tool_uses: 0` — the harness never recorded a tool invocation. We have no `PreToolUse:Read` hook configured. The subagent fabricated the specific error text. Separately, the subagent reported that the contents of `CLAUDE.md` were injected into its context via the system-reminder mechanism. | Two findings. **(a)** Architectural block holds: `tools: []` removes Read from the palette; the file genuinely cannot be read. The Hard Rule #2 property required by the rubric is real. **(b)** CLAUDE.md auto-injection is a leak in the ground-truth-isolation architecture — addressed separately in `docs/decisions-log.md` 2026-05-05. **(c)** Subagent self-reporting of harness behavior is not trustworthy; the audit log cannot rely on subagent prose to record what the harness did. |

## 4. Decision

**Claude Code subagents defined in `.claude/agents/*.md` are the
primary harness for SIFT-Guard's analyst orchestration.** The Week-5
wiring step in CLAUDE.md proceeds against this surface directly.

**The Python orchestrator fallback (Anthropic Messages API +
`asyncio.gather`) is parked, not deleted.** It remains a documented
break-glass option in CLAUDE.md's stack section. It is no longer the
primary contingency for Triage-step parallelism, because parallelism
has been demonstrated on the primary path. It would be reactivated
only if a future Claude Code change broke forced-by-name dispatch,
broke parallel `Agent` tool calls, or removed the architectural
enforcement of the `tools:` allowlist.

This decision serves rubric criterion 4 (Constraint Implementation —
"architectural guardrails > prompt guardrails") directly: the
analysts' inability to reach `docs/`, `.git/`, or the source tree is
enforced by the harness's tool palette, not by a sentence in a
system prompt.

## 5. Constraints discovered

The decision is not free. It carries three constraints that flow into
the analyst design.

### 5.1 Final-message-only output → structured return contract

The parent receives only the subagent's final assistant message. No
tool-call transcript, no intermediate text, no streaming partials.
Anything an analyst learns during its run must be funneled through
its last message, or it is lost.

**Implication:** every SIFT-Guard analyst returns a strict, parseable
contract on the last lines of its response. The chosen format is a
single fenced JSON block at the bottom of the message:

````
... analyst free-form reasoning ...

```json
{
  "analyst": "process_analyst",
  "iteration": 1,
  "draft_findings": [
    {
      "id": "F-001",
      "summary": "...",
      "confidence": "MEDIUM",
      "validation_mode": "single_source",
      "source_artifacts": [...],
      "tool_calls": ["mcp__sift_guard__memory_pslist@<call_id>"]
    }
  ],
  "errors": []
}
```
````

The validator parses the trailing fenced block; the free-form
reasoning above it is stored verbatim in the audit log but not used
for finding generation.

### 5.2 Session-startup loading → subagent files are bootstrap-tier

`.claude/agents/*.md` files are loaded by the harness at session
start. Files added mid-session are not visible to the running
session — `Agent(subagent_type="X", ...)` returns
`Agent type 'X' not found` until Claude Code is restarted. This was
observed directly when the three test files were written and
immediately dispatched: dispatch failed; restarting the session and
re-dispatching succeeded.

**Implication:** the analyst roster is part of project bootstrap, not
runtime configuration. The four analyst `.md` files live in
`.claude/agents/` and are committed to git alongside `pyproject.toml`,
not generated by the orchestrator at runtime.

### 5.3 CLAUDE.md auto-injection leak → CLAUDE.md must be policed

Every subagent dispatched from this directory receives `CLAUDE.md`
verbatim in its system context, regardless of its `tools:` allowlist.
This is the harness's standard project-context behavior. It was
observed directly in Test 3 (a subagent with `tools: []` and no
ability to read any file still reported the contents of CLAUDE.md
were available to it).

**Implication:** CLAUDE.md must contain only architectural rules,
dispatch logic, and repository conventions. Case-scenario facts,
ground-truth artifacts, and per-run findings must never land in
CLAUDE.md, because every analyst would see them and the autonomy
claim would collapse silently. A banner header was added to CLAUDE.md
on 2026-05-05 making this rule explicit. A Week-5 task investigates
whether per-subagent `systemPrompt` overrides can suppress the
auto-injection entirely; if they can, every analyst adopts the
override so the architectural guarantee no longer depends on CLAUDE.md
hygiene. See `docs/decisions-log.md` 2026-05-05 entry "CLAUDE.md
auto-injection leak."

## 6. Implications for Week 5

Four analyst `.md` files to define under `.claude/agents/`. Tool
allowlists below reference SIFT-Guard MCP tool names that do not yet
exist — the MCP scaffolding lands in Week 2 and the wrappers in
Weeks 3–4. The analyst files can be written in Week 5 once the tool
names are stable; the placeholders here are the planned namespace and
serve as the schema-introspection-test target (see Week-3 task in
`docs/decisions-log.md` 2026-05-05).

| Subagent | Activates when | Planned `tools:` allowlist (placeholder) |
|---|---|---|
| `process_analyst` | `memory_image` registered in `CASE.yaml` | `mcp__sift_guard__memory_pslist`, `mcp__sift_guard__memory_psscan`, `mcp__sift_guard__memory_pstree`, `mcp__sift_guard__memory_cmdline`, `mcp__sift_guard__memory_handles` |
| `network_analyst` | `memory_image` | `mcp__sift_guard__memory_netscan`, `mcp__sift_guard__memory_netstat` |
| `injection_analyst` | `memory_image` | `mcp__sift_guard__memory_malfind`, `mcp__sift_guard__memory_dlllist`, `mcp__sift_guard__memory_ldrmodules`, `mcp__sift_guard__memory_modules`, `mcp__sift_guard__memory_modscan` |
| `validator` | always | `mcp__sift_guard__correlation_cross_plugin`, `mcp__sift_guard__correlation_cross_source`, `mcp__sift_guard__correlation_cross_artifact`, `mcp__sift_guard__rag_search` |

Hard requirements for every analyst file, enforced by the Week-3
schema-introspection test:

- `tools:` is present and explicit (no implicit defaults).
- Every entry in `tools:` matches `mcp__sift_guard__*`.
- No `Read`, `Bash`, `Grep`, `Edit`, `Write`, `Glob`, or `WebFetch`.
- Frontmatter `description` is sharp enough that the agent dispatch
  table in CLAUDE.md still matches even if forced-by-name dispatch
  ever regresses to description-matching.

The validator's allowlist is intentionally narrower than the
analysts': it has no plugin tools and cannot run Volatility itself.
Its job is to consume DRAFT findings from the analysts and run
correlation queries. Forcing it through dedicated correlation MCP
tools (rather than re-running plugins) keeps a clean separation
between evidence acquisition and evidence reasoning, and makes the
audit trail straightforward to read.

The `disk_analyst`, `registry_analyst`, and `eventlog_analyst`
defined in CLAUDE.md's dispatch table stay dormant for the Rocba case
(memory-only) but their `.md` files should still ship — the
artifact-driven dispatch logic in `server/dispatch.py` reads
`CASE.yaml` and activates whichever analysts are needed by the
current case. Empty rosters are fine; missing rosters are not.

---

**Standup line:** Subagent harness verified — forced-by-name dispatch
and parallel fan-out both work, tool allowlists are architecturally
enforced, Python orchestrator fallback is parked, Week 5 builds the
four analyst `.md` files against placeholder `mcp__sift_guard__*`
tool names.
