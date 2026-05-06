# Architecture diagram

SIFT-Guard is an autonomous DFIR agent for SANS' "Find Evil!" 2026
hackathon. A custom MCP server exposes typed, evidence-safe forensic
tool wrappers; analyst and validator subagents call those tools; a
plain-Python orchestrator drives a 5-step self-correction loop over
the resulting findings. Every action lands in one of four
hash-chained JSONL logs so any run is fully replayable from disk.

## Diagram

```mermaid
flowchart TD
    %% --- Inputs ---
    Reg["register_evidence<br/>SHA-256 + chmod 444 + audit"]
    EvDir[("case-data/evidence/<br/>read-only after registration")]
    Reg --> EvDir

    %% --- MCP server tools ---
    subgraph MCP["SIFT-Guard MCP server (12 typed tools)"]
        Tier1["Tier-1 wrappers<br/>vol_pslist · vol_psscan<br/>vol_pstree · vol_netscan<br/>persists extractions/ + extractions.jsonl"]
        Tier2["Tier-2 analytical<br/>query_records · group_by<br/>set_difference · subtree"]
        RecF["record_finding"]
        RecC["record_correlation"]
        UpdF["update_finding"]
    end

    EvDir -->|read-only| Tier1
    Tier1 -.->|reads cached extractions| Tier2

    %% --- Subagents + orchestrator ---
    PA["process_analyst<br/>subagent"]
    NA["network_analyst<br/>subagent"]
    Val["validator<br/>subagent"]
    Orch["Orchestrator (Python)<br/>5-step loop:<br/>ANALYZE → CORRELATE →<br/>PROMOTE → PLAN → WRITE"]

    %% Read paths: every subagent can call tier-1 + tier-2.
    PA --> Tier1
    PA --> Tier2
    NA --> Tier1
    NA --> Tier2
    Val --> Tier1
    Val --> Tier2

    %% Write paths: role-restricted by frontmatter + schema.
    PA --> RecF
    NA --> RecF
    Val --> RecC
    Orch --> UpdF

    %% Control: orchestrator dispatches subagents.
    Orch -.->|dispatch| PA
    Orch -.->|dispatch| NA
    Orch -.->|dispatch| Val

    %% --- Chains ---
    Findings[("findings.jsonl<br/>DRAFT + UPDATE entries")]
    Corrs[("correlations.jsonl")]
    Iters[("iterations.jsonl")]
    Audit[("audit.jsonl<br/>every tool call, hash-chained")]

    RecF --> Findings
    UpdF --> Findings
    RecC --> Corrs
    Orch --> Iters

    %% Audit tap: every MCP tool call appends one line.
    Reg --> Audit
    Tier1 --> Audit
    Tier2 --> Audit
    RecF --> Audit
    RecC --> Audit
    UpdF --> Audit

    %% --- Per-writer-role coloring ---
    classDef analyst fill:#cce5ff,stroke:#0044cc,color:#003366
    classDef validator fill:#ffe5cc,stroke:#cc6600,color:#663300
    classDef orchestrator fill:#d5e8d4,stroke:#2e7d32,color:#1b5e20
    classDef chain fill:#fafafa,stroke:#888,stroke-dasharray:3 3,color:#333
    classDef storage fill:#fff8dc,stroke:#aa9,color:#333
    classDef tool fill:#ffffff,stroke:#444,color:#222

    class PA,NA analyst
    class Val validator
    class Orch orchestrator
    class Findings,Corrs,Iters,Audit chain
    class EvDir storage
    class Reg,Tier1,Tier2,RecF,RecC,UpdF tool
```

## Legend

| Element | Meaning |
| --- | --- |
| Blue boxes (`process_analyst`, `network_analyst`) | Analyst subagents — write `DraftFinding` entries via `record_finding`. |
| Orange box (`validator`) | Validator subagent — writes correlation entries only; cannot mutate findings. |
| Green box (`Orchestrator`) | Plain Python (not an LLM). Drives the 5-step loop and is the sole writer of `update_finding` (DRAFT → CONFIRMED / DISPUTED). |
| White boxes inside the MCP-server subgraph | The 12 typed MCP tools, grouped by role. |
| Yellow cylinder | Read-only evidence storage (chmod 444 from registration). |
| Grey dashed cylinders | The four hash-chained JSONL chains. |
| Solid arrow `→` | A direct call or write. |
| Dashed arrow `⇢` | Control / cache flow (orchestrator dispatches subagents; tier-2 reads cached extractions). |

The architectural constraint is encoded in **which arrows are
absent**, not just which are present. There is no arrow from the
validator to `record_finding` or `update_finding`; no arrow from
the analysts to `record_correlation` or `update_finding`; no arrow
from the orchestrator to `record_finding` or `record_correlation`.
The frontmatter of each subagent
(`.claude/agents/{process,network,validator}_analyst.md`)
restricts its visible tool surface; the schema (`server/schemas.py`)
restricts the payloads it can construct; the audit chain captures
every call regardless.

## MCP tools by writer role

The 12 tools the MCP server exposes, grouped by what's allowed to
call them. Every successful invocation appends one line to
`audit.jsonl`; every rejection appends a typed `<tool>:rejected_*`
line.

| Tool | Tier | Allowed callers |
| --- | --- | --- |
| `register_evidence` | bootstrap | Any caller (idempotent on the registered file's SHA-256) |
| `vol_pslist` | Tier-1 (memory) | Any subagent + the orchestrator's MCP client |
| `vol_psscan` | Tier-1 (memory) | Any subagent + the orchestrator's MCP client |
| `vol_pstree` | Tier-1 (memory) | Any subagent + the orchestrator's MCP client |
| `vol_netscan` | Tier-1 (memory) | Any subagent + the orchestrator's MCP client |
| `query_records` | Tier-2 (analytical) | Any subagent + the orchestrator's MCP client |
| `group_by` | Tier-2 (analytical) | Any subagent + the orchestrator's MCP client |
| `set_difference` | Tier-2 (analytical) | Any subagent + the orchestrator's MCP client |
| `subtree` | Tier-2 (analytical) | Any subagent + the orchestrator's MCP client |
| `record_finding` | finding writer | `process_analyst` and `network_analyst` only (DISPUTED self-mark rejected) |
| `record_correlation` | correlation writer | `validator` only |
| `update_finding` | promotion writer | The orchestrator only (DRAFT → DRAFT/CONFIRMED transitions) |

Tier-1 tools also persist the full Volatility output to
`case-data/extractions/<evidence_id>/<plugin>.json` (with a
`.sha256` sidecar) and append a chain line to `extractions.jsonl`.
Tier-2 tools never invoke Volatility — they read the cached
extractions and compose narrowed answers under a 10 KB
return-size budget.

## Data flow — the V-C self-correction loop in five sentences

The orchestrator's `run_loop()` reads the registered evidence's
`artifact_class` from `CASE.yaml` and dispatches the matching
analyst subagents (currently `process_analyst` + `network_analyst`
for memory images), each of which calls Tier-1 / Tier-2 tools and
commits its observations as DRAFT findings via `record_finding`.
The orchestrator then dispatches the `validator` subagent with a
summary of every DRAFT finding; the validator independently calls
the same tool surface and commits cross-source / cross-plugin
observations as one of five correlation types via
`record_correlation`. The orchestrator's PROMOTE step applies the
six-rule R1-R6 engine
(`orchestrator/promotion.py`,
documented in `docs/confidence-methodology.md`) per finding and
writes any non-R6 outcome via `update_finding`. The PLAN step
computes the four termination flags
(`R_a_zero_unresolved`, `R_b_disputed_set_unchanged`,
`R_c_token_budget_exceeded`,
`max_iterations_reached`); if none fires and at least one
`request_followup` correlation is pending, the next iteration
dispatches the named analyst with the requested `focus_context`.
The WRITE step appends one record to `iterations.jsonl`, and the
loop terminates when any flag fires or no follow-up remains —
every iteration's full provenance is reconstructible from the
four hash-chained logs alone.

## Sources

This diagram reflects what ships as of the
[`Closing-out` commit](../). It is consistent with:

- `orchestrator/loop.py` — the 5-step loop, dispatch, termination
- `orchestrator/promotion.py` — R1-R6 rule engine
- `server/schemas.py` — three-writer chain schemas + Literal
  constraints on payload values
- `server/tools/{evidence,memory,analytical,findings,correlations}.py`
  — the 12 tool implementations
- `.claude/agents/{process,network,validator}_analyst.md` — the
  per-subagent tool-surface restriction (the architectural
  enforcement that makes "validator can't write findings" true at
  the agent surface, not just at the schema)
- `docs/confidence-methodology.md` — what the loop's PROMOTE step
  does in detail
- `docs/loop-design.md`, `docs/validator-design.md`,
  `docs/decisions-log.md` — design rationale and deferred items

If the diagram and the implementation ever drift, the
implementation wins; file a `decisions-log.md` entry for triage
rather than editing the code to match.
