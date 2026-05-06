# SIFT-Guard

Autonomous DFIR agent built on the SANS SIFT Workstation toolset.
Submission for the SANS "Find Evil!" hackathon
([findevil.devpost.com](https://findevil.devpost.com/), deadline
15 June 2026).

A custom MCP server exposes typed, evidence-safe forensic tool
wrappers; analyst and validator subagents call those tools; a
plain-Python orchestrator drives a 5-step self-correction loop over
the resulting findings. Every action lands in one of four
hash-chained JSONL logs so any run is fully replayable from disk.

The differentiator vs. published reference submissions: **autonomous
iterative self-correction with cross-validation.** The validator is
its own subagent with a deliberately-restricted tool surface (it
can re-query the evidence but cannot write findings); the
orchestrator owns the promotion rules; analyst subagents can be
re-dispatched with focus context across iterations until the
finding set converges.

## Architecture

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

    %% Read paths.
    PA --> Tier1
    PA --> Tier2
    NA --> Tier1
    NA --> Tier2
    Val --> Tier1
    Val --> Tier2

    %% Write paths — role-restricted by frontmatter + schema.
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

See [`docs/architecture-diagram.md`](docs/architecture-diagram.md)
for the legend, the 12-tool table by writer role, and the
loop-narrative writeup.

## Documentation

| Doc | Purpose |
| --- | --- |
| [`docs/architecture-diagram.md`](docs/architecture-diagram.md) | This diagram + legend + tools table + V-C loop narrative. |
| [`docs/confidence-methodology.md`](docs/confidence-methodology.md) | Four confidence levels, three writer roles, six promotion rules R1-R6, worked examples from the live chains. |
| [`docs/loop-design.md`](docs/loop-design.md) | The 5-step ANALYZE / CORRELATE / PROMOTE / PLAN / WRITE loop, termination flags, sequential-dispatch rationale. |
| [`docs/validator-design.md`](docs/validator-design.md) | V-C hybrid design choices; why the validator is a subagent (not a function), why it can re-query plugins, why it sees only DRAFT findings. |
| [`docs/adversarial-robustness.md`](docs/adversarial-robustness.md) | Threat model, layered defenses, demo on the synthetic injection-content image. |
| [`docs/synthetic-demo-image.md`](docs/synthetic-demo-image.md) | Construction of the synthetic adversarial image. |
| [`docs/decisions-log.md`](docs/decisions-log.md) | Design rationale, deferred items, every architectural decision with date and reason. |

## Status

Week 7 day 1. 361 unit tests + 4 deselected integration tests. End-
to-end runs validated on the SANS Standard Forensic Case (Rocba)
and on the synthetic adversarial-robustness demo image.

## License

[MIT](LICENSE).
