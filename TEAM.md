# SIFT-Guard — team & process working file

Project orientation, roles, build plan, and dev-session behavior.
Loaded by humans and by Claude Code dev sessions at the repo root,
but **not** auto-injected into analyst subagent context — that's
why this content was lifted out of `CLAUDE.md` (which IS injected
into every analyst, where every kilobyte costs tokens across all
parallel dispatches).

If you are editing this file, you are editing team/process notes.
Analyst-relevant content (hard rules, architecture, evidence
integrity, validation modes) belongs in `CLAUDE.md`.

## Project

A custom MCP server exposing SANS SIFT Workstation forensic tools as
typed, read-only, evidence-safe functions, driven by an autonomous
iterative self-correction loop. Submission for the SANS "Find Evil!"
hackathon (<https://findevil.devpost.com/>, deadline 15 June 2026).

## Reference architecture: Valhuntir

Valhuntir (<https://github.com/AppliedIR/Valhuntir>, by SANS author
Steve Anson) is the published reference submission. Treat its
patterns as known-good and copy them: DRAFT state for findings,
provenance chains, JSONL audit logs, typed MCP tool functions,
SHA-256 evidence registration with chmod 444/555, the case
directory layout. Do NOT replicate its breadth (gateway aggregator,
web portal, multi-VM deployment, HMAC-signed approvals, 22K-record
RAG, 2.6M-row Windows triage database).

Our differentiator is **autonomous iterative self-correction with
cross-validation across whatever artifact families exist in the
case.** Valhuntir is human-in-the-loop, the rubric tiebreaker is
autonomous self-correction. That gap is our wedge.

## Hackathon judging criteria, optimization order

1. **Autonomous Execution Quality** (tiebreaker) — agent reasons
   about next steps, handles failures, self-corrects in real time
2. **IR Accuracy** — findings correct, hallucinations caught
3. **Breadth and Depth of Analysis** — depth beats shallow breadth
4. **Constraint Implementation** — architectural guardrails > prompt
   guardrails
5. **Audit Trail Quality** — every finding traceable to a tool
   execution
6. **Usability and Documentation** — another practitioner can deploy

When you make a design choice, name which criterion it serves.

## Repository layout

```
/                           # repo root, CLAUDE.md + TEAM.md live here
  case-data/                # SANS case (gitignored, large)
    evidence/               # original evidence, chmod 444 after registration
    extractions/            # working copies, anything that needs writes
    CASE.yaml               # case metadata + evidence inventory + classes
    findings.jsonl          # DRAFT | CONFIRMED | DISPUTED findings (hash-chained)
    correlations.jsonl      # cross-validation records (hash-chained)
    iterations.jsonl        # one entry per self-correction loop iteration
    audit/
      sift-guard-mcp.jsonl  # every MCP call, hash-chained
      rejections.jsonl      # operator-console side-channel: redacted inputs for ! MCP lines
  server/                   # the MCP server
    main.py                 # stdio entrypoint
    schemas.py              # pydantic models for every tool
    audit.py                # hash-chained JSONL writer
    rejections_log.py       # side-channel rejections writer
    findings_log.py         # hash-chained findings writer
    correlations_log.py     # hash-chained correlations writer
    extractions.py          # tier-1 extraction store
    tools/                  # one module per tool family
      memory.py             # vol 3 plugin wrappers (tier-1 memory)
      disk.py               # MFT/Prefetch/EVTX/Registry wrappers (tier-1 disk)
      analytical.py         # query_records, group_by, set_difference, subtree (tier-2)
      findings.py           # record_finding, update_finding
      correlations.py       # record_correlation
      rag.py                # rag_query
      evidence.py           # register_evidence
    runners/                # local + ssh_remote + disk_mount execution
  orchestrator/             # CLI + loop driver
    main.py                 # `run` / `run-case` subcommands
    loop.py                 # 5-step self-correction loop
    dispatch.py             # claude -p subagent dispatch + per-host .mcp.json synthesis
    inventory.py            # evidence-directory scanner
    manifest.py             # CaseManifest schema
    iterations_log.py       # hash-chained iterations writer
    promotion.py            # R1-R6 promotion rules
  sift_guard/               # operator CLI (`sift-guard analyze`)
    cli.py                  # argparse + flow
    display.py              # live console renderer (audit-tail thread)
    preflight.py            # OS-guess probe before dispatch
  reporting/                # post-run summary + report.md generator
  rag/                      # forensic knowledge base (FAISS index)
  scripts/                  # one-off helper scripts (e.g. seed_synthetic_demo.py)
  tests/                    # pytest
  docs/                     # human-readable documentation
    architecture-diagram.md
    accuracy-report.md
    confidence-methodology.md
    adversarial-robustness.md
    dataset-inventory.md     # HUMAN-ONLY — agent must never read this
    decisions-log.md
    demo-script.md
    devpost-description.md
    execution-logs/          # hackathon deliverable #8
    archive/                 # superseded run results, design notes
  .claude/agents/           # subagent system prompts
  CLAUDE.md                 # auto-injected into every analyst — analyst-relevant rules only
  TEAM.md                   # this file — operator/team context, NOT injected
  README.md                 # public-facing
  pyproject.toml
  setup-sift-guard.sh       # one-shot SIFT VM installer
```

## Stack

Python 3.11+. Official `mcp` SDK. pydantic for schemas. pytest +
ruff. Volatility 3 (NOT 2 — verify with `vol --version`). plaso /
log2timeline.py. RegRipper. ewf-tools. SIFT Workstation OVA in a VM
(VirtualBox or VMware). Claude Code as the runtime. Fallback for the
agent harness: thin Python orchestrator using the Anthropic Messages
API directly with asyncio.gather for parallel analyst dispatch.

## Build order (8 weeks, ~400 person-hours, 5 official members)

| Week | Focus |
|---|---|
| 1 | Verification: read case-background materials, verify Volatility 3 reads the memory image, validate Claude Code subagent parallel dispatch (or commit to Python fallback), download Windows symbol pack, finalize project name, install Protocol SIFT, study Valhuntir source |
| 2 | MCP scaffolding + thin RAG (200 records: MITRE ATT&CK + SANS public posters + curated Sigma) + evidence read-only enforcement with mount validation + `<evidence>` delimiter system + artifact_class detector |
| 3-4 | Tool wrappers — start with the memory MVP set (vol pslist, psscan, pstree, netscan, malfind, cmdline + register_evidence), pydantic schemas, parsers, unit tests. Add disk/registry/eventlog wrappers as scaffolding |
| 5 | Subagent or orchestrator wiring, dispatch logic that reads `CASE.yaml` and selects analysts, end-to-end smoke test |
| 6 | Validator + 5-step loop + iterations.jsonl + cross-plugin validation rules + the synthetic "demo case" (runs full loop in <2 min for the screencast) |
| 7 | Accuracy benchmark (5 runs each, median + range); cross-source on a public disk+memory pair if available. Expand RAG to 1-2K records |
| 8 | All 8 deliverables: 5-min demo screencast, Devpost writeup, accuracy report, README, architecture diagram, dataset docs, try-it-out instructions, redacted execution logs |

## Submission deliverables (missing any one = elimination)

1. Code repo (GitHub, MIT or Apache-2.0)
2. Demo video, 5 min max, includes a live self-correction sequence
3. Architecture diagram
4. Written project description (Devpost format)
5. Dataset documentation
6. Accuracy report with documented failure modes
7. Try-it-out instructions
8. Agent execution logs (real, redacted if needed)

Each needs a named owner. Track in `docs/decisions-log.md`.

## Roles (5 official Devpost members + 1 unofficial collaborator)

- **Lead/architect** — MCP server core, audit logging, integration
- **Memory engineer** — Volatility 3 wrappers (primary load)
- **Disk/triage engineer** — disk + registry + eventlog wrappers,
  artifact_class detector
- **AI/agent engineer** — subagent prompts, validator logic, the loop
- **Docs/QA owner** — ground truth fixtures, accuracy report, demo
  video, Devpost writeup. Critical role — the rubric rewards
  documented failure modes and that document needs an owner.

## How to behave in this repo (dev sessions)

When the user gives you a task, identify which hat applies and state
it in one line at the top of your reply.

- **DFIR mentor** — when explaining artifacts, attack chains, SIFT
  tools, or interpreting evidence
- **MCP/agent architect** — when designing tool schemas, subagent
  logic, the loop, or evidence boundaries
- **Pair programmer** — when writing Python, schemas, tests, configs
- **Submission editor** — when drafting deliverables

When you don't know something (a Volatility 3 plugin's exact name, a
SIFT tool's flags, the current MCP SDK signature), say so plainly and
suggest verification on the SIFT VM, in the official docs, or in the
Valhuntir source. Never invent.

When the case data isn't yet downloaded or registered, say so and
ask the user to confirm before assuming.

When a question is ambiguous, ask one clarifying question, max. Then
proceed with stated assumptions. The team has 10 hrs/week per person
— don't stall them.
