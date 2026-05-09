# Execution logs — submission package

Required Devpost deliverable per the SANS "Find Evil!" 2026 hackathon
rubric ("Agent execution logs (real, redacted if needed)"). This
directory contains the hash-chained JSONL logs produced by
SIFT-Guard across six orchestrator runs over three independent
evidence corpora (Rocba single-host memory, synthetic-injected
adversarial, and SRL-2015 four-host APT teaching case).

## What you get

| File | Lines | Size | Role |
|---|---|---|---|
| `audit/sift-guard-mcp.jsonl` | 1266 | 588K | **Primary deliverable.** Every MCP tool call (success and rejection paths), hash-chained via `prev_line_hash` / `this_line_hash`. Genesis line's `prev_line_hash` is `000…0`. |
| `findings.jsonl` | 279 | 376K | DRAFT entries written by analyst subagents via `record_finding`; UPDATE entries written by the orchestrator via `update_finding`. Discriminated on `record_kind`. |
| `correlations.jsonl` | 160 | 256K | Validator's typed correlation entries (`corroborates`, `contradicts`, `strengthens`, `weakens`, `request_followup`, `cross_host`). |
| `iterations.jsonl` | 15 | 116K | One record per loop iteration with the four-flag termination check (`R_a_zero_unresolved`, `R_b_disputed_set_unchanged`, `R_c_token_budget_exceeded`, `max_iterations_reached`). |
| `extractions.jsonl` | 31 | 24K | Tier-1 cache provenance: SHA-256 of every persisted Volatility / disk extraction stored under `case-data/extractions/`. |

## Redaction status: none required

> **The logs are byte-for-byte copies of the on-disk chains. Hash
> verification passes end-to-end on the published files.**

The SIFT-Guard architecture was designed so the chains cannot leak
sensitive content by construction. Specifically:

1. **Audit-log payloads are hashed, not stored.** Every audit
   entry records only `input_hash` and `output_hash` (SHA-256 of
   the call's serialized arguments and result), never the raw
   bytes. Full file paths, evidence content, and tool-call
   arguments are hashed at the boundary and discarded — the chain
   is compact and PII-free by design.
2. **MCP error-message sanitization rule** (`docs/decisions-log.md`,
   2026-05-05). Every tool catches known exceptions and returns
   sanitized messages that do not echo agent-supplied input.
   `Path outside evidence directory rejected` is the canonical
   shape — the offending path is never reflected.
3. **Closed Literal payload schemas.** `record_finding`'s
   `category` and `severity`, `record_correlation`'s
   `correlation_type`, `update_finding`'s `promotion_rule` are all
   pinned to closed Literal sets. Free-form text fields exist
   (finding `title`, `description`, `hypothesis`) but are
   pydantic-validated for size and pure UTF-8.
4. **Path confinement at `register_evidence`.** The single on-ramp
   for arbitrary paths refuses anything outside `<case_dir>/evidence/`.
   Every other tool takes only an `evidence_id` (UUIDv4) — the
   agent cannot construct a path.

A pre-publication audit (Step 2 of the packaging procedure) ran the
following pattern set against every file in this directory:

| Pattern | Result |
|---|---|
| `sk-ant-…` API key prefixes | none |
| Anthropic / API key / token / secret / credential keywords | only forensic finding text discussing credential-attack TTPs (T1110, T1003, T1110.001) — legitimate content |
| Real user home paths (`/home/galvarino/`, `/Users/`, `C:\Users\`) | none |
| Email addresses | none |
| SSH connection strings, hostname FQDNs, internal infrastructure | none |
| External IPv4 addresses | only forensic-evidence content (Rocba's RDP attacker IPs `81.30.144.115`, `213.202.233.104`, `173.173.88.154`, etc.; SRL-2015 internal `10.3.58.*`; synthetic `192.168.1.*`) — these are precisely the data the logs exist to record |

Result: zero strings required redaction. Architectural defenses
removed the failure modes that traditional log-publication
workflows have to redact for.

## Hash-chain verification

Verification on the published copies uses the standard chain rule
— every line's `prev_line_hash` matches the prior line's
`this_line_hash`, with the genesis line at `prev_line_hash = "0" * 64`.

Quick check using the SHA-256-linked invariant only:

```python
import json
prev = "0" * 64
with open("docs/execution-logs/audit/sift-guard-mcp.jsonl") as f:
    for i, line in enumerate(f, 1):
        entry = json.loads(line)
        assert entry["prev_line_hash"] == prev, f"break at line {i}"
        prev = entry["this_line_hash"]
print("OK")
```

This passes end-to-end on the audit chain (1266 lines). Equivalent
checks pass on `findings.jsonl` (`prev_finding_hash` /
`this_finding_hash`), `correlations.jsonl` (`prev_correlation_hash`
/ `this_correlation_hash`), `iterations.jsonl`
(`prev_iteration_hash` / `this_iteration_hash`), and
`extractions.jsonl` (`prev_extraction_hash` /
`this_extraction_hash`). Three writers, three roles, four chains.

The chains use distinct hash field names per chain so a line read
out of context cannot be silently misinterpreted as a line from a
different chain.

## Run map — which lines came from which run

The six orchestrator runs are visible end-to-end in
`iterations.jsonl`. Cross-referencing with the accuracy report
(`docs/accuracy-report.md` § "Iterations"):

| iter line | Timestamp (UTC) | Run | Iter # | Notes |
|---|---|---|---|---|
| 1 | 2026-05-06 19:48:58 | Run 1 — Rocba (early) | 1 | Manual stop after analyst dispatch — pre-validator iteration |
| 2 | 2026-05-06 20:00:36 | Run 2 — Rocba (validator first) | 1 | Validator's first run, 11 invalid-payload rejections (failure mode #3) |
| 3-5 | 2026-05-06 22:22 — 22:30 | Run 3 — Synthetic | 1-3 | `max_iterations_reached` (cap=3, natural quiescence) |
| 6-7 | 2026-05-06 23:01 — 23:09 | (Synthetic re-run) | 1-2 | Pre-rag-sigma synthetic re-validation |
| 8-9 | 2026-05-07 08:24 — 08:34 | Run 4 — Rocba (post-R5-fix) | 1-2 | `no_followup_pending` short-circuit |
| 10-11 | 2026-05-08 22:52 — 23:03 | Run 5 — Rocba (post-rag-sigma, `v0.7-rag-sigma`) | 1-2 | First naturally-fired R_b across all runs; first run with autonomous rag_query |
| 12-13 | 2026-05-08 23:38 — 23:48 | (SRL-2015 dry run) | 1-2 | Path-translation-fix verification before the headline run |
| **14-15** | **2026-05-09 00:25 — 10:01** | **Run 6 — SRL-2015 (4-host)** | **1-2** | **The headline multi-host run.** 10 cross_host correlations, 8 rag_query calls, R_b termination. The 9h 36min gap between iter 1 and iter 2 is failure mode #11 — the validator subprocess pipe-buffer deadlock (work product intact, wallclock guarantee violated) |

`iterations.jsonl` row 10–15 are the runs the accuracy report's
SRL-2015 section measures against; row 15's `iteration` payload
contains the full per-host findings count, the `cross_host`
correlation count, and the `R_b_disputed_set_unchanged` flag set
to `true`.

### Findings count per evidence_id (DRAFT writes)

Cross-checked against the chains as published:

| evidence_id (first 8) | Filename | DRAFTs |
|---|---|---|
| `6770da81…` | `Rocba-Memory.raw` | 63 |
| `c60883bc…` | `synthetic-injected.raw` | 12 |
| `e51824c8…` | `win7-64-nfury-memory-raw.001` (SRL) | 14 |
| `d05750d4…` | `win7-32-nromanoff-memory-raw.001` (SRL) | 12 |
| `8bd306ce…` | `win2008R2-controller-memory-raw.001` (SRL) | 12 |
| `c6c61e79…` | `xp-tdungan-memory-raw.001` (SRL) | 7 |

SRL totals: 14 + 12 + 12 + 7 = 45 — matches the accuracy report's
"45 substantive findings (SRL-2015, 4 hosts)" exactly. Total DRAFT
findings across the three corpora: 63 + 12 + 45 = 120, matching
the accuracy report's headline. The remaining lines in
`findings.jsonl` are `record_kind="update"` entries written by
the orchestrator under R1 / R3 / R4 promotion rules.

## What's NOT in this package

- **`case-data/CASE.yaml`** — the registration ledger. Contains
  evidence-id → on-disk-path mappings. Not included because the
  paths are local to the team's filesystem; the chains record
  evidence by `evidence_id` (UUID) and that is sufficient for
  replay against an independently-registered copy.
- **`case-data/extractions/<evidence_id>/<plugin>.json`** — the
  full Volatility / disk-tool outputs that tier-1 wrappers
  persist. Sizes range from ~50 KB (small process lists) to
  ~800 KB (full pstree on Rocba); cumulatively several MB.
  `extractions.jsonl` (included here) records the SHA-256 of
  each so replay can verify cache integrity, but the bulk JSON
  is not packaged. To replay end-to-end, register the same
  evidence file on the same Volatility build and the cache will
  re-populate identically.
- **`case-data/manifest.json`** — the multi-evidence
  `CaseManifest` written by `run-case` invocations. Contains
  evidence-id → host-id grouping; redundant with the host_id
  field already present on every finding.
- **Orchestrator stdout logs** (`case-data/*.log`) — verbose
  run-time logging. Not part of the chain-of-custody
  deliverable.

## How to replay

The three primary chains have a strictly-defined replay
contract documented in `docs/confidence-methodology.md`. Briefly:

1. Re-register the same evidence files via `register_evidence` —
   you will get different `evidence_id` UUIDs (those are
   generated server-side per registration), but the SHA-256s
   will match the chain-recorded values.
2. Tier-1 tools will re-populate the extractions cache
   identically (Volatility 3 is deterministic on the same image
   + symbol pack).
3. The orchestrator's `promote()` is a pure function — given
   the chained correlations and current finding state, it
   produces identical `PromotionDecision` outputs.
4. The four chains are append-only; replaying produces a fresh
   on-top-of-existing chain rather than overwriting these files.

The hash chains are tamper-evident: if a single byte in any
published file changes, the genesis-to-tail verification breaks
on the line containing the changed byte. Verify before quoting.

## Sources

- `docs/accuracy-report.md` — chain-truth numbers,
  failure-mode catalog, run table
- `docs/architecture-diagram.md` — V-C hybrid pattern, MCP tools
  by writer role, four-chain layout
- `docs/confidence-methodology.md` — promotion rules R1–R6,
  termination flags, replay contract
- `docs/decisions-log.md` — MCP error-message sanitization rule
  (2026-05-05); audit-payload-hash design decision
- `server/audit.py` — the hash-chained writer; single canonical
  field-ordering + SHA-256 implementation
- `server/correlations_log.py`, `server/findings_log.py`,
  `server/extractions_log.py`, `orchestrator/iterations_log.py`
  — the four chain writers, one per chain
