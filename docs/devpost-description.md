# SIFT-Guard — autonomous cross-host forensic agent

## Inspiration

LLM-driven forensic tooling has a credibility problem. Public
demonstrations of "Protocol SIFT" — using a general-purpose
assistant to drive Volatility, plaso, and friends — show the
model fabricating tool names, inventing flags, and confidently
asserting findings on evidence it never actually parsed. A
finding that cites a misspelled plugin name and an artifact
path under a directory that doesn't exist is worse than no
finding — it gives the analyst a false signal to chase down.

The published reference submission for the SANS "Find Evil!" 2026
hackathon, Valhuntir (Steve Anson, AppliedIR), takes the opposite
trade: impressive breadth — a gateway aggregator, a 22K-record
RAG corpus, a 2.6M-row Windows triage database, a multi-VM
deployment, HMAC-signed approval flows — but every finding
routes through a human analyst for validation. That scales
linearly with analyst hours; it doesn't scale with case volume
during an active incident.

The gap we built into is *autonomous cross-source validation*. A
single-source finding — an unusual process in one host's memory —
is one observation away from being sysadmin tooling. The same
finding observed in two independently-acquired sources, or in two
independent tool paths on the same source (psscan and pslist
disagreeing on a PID), is fundamentally more trustworthy. The
SANS rubric ranks autonomous self-correction as criterion #1 —
the explicit tiebreaker. We built for that criterion.

---

## What it does

SIFT-Guard analyzes forensic memory images (and disk images) from
one or more hosts simultaneously. The MCP server exposes 19 typed
tool wrappers: six tier-1 memory plugins (`vol_pslist`,
`vol_psscan`, `vol_pstree`, `vol_netscan`, `vol_cmdline`,
`vol_malfind`); four tier-1 disk wrappers (`disk_mft_timeline`,
`disk_prefetch`, `disk_evtx`, `disk_registry`); four tier-2
analytical primitives (`query_records`, `group_by`,
`set_difference`, `subtree`); `rag_query` against a 2844-record
corpus of MITRE ATT&CK techniques and Sigma detection rules;
`register_evidence` for cataloging; and three writers
(`record_finding`, `record_correlation`, `update_finding`) — one
per role.

Three analyst subagents (`process_analyst`, `network_analyst`,
`disk_analyst`) read evidence and emit DRAFT findings, each
restricted by frontmatter to a specific tool surface. A separate
validator subagent re-queries the evidence, autonomously consults
the RAG corpus, and emits one of six correlation types:
`corroborates`, `contradicts`, `strengthens`, `weakens`,
`request_followup`, and `cross_host`. The validator's frontmatter
does not list `record_finding` or `update_finding` — finding
mutation is architecturally unreachable.

A Python orchestrator (not an LLM) drives a 5-step self-correction
loop: ANALYZE → CORRELATE → PROMOTE → PLAN → WRITE. PROMOTE
applies six rules R1–R6 as a pure function over correlations and
current state. The loop stops when the disputed-finding set
stabilizes (`R_b`), when zero followups are pending (`R_a`), when
the token budget is exceeded (`R_c`), or at `max_iterations` —
there is no fixed iteration count. Every tool call, finding
write, correlation, and promotion lands in one of four
hash-chained JSONL logs. Evidence files are SHA-256-stamped,
set to `chmod 444`, and mounted read-only with `/proc/mounts`
validation. The agent cannot construct a path — only an
`evidence_id` registered in `CASE.yaml`.

We've demonstrated SIFT-Guard end-to-end on three independent
corpora: **Rocba** (the SANS hackathon's 19 GB Windows 10 memory
image, single host), **synthetic-injected** (a 200 MiB image
carrying directive-content prompt injection in
`untrusted_fields`-flagged columns, used for adversarial
robustness), and **SRL-2015** (the SANS FOR508 four-host APT
teaching case — Windows 7, Windows XP, and a Server 2008 R2
domain controller, captured 2012-04-06 within a three-hour
window during active incident response).

The headline result is from the SRL run. The validator emitted
ten `cross_host` correlations autonomously, three of which are
conclusions a single-host workflow could not reach at the same
confidence: (1) `spinlock.exe` as a shared APT toolkit across
`nromanoff` and `xp-tdungan` — delivered via PsExec on one host,
actively rootkit-hidden via DKOM on the other; (2) a TCP session
`10.3.58.5:49805 ↔ 10.3.58.9:445` visible from both endpoints
simultaneously, with source-port match across independent memory
captures, confirming SMB lateral movement in flight; (3)
`svchost.exe` masquerading from an identical non-standard path
(`C:\Windows\System32\dllhost\svchost.exe`) on two separate hosts.
Each is invisible to single-host analysis.

---

## How we built it

The stack is deliberately small. Python 3.11+, the official
Anthropic `mcp` SDK with `FastMCP`, pydantic v2 for every payload
schema, pytest + ruff. Volatility 3 (verified, not Volatility 2 —
Protocol SIFT is known to confuse the two) running inside a SIFT
Workstation 2026.1 VM, accessed by the MCP server over SSH.
Claude Code as the runtime; analyst and validator subagents are
`claude -p --agent <name>` invocations parsed via `stream-json`,
with a plain-Python orchestrator harness as the dispatch
fallback.

The architecture-over-prompt thesis runs through every design
decision: the agent cannot violate what its tool surface does
not expose. The validator has no `record_finding` in its
frontmatter — even an injected directive cannot make it write a
finding because Claude Code never offers the tool.
`record_finding`'s `category` and `severity` are closed `Literal`
types — pydantic rejects an attempt to invent a category.
`DISPUTED` is reserved to the orchestrator's `update_finding`;
analyst self-marking is rejected as
`record_finding:rejected_disputed_self_marked`. Five defense
layers, three architectural and two prompt-level, in descending
strength order (`docs/adversarial-robustness.md`).

The "V-C hybrid" pattern is the architectural split between
**V** (validator subagent — natural-language reasoning about
whether independent observations agree, autonomous RAG queries)
and **C** (the orchestrator's promotion engine — six pure
deterministic rules, evaluated in fixed order, first match wins).
The validator decides what corroborates what; the orchestrator
decides what to do about it. Neither can do the other's job.

The team is five early-career engineers plus one unofficial
collaborator, on a self-imposed 8-week / ~400 person-hour budget
tracked in `docs/decisions-log.md`. The schedule was incremental:
Week 1 verification, Week 2 MCP scaffolding + thin RAG, Weeks 3–4
tier-1 wrappers, Week 5 subagent wiring, Week 6 validator + loop,
Week 7 accuracy benchmark + RAG expansion, Week 8 cross-host
extension + deliverables. Every milestone had written success
criteria and failure paths *before* the work started, so weeks
that produced negative results (the first analyst run produced
zero findings — see Challenges) still produced rubric points.

The RAG corpus merges 697 MITRE ATT&CK Enterprise techniques
(`ATT&CK-v19.0`) with 2147 SigmaHQ Windows detection rules
(`r2026-04-01`) into a single FAISS index using
`all-MiniLM-L6-v2` embeddings. The validator queries it
autonomously; on the post-RAG runs, ~62% of new correlations
cite at least one `rag_query` audit line as an `evidence_ref`.

---

## Challenges we ran into

**Tier-1/tier-2 split.** The first end-to-end Rocba dispatch
went poorly. The analyst received the full Volatility output —
459 KB of pslist, 800 KB of pstree — discovered that Claude
Code substitutes a stub message for tool results above its
token threshold, and exited cleanly with zero findings. Failing
loud beat failing silent. We resolved it by splitting every
memory tool into tier-1 (persists the full extraction with a
SHA-256 sidecar, returns a ≤10 KB summary) and tier-2 (reads
cached extractions, projects narrowed answers under a 10 KB
budget). The next run produced five substantive findings on the
first try.

**Validator prompt sensitivity.** The validator's first dispatch
emitted 11 malformed correlation calls — its prompt enumerated
the five correlation types but not the per-type field
requirements. Pydantic rejected every one; zero spurious
correlations on disk. The architecture compensated for the
prompt failure with no chain damage. We tightened `validator.md`
with explicit per-type call shapes; the next run produced 11
valid correlations on first attempt.

**R5 promotion rule persistence.** R5 ("quiet stabilization")
fires when a finding has been silent for two iterations. By
design it has no driving correlation — but
`FindingUpdate.driving_correlation_ids` required `min_length=1`,
so R5 outcomes silently failed to persist. Nine Rocba findings
stuck DRAFT. Resolved with a model-level validator gating empty
lists to `promotion_rule == "R5"` plus a tool-layer pre-check.
The related cumulative-vs-per-run semantics gap is documented
and deferred (failure mode #5).

**XP `vol_netscan` unsupported.** Volatility 3's
`windows.netscan.NetScan` plugin lacks Windows XP symbol-table
support. The `xp-tdungan` host succeeds on five of six tier-1
plugins; netscan rejects cleanly as
`vol_netscan:rejected_runner_failure`. No fix within scope — it
requires upstream Vol3 contribution. Documented as failure
mode #9, scope-bounded.

**Multi-host VM path translation.** The bind-mount that worked
for single-evidence Rocba didn't cover SRL's four-host directory
layout. Zero-code fix — a `/mnt/rocba/srl-2015/ →
/mnt/evidences/` bind mount in the SIFT VM. Worth mentioning
because it took an hour to find and zero to write;
"infrastructure problem looks like code problem" is a common
DFIR shape.

**Validator wallclock anomaly.** The SRL run's iter 2 dispatched
two analysts (~30 min each) followed by a validator session that
ran ~9.5 hours despite a 30-minute subprocess timeout default.
No timeout warning fired. Most likely cause: classic
`subprocess.run` deadlock where the parent blocks on a full
stdout pipe buffer (the default `capture_output=True` uses an
in-memory bytes buffer with OS-pipe-sized backpressure; `timeout=`
only fires on child wait, not on a stuck pipe-read). Work
product intact — 20 correlations including the 10 `cross_host` —
but the timeout guarantee was violated. Documented as failure
mode #11, deferred (transport rewrite to `Popen` with
non-blocking pipe drain).

---

## Accomplishments that we're proud of

**Cross-host detection on real APT evidence.** The three SRL
smoking guns — shared `spinlock.exe` toolkit, bidirectional SMB
session caught mid-flight, identical non-standard `svchost.exe`
path — are conclusions single-host analysis cannot reach at the
same confidence. The validator produced them autonomously,
grounding the underlying findings in MITRE T1014, T1021.001,
T1036.005, T1071.001, T1219, and T1569.002.

**Eleven documented failure modes.** Every one carries root
cause, impact, architectural response, resolution status, and
rubric criterion. Failure modes #1–#7 closed during development;
#8 scope-bounded (disk-side cross-source on real evidence
pending); #9 upstream-bounded (XP netscan); #10 resolved at v0.9
(malfind schema); #11 deferred (validator wallclock).

**Zero evidence mutations across six orchestrator runs.** SHA-256
re-verified at the end of every run; the audit log has never
produced a verification failure. Evidence files are `chmod 444`,
parent directories `chmod 555`, mounts validated read-only
against `/proc/mounts` before every read. `register_evidence` is
the single on-ramp for arbitrary paths; every other tool takes
only an `evidence_id`.

**491 tests, zero lint violations, architectural enforcement at
every safety-critical boundary.** A surface-lock test asserts
the exact 19-tool MCP surface — adding a tool without extending
the test fails CI by design.

---

## What we learned

**Architecture beats prompting, every time.** Every problem we
tried to solve with "we'll tell the LLM not to..." failed under
stress. The validator malformed-correlation incident, the R5
silent-skip, the analyst-too-much-data deadlock — all resolved
by redesigning so the failure mode was unreachable, not by
adding prompt language. The adversarial-robustness demo is the
strongest version of this: prompt-injection in evidence-derived
strings is neutralized because the tool surface and schema
expose no way to act on it.

**Document failure modes from week 1.** The accuracy report had
a named owner from the first sprint. Every bug became a
documented failure mode with root cause, impact, and resolution.
By the time we shipped, the section was eleven entries long and
read as engineering discipline rather than embarrassment. The
rubric explicitly rewards this; the framing converts private
engineering notes into a graded deliverable.

**Cross-source validation is the real differentiator.**
Single-source forensic findings are inherently ambiguous: an
unusual binary could be sysadmin tooling; an unusual TCP session
could be a misconfigured service. The moment you have two
independent sources agreeing on a shared indicator — same
binary, same source-port match, same non-standard path —
confidence jumps categorically. The `cross_host` correlation
type is the architectural surface for this; the SRL run is the
empirical validation. Memory↔disk cross-source remains the
next frontier.

---

## What's next

Disk-side tools are built and tested but have not been
exercised on real disk evidence yet — registering an `.E01` or
a triage zip into a multi-host run will exercise the
`disk_analyst` agent and add memory↔disk to the cross-source
substrate. R5's cumulative-vs-per-run semantics need a
chain-history-aware fix so findings silent across many short
runs accumulate credit correctly. The validator subprocess
transport needs the `Popen` rewrite to enforce timeouts on
large stdout. The hash-chained-writer logic is implemented
three times across `audit`, `findings`, `correlations`, and
`extractions` — that's beyond rule-of-three and a base class
extraction is overdue. And `R_b` should grow a subset-stability
variant (`R_b'`) that terminates when the disputed set is a
subset of the prior iteration's, not just exactly equal — the
synthetic run surfaced a "stable core, growth on top" pattern
that the strict equality rule never trips.

---

## Built for

**SANS "Find Evil!" 2026 hackathon** (deadline 15 June 2026).
Repository: [`github.com/chang6chang/SIFT-Guard`](https://github.com/chang6chang/SIFT-Guard).
MIT licensed. Eight required deliverables — code, screencast,
architecture diagram, this description, dataset docs, accuracy
report, try-it-out, redacted execution logs — each with a
named owner in `docs/decisions-log.md`.
