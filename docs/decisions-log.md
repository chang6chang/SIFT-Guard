# Decisions log

Chronological record of design and process decisions. Each entry:
date, what changed, why, where it's encoded.

## 2026-05-03

**Day 2: ground truth isolation rules added to CLAUDE.md** after
observing that real-world IR cases never come with a curated
briefing. Agent must operate from evidence alone.

Encoded as a new section "Ground truth isolation" in `CLAUDE.md`,
placed between "Hard rules" and "Architectural enforcement of
evidence integrity". Three rules:

1. `docs/dataset-inventory.md` is a human-only artifact, used post-run
   to score findings. The agent must never read it.
2. The agent reads nothing under `docs/` at runtime. Only
   `case-data/evidence/` (read-only) and `case-data/extractions/`
   (its own parsed outputs) are in scope.
3. MCP functions never accept arbitrary file paths. They take an
   `evidence_id` registered in `CASE.yaml` and resolve to the path
   internally — the agent cannot route itself into `docs/`, `.git/`,
   or the source tree.

Why this matters: the autonomy criterion (rubric tiebreaker) measures
the agent's ability to reason from raw evidence. A leaked briefing
turns "detection" into "memorization" and inflates the accuracy
report. These rules are architectural, not prompt-level — enforced
by which MCP tools exist and what they accept.

**Day 2: Week 3 task — schema-introspection test that fails the build
if any MCP tool exposes a free-form path field.** Owner:
lead/architect.

Why this matters: rule 3 above (MCP functions take only `evidence_id`,
never raw paths) is the structural lock on the case sandbox. If even
one tool accidentally exposes a `path: str` parameter, the guardrail
leaks silently. A schema-introspection test that walks every tool's
pydantic model and rejects free-form path fields turns the rule from
a convention into a build-time check. To be implemented during Week 3
when tool schemas are scaffolded.

**Day 2: Week 5 task — analyst subagent definitions must restrict
tool list to MCP calls only, no bare Read/Bash/filesystem access.**
Owner: AI/agent engineer.

Why this matters: CLAUDE.md rule 2 (the agent reads nothing under
`docs/` at runtime) is enforced on the MCP server side, but if an
analyst subagent inherits the parent's bare `Read` / `Bash` / generic
filesystem tools, it can bypass the MCP boundary and read `docs/`,
`.git/`, or the source tree directly. That makes rule 2 a prompt
guardrail for the subagents instead of an architectural one. When
subagent definitions are wired up in Week 5, each analyst's allowed
tool list must be explicitly restricted to the SIFT-Guard MCP tools —
no `Read`, no `Bash`, no `Grep` against the repo. To be encoded in
`agent/.claude/agents/*.md` (or the Python orchestrator's analyst
config if the fallback path is taken).

**Day 2: Week 8 pre-submission task — replace dev-convenience SSH +
sudo access to the SIFT VM with a documented MCP server transport.**
Owner: lead/architect.

Current development setup: Claude Code reaches the SIFT VM via
`ssh -p 2222 sansforensics@<wsl-default-gw>` with passwordless sudo on
the guest, used during Day-1 verification (e.g. running
`vol windows.info.Info` and `sha256sum` on the memory image).

Why this matters: this is fine for the team's dev loop but
unacceptable for a submission. The hackathon judges should not be
asked to grant the agent passwordless sudo over SSH to a VM in order
to reproduce results — it inflates the trust surface, makes the
"architectural guardrails > prompt guardrails" claim look hollow, and
turns the try-it-out instructions into a security incident waiting to
happen. Before submission, this access path must be replaced with a
documented MCP server transport: either (a) the MCP server runs
inside the SIFT VM and Claude Code talks to it over stdio piped
through SSH (no shell, no sudo, only the typed MCP protocol on the
wire), or (b) the MCP server binds a TCP port on the VM that the host
connects to, with an explicit allow-list and no shell access. The
README's try-it-out section must reflect whichever option is chosen
and must NOT require the operator to grant the agent passwordless
sudo on the SIFT VM.

## 2026-05-05

**Day 4: subagent harness verified — forced-by-name dispatch and
parallel fan-out both work in this Claude Code version. Subagent path
is the primary architecture. Python-orchestrator fallback parked.**
Owner: AI/agent engineer.

Three-part hello-world experiment under `.claude/agents/`
(`hello_alpha.md`, `hello_beta.md`, `hello_restricted.md`). Findings:

1. `Agent(subagent_type="hello_alpha", ...)` is accepted by the
   harness and dispatches the named subagent. The harness rejects
   unknown names — agent-name-as-string is schema-validated, not a
   description-matching heuristic. Note: `.claude/agents/*.md` files
   are loaded at session start. New files added mid-session are
   ignored until Claude Code is restarted.
2. Two `Agent` calls in a single assistant turn run **concurrently**,
   not serially. Two subagents each performing `sleep 5 && date +%s.%N`
   completed 0.684 s apart (1777963569.670 vs 1777963570.354). Serial
   execution would have produced ~5 s delta. The published Claude Code
   docs claim "subagents are not for parallel execution, use agent
   teams instead" — that is incorrect for the `Agent` tool path in
   the version we are targeting.
3. The parent receives only the subagent's final assistant message.
   No tool-call transcript, no intermediate text. Analysts must
   structure their return as a strict, parseable contract (e.g. a
   fenced JSON block on the last line of the response) because the
   validator only sees what the analyst chose to put in its final
   message.

Why this matters: the 5-step loop's Triage step assumes the
orchestrator can fan out to all active analysts in one turn. The
`asyncio.gather` over Anthropic Messages API fallback documented in
CLAUDE.md is no longer required to unblock that fan-out, and is
demoted from "primary contingency" to "break-glass." Week 5 wiring
proceeds against `.claude/agents/*.md` directly.

The three test subagents are disposable. They will be removed before
the Week-5 analyst roster lands; they served only to settle the
forced-dispatch and parallelism questions architecturally.

**Day 4: CLAUDE.md auto-injection leak — the harness drops CLAUDE.md
verbatim into every subagent's system context, bypassing the
ground-truth-isolation rules at the prompt layer.** Owner:
lead/architect (banner header), AI/agent engineer (Week 5
systemPrompt investigation).

Observed during Test 3 of the hello-world experiment. The
`hello_restricted` subagent — defined with empty `tools: []` and no
file-reading capability — reported in its response that
"the contents of CLAUDE.md were nevertheless injected into my context
via the system-reminder mechanism (project instructions)." This is
the harness's standard project-context behavior. It applies to every
subagent dispatched from this directory, regardless of the
subagent's `tools:` allowlist.

Why this matters: the ground-truth isolation rules added 2026-05-03
prevent the agent from reading `docs/` at runtime. They do **not**
prevent CLAUDE.md from being read, because CLAUDE.md is loaded by
the harness, not by an agent tool call. Today CLAUDE.md is mostly
architectural rules and dispatch logic — workable. But the moment a
case-scenario fact, a ground-truth artifact, or a finding leaks into
CLAUDE.md, every analyst sees it and the autonomy claim collapses
silently. This is the kind of guardrail that fails by drift, not by
a single bad commit.

Defense in two layers:

1. **Banner header on CLAUDE.md** declaring it architecture-only.
   Added immediately. Stating the rule visibly at the top of the
   file forces the reviewer to confront it before adding new
   content.
2. **Week 5 task — investigate per-subagent `systemPrompt` override
   to suppress CLAUDE.md auto-injection entirely.** Owner: AI/agent
   engineer. The subagent frontmatter spec includes fields the
   published docs treat as advanced (`initialPrompt`, possibly
   harness-private fields for system-prompt scope). Verify whether
   any of them prevent CLAUDE.md auto-load for that subagent. If
   yes, adopt for every analyst — the architectural guarantee should
   not depend on CLAUDE.md hygiene. If no, escalate to a runtime
   check: the orchestrator hashes CLAUDE.md at run start and refuses
   to dispatch if the file contains banned tokens (case host names,
   the strings "ground truth" or "expected findings", etc.).

**Day 4: audit logging principle — subagents narrate plausible-sounding
lies about harness behavior. The audit log records parent-observable
facts only, never the subagent's prose self-report.** Owner:
lead/architect (encode in `server/audit.py` design during Week 2).

Observed during Test 3 of the hello-world experiment. The
`hello_restricted` subagent claimed verbatim:

> ERROR: Read operation blocked by hook:
> - [PreToolUse:Read] Hook blocked: hello_restricted is not permitted
>   to read CLAUDE.md

We have no `PreToolUse:Read` hook configured. The harness usage line
on the same response showed `tool_uses: 0` — the subagent never
actually invoked Read. The block was real (Read was not in its tool
palette because of `tools: []`), but the subagent's narrative of
*how* it was blocked is fabricated. It produced a confident,
structured, plausible error message describing a mechanism that does
not exist in this configuration.

Why this matters: the Audit Trail rubric requires every finding to
be traceable to a tool execution. If the audit log records the
subagent's prose ("I was blocked by hook X", "I successfully ran
plugin Y") as authoritative, the trail is poisoned by hallucination
the moment a subagent confabulates a response. The architectural
guardrail (the Read tool was genuinely unavailable) held; the prose
explanation of that guardrail did not.

Encoded in `server/audit.py` design (Week 2):

- Every JSONL audit record is built from **parent-observable facts**:
  the dispatched `subagent_type`, the resolved `tools:` allowlist as
  applied by the harness, the `tool_uses` count from the harness
  usage block, the `duration_ms` from the harness usage block, and
  the SHA-256 of the subagent's final message text.
- The subagent's final message is stored verbatim as a payload but
  is **not** parsed for harness-state claims. Statements like "I was
  blocked", "the tool returned an error", "the file did not exist"
  are treated as model output, not as facts about the harness.
- Findings derived from a subagent message must cite a tool call
  recorded by the parent — not a sentence in the subagent's
  response.

This rule is the audit-side complement to Hard Rule #2
("architectural guardrails beat prompt guardrails"): the audit log
trusts what the system did, not what the model said about what the
system did.

### New tasks created today

- **Week 3 (lead/architect): extend the schema-introspection test**
  to also walk every `.claude/agents/*.md` file and assert each
  analyst has an explicit `tools:` allowlist containing only
  `mcp__sift_guard__*` entries — no `Read`, `Bash`, `Grep`, `Edit`,
  `Write`, `Glob`, `WebFetch`, or implicit defaults. Same build-time
  enforcement model as the path-field check from 2026-05-03.
- **Week 5 (AI/agent engineer): investigate per-subagent
  `systemPrompt` override** to suppress CLAUDE.md auto-injection. If
  unavailable in the subagent frontmatter spec, fall back to a
  runtime banned-token check on CLAUDE.md before any analyst
  dispatch. See Day-4 CLAUDE.md auto-injection leak entry above.
- **Week 2 (lead/architect): encode the audit-log principle in
  `server/audit.py` design** — JSONL records carry only
  parent-observable harness facts; subagent prose is stored as
  opaque payload, never parsed for harness-state claims. See Day-4
  audit logging principle entry above.

**Week 2 Day 1: `register_evidence` ships with `case_id` derived from
`case_dir.name`. This is a placeholder; an explicit `case_id`
parameter will be added in Week 7 when multi-case workflows are
needed.** Owner: lead/architect.

Why this matters: today the prototype operates on a single case
(Rocba), and every audit-log line, every CASE.yaml, every set of
findings is implicitly scoped to that one case directory. Hardcoding
`case_id` to the directory name keeps the on-disk shape stable for
the Week 2–6 build without prematurely committing to a case-id
naming scheme. Week 7 introduces the accuracy-benchmark workflow
(per CLAUDE.md's build order: "5 runs each, median + range" on
Rocba, plus a second config if a public disk+memory pair is found),
which is the first time multiple cases coexist in the same audit
trail. At that point `register_evidence` grows an optional `case_id`
keyword that overrides the directory-derived default; the migration
is mechanical because the on-disk `case_id` field already exists
and is read by every consumer.

**Week 2 Day 1: `server/integrity.py` exists as a stub.
`verify_mount_readonly` raises `NotImplementedError` until the first
disk-image MCP tool is implemented (Week 3-4).** Owner:
lead/architect.

Why this matters: CLAUDE.md "Architectural enforcement of evidence
integrity" requires a `/proc/mounts` read-only check before every
read of evidence. The check is moot for the Rocba memory-only
prototype because `register_evidence` is the only on-ramp and it
streams the file once at registration time — but the moment a
disk-image tool wants to mount via `ewfmount` or `affuse` and read
repeatedly, the check becomes load-bearing. Creating the stub now
fixes the import boundary (`from server.integrity import
verify_mount_readonly`) so callers can be written against the final
shape, and the `NotImplementedError` ensures no Week 2-3 caller
silently believes it has the protection. The function lands in full
form when the first disk-image tool requests it, not before.

**Week 2 Day 1: MCP error-message sanitization rule. Every MCP tool
function must catch known exceptions and return sanitized error
messages that do NOT echo agent-supplied input back.** Owner:
lead/architect.

Rationale: FastMCP returns tool exceptions as
`CallToolResult(isError=True)` with the Python exception's `str()` as
the content the LLM sees. Echoing the agent's input back inside that
error string creates a filesystem-mapping oracle: the agent crafts
calls with probe paths and reads back which ones exist, are
permission-denied, or fail validation, learning the layout of the
host filesystem one error at a time. The same mechanism leaks
internal state for any string-shaped input — registry key names,
process names, IPs, hostnames — once tools that accept those land in
Weeks 3-4.

Today this is largely moot. `register_evidence` is the only tool, and
the agent can only pass paths it already knows about (the operator
hands them over out of band before the run starts). The error message
discovered during the Phase 4a protocol round-trip
(`tests/test_mcp_protocol.py`) reads
`Evidence path does not exist: /tmp/.../does-not-exist.dat`, which
echoes the input verbatim. Acceptable for the prototype, not
acceptable once the agent is calling tools whose parameters it
synthesizes from evidence.

Pattern to follow when implementing Week 3-4 tool wrappers:

- Catch `FileNotFoundError`, `PermissionError`, `ValueError`, and any
  domain-specific exceptions the wrapper raises.
- Re-raise as a sanitized message that names the failure mode and
  the `evidence_id` (a server-minted UUID) but never the underlying
  path, key name, or other agent-supplied string. Example:
  `"invalid evidence reference: <evidence_id>"`,
  `"plugin failed for evidence_id=<evidence_id>"`,
  `"argument validation failed for evidence_id=<evidence_id>"`.
- Log the original exception (with the input that triggered it) into
  the hash-chained audit log via `append_audit_entry`. The audit log
  is the operator-visible diagnostic surface; the LLM-visible error
  string is not.
- The single allowed input echo is the `evidence_id` itself, because
  the agent named it in the call and the server resolved it through
  the `CASE.yaml` registry — there is no information leak in echoing
  what the agent already knows.

This rule is recorded in CLAUDE.md "Hard rules" as a one-line entry
pointing back here. The Week-3 schema-introspection test should be
extended again to scan tool implementations for the pattern (e.g.
flag any `raise FileNotFoundError(f"... {filepath}")` inside
`server/tools/`), but the immediate enforcement is reviewer
discipline.

**Week 2 Day 1: Hash transcription correction.** The earlier
conversational reference to `Rocba-Memory.raw`'s SHA-256 starting with
`be33...` was a transcription error. Authoritative pre-registration
hash:

```
eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563
```

(full 64 chars), captured to `docs/rocba-pre-registration-hash.txt`
by `sha256sum` on 2026-05-05.

Process rule going forward: hashes are never retyped from chat or
memory; they are sourced from on-disk files or the audit log. This
will become important in the accuracy report when we discuss
chain-of-custody discipline.

**Week 2 Day 2: `ProcessRecord` and `PslistResult` schemas use
`Literal[...]` for `plugin_name` to architecturally prevent
cross-plugin result confusion.** Pattern continues for every
Volatility wrapper in Weeks 3-4.

**Week 2 Day 2: Audit log `tool_name` namespacing convention.**
Format: ``<tool_name>[:<sub_event>]``. Examples:

- ``register_evidence`` (no sub-event)
- ``vol_pslist`` (the main result line)
- ``vol_pslist:record_validation_warning`` (per-record validation
  failure during pslist)
- ``vol_pslist:rejected_evidence_not_found`` (rejection-path line)

Rationale: greppable, sortable, self-documenting, and per-call
sequencing within the JSONL is preserved by `line_number`. Pattern
continues for every Volatility wrapper in Weeks 3-4.

**Week 2 close: first live `vol_pslist` invocation against Rocba
returned 2186 processes — anomalously high (normal Win10 baseline:
80-250).** This is precisely the kind of cross-plugin discrepancy the
validator subagent (Week 6) will resolve via psscan vs pslist
comparison. Hypotheses to test: terminated process artifacts in
ActiveProcessLinks, real high-process workload, parser duplication.
NOT treated as a defect — system surfaced an analytical question,
which is the intended behavior.

**Week 2 close: process name field `_EPROCESS.ImageFileName` is
hard-truncated to 15 bytes by the Windows kernel.** The `vol_pslist`
tool returns this value verbatim; downstream correlation in Week 6
must use prefix matching, not equality, when comparing against full
process names from cmdline or the PEB. Logged as a known kernel
artifact, not a bug. Reference in `adversarial-robustness.md` when
written: an attacker can engineer collisions in this field via 15+
char executable names.

## 2026-05-05 — Protocol SIFT: do not compare against

**Decision:** SIFT-Guard does not benchmark against Protocol SIFT.
Accuracy report compares SIFT-Guard findings against ground-truth
labels only.

**Rationale:** Protocol SIFT is a Claude Code skills package, not an
MCP framework (verified: zero MCP code in upstream HEAD 40bed7a, no
LICENSE file). Adoption (Option A) and fork (Option C) blocked by
license. Black-box benchmark (Option B) was viable but the team is
budget-constrained on hours; comparison work deferred indefinitely.

**Consequence for rubric:** weaker IR Accuracy (#2) and Constraint
Implementation (#4) narrative — no head-to-head numbers, no
prompt-vs-architectural-guardrail contrast pulled from a real run.
Mitigation: lean harder on the iterative self-correction demo (#1
tiebreaker) and the hash-chained audit (#5).

**Artifacts retained:** docs/protocol-sift/ (assessment + raw inputs)
kept for reference. Protocol SIFT install on SIFT VM left in place,
unused.

## 2026-05-06 — Set vs record semantics in `set_difference`

**Decision:** `set_difference` returns BOTH unique-key counts and
record counts. The week-4 baseline note "psscan +26 unlinked" was a
count-vs-set conflation; the forensically meaningful set-diff is 11
unique PIDs.

The `SetDifferenceResult` schema carries:

- `a_only_count`, `b_only_count`, `intersection_count` —
  SET-semantic on the join key (unique-PID counts on Rocba:
  11, 1, 2185).
- `a_record_count`, `b_record_count` — total record counts in each
  extraction (2212, 2186 on Rocba). Surfaces the simple
  length-delta the week-4 note referred to.
- `a_duplicate_key_count`, `b_duplicate_key_count` — records in each
  extraction whose key value has been seen earlier in the same
  extraction ("extras beyond first occurrence"). On Rocba:
  16 in psscan, 0 in pslist. The 16 captures pool-tag aliasing
  across the whole psscan extraction; 15 of those are intersection
  PIDs (same EPROCESS rediscovered across pool boundaries — benign
  pool-scan noise), 1 is in the a_only set (PID 7900 svchost.exe,
  the DKOM candidate).
- `returned_records` is per-record (not deduped by key). PID 7900's
  two pool-aliased EPROCESS records both return when querying
  a_only — the agent typically wants every alias for forensic
  evidence.

**Rationale:** Both metrics answer different questions and the
validator needs both. The set count answers "how many distinct
entities are missing from plugin_b" (the DKOM-candidate count). The
record count answers "is the record-count delta we see in the
extraction sizes a real anomaly or pool-tag noise?" The
duplicate-key counts let the agent reconcile the two without
re-loading the extractions.

**Live verification on Rocba reconciliation:**

    record-count delta:     |psscan| - |pslist| = 2212 - 2186 = 26
    set diff a_only:        11  (unique PIDs in psscan, not pslist)
    set diff b_only:        1   (unique PIDs in pslist, not psscan)
    psscan duplicate keys:  16  (pool-tag aliases across whole extraction)
    psscan total records:   2212
    pslist total records:   2186

    reconciliation:
        records in psscan with PID not in pslist key set
            = 12 (11 unique PIDs + PID 7900 alias)
        psscan extra-records due to pool-tag aliasing
            = 16
        records in pslist with PID not in psscan key set
            = 1
        |psscan| - |pslist| = 12 + 16 - 1 - 1
                            = 26 ✓
            (the trailing -1 accounts for PID 7900 being one of the
            duplicate keys but ALSO one of the a_only PIDs — its
            second alias is counted by both `a_duplicate_key_count`
            and "records with PID not in pslist", so we subtract
            once to avoid double-counting in the reconciliation.)

**Validator usage rule:** hypotheses are formed against
`a_only_count` (entity-set semantics). Audit-style sanity checks
("did the cross-plugin counts move between iterations?") use the
record counts. Pool-tag-aliasing context comes from the duplicate-key
counts.

## 2026-05-06 — Verdict A on subagent architecture

process_analyst v2 produced 5 substantive findings on Rocba including
PID 7900 caught with correct category (`process_hidden`).
Tier-1→tier-2 workflow was discovered organically by the analyst from
tool descriptions alone, not prompted. This validates:

- Restricted MCP-only tool surface elicits useful analysis.
- Literal-typed categories enforce classification architecturally.
- Tier-1/tier-2 split is discoverable from schema alone.
- `record_finding` contract holds; analyst does not drift to prose.

The architecture-over-prompt rule is now empirically supported, not
just claimed. See `docs/process-analyst-v2-results.md` for the full
run analysis and Verdict A justification.

## 2026-05-06 — Probe-finding pattern: `audit_line` not surfaced

7 of 12 findings from process_analyst v2 were probe placeholders
where the analyst was searching for valid `(audit_line, source_tool)`
pairs because tool returns don't surface their own audit-chain line
number. This is structurally the same class of problem as v1's
oversized-return deadlock: the analyst needs metadata that the
architecture withholds.

**Fix:** add `audit_line: int` to `ExtractionRef` and the tier-2
result models (`QueryRecordsResult`, `GroupByResult`,
`SetDifferenceResult`, `SubtreeResult`). Migrate before
`network_analyst` lands so the same probe pattern does not propagate
into a second analyst.

Documented as a failure mode in
`docs/process-analyst-v2-results.md` and propagated to
`docs/accuracy-report.md` as documented-failure-mode #1.

## 2026-05-06 — Findings corpus state, end of week 5

`case-data/findings.jsonl` now contains:

- **line 1**: synthetic genesis from week-5 `record_finding`
  live-verification (`analyst=process_analyst`, but pre-experiment
  placeholder).
- **lines 2-13**: process_analyst v2 actual output — 5 substantive
  findings + 7 probe placeholders.

The week-6 validator operates on substantive entries (filter:
`finding.title` does not start with `"probe"`). The 7 probe lines are
retained on disk per the experiment's "do NOT manually clean up
findings.jsonl" rule and because the architecture has no revocation
primitive — once a finding lands in the chain, the chain extends
forward only.

## 2026-05-06 — `audit_line` plumbing into ExtractionRef + tier-2 results

**Decision:** Surface the audit-chain line of the originating tier-1
invocation in `ExtractionRef.audit_line`, and the calling tool's own
audit line in tier-2 result models (`QueryRecordsResult.audit_line`,
`GroupByResult.audit_line`, `SetDifferenceResult.audit_line`,
`SubtreeResult.audit_line`). Eliminates the probe-finding pattern
documented in `docs/process-analyst-v2-results.md` (failure mode #1
in `docs/accuracy-report.md`).

**Migration approach: nullable, no retroactive backfill.** The 3
existing `extractions.jsonl` lines (from the 2026-05-06 tier-1/tier-2
live verification) were written before this field existed; loading
them yields `audit_line=None` in the returned `ExtractionRef`. New
writes always populate it. The schema is asymmetric:
`ExtractionRef.audit_line` is `Optional[int]` (nullable for legacy);
the four tier-2 `*Result.audit_line` fields are required `int` (every
tier-2 call happens under the new schema). Append-only invariant
holds — neither `audit.jsonl`, `findings.jsonl`, nor
`extractions.jsonl` was modified retroactively. `EvidenceRefSourceTool`
expanded to include the four tier-2 names (`query_records`,
`group_by`, `set_difference`, `subtree`) so derived analyses can be
cited as evidence directly.

**Live verification on Rocba (cached state, 2026-05-06):**

    step 1: vol_pslist (cached) → ExtractionRef.audit_line = None
            (correct legacy migration semantic)
    step 2: set_difference(psscan, pslist, pid, a_minus_b)
            → Result.audit_line = 100 (populated, new)
              extraction_a/b.audit_line = None (legacy sources)
    step 3: record_finding(EvidenceRef.audit_line=100,
                           source_tool="set_difference")
            → accepted on first call; no probe pattern

The probe-finding workflow that contaminated `findings.jsonl` lines
2-8 in the v2 experiment is no longer reachable: every tool the
analyst can call surfaces the audit_line it just produced.

## 2026-05-06 — network_analyst v1: Verdict A reproduced; cross-source data is correlatable on `pid`

`network_analyst` v1 ran against Rocba immediately after
`process_analyst` v2 and produced 4 substantive findings, 0 probes,
0 server-side rejections of any class, in 13 tool calls / 14 turns /
$0.51 (vs v2's 79 tool calls / 80 turns / $2.61). Verdict A.
The d54636d audit_line plumbing was exercised end-to-end on a *fresh*
tier-1 path for the first time (`vol_netscan` was uncached); the fix
is empirically validated on the fresh-write path — see
`docs/network-analyst-v1-results.md` § Failure modes.

**Cross-source observation (data only; not implemented in this PR).**
`findings.jsonl` now carries 5 substantive process findings (lines
9-13) and 4 substantive network findings (lines 15-18) on the same
evidence. The two sets are correlatable on the `pid` join key, but
no PID appears as an anomaly in *both* sets: process_analyst flagged
`7900` (hidden svchost), `4420`/`16480` (SearchFilterHost /
SearchProtocolHost cohort), `29664` (b_only gap), `8908`/`11672`
(Teams.exe fan-out parent); network_analyst pivoted on `1248`
(TermService svchost) and `4` (System). The week-6 validator can
compute meaningful cross_plugin corroborations from this join key —
e.g. confirming that process_analyst's hidden PID 7900 owns *zero*
netscan records (a hidden process should not have active sockets) is
an automatic HIGH-confidence cross-validation, and confirming
network_analyst's PID 1248 has a canonical pslist record
(`PPID=828=services.exe`) reframes finding #1 from "host owns the
connection" toward "RDP service canonical, inbound IPs are the
anomaly". Neither correlation is computed in this PR — that is the
validator's job. The observation here is that the substrate (shared
findings.jsonl, shared evidence, schema-pinned join key on `pid`)
is correlatable.

## 2026-05-06 — Validator subagent + orchestrator loop, V-C hybrid

The validator subagent (`.claude/agents/validator.md`) and the
Python orchestrator (`orchestrator/`) ship together. This is the
project's flagship piece — autonomous self-correction across the
analyst output is what the rubric tiebreaker (criterion 1) rewards.

**V-C hybrid**: validator is an LLM subagent with restricted tool
surface; promotion logic is a pure Python R1-R6 rule engine. The
validator emits typed correlations (corroborates / contradicts /
strengthens / weakens / request_followup); the orchestrator's
`promote()` function applies the rules deterministically. Auditable
promotion + judgment-under-evidence both land in the same loop. See
`docs/validator-design.md` for V-A vs V-B vs V-C tradeoff.

**5-step loop**: ANALYZE → CORRELATE → PROMOTE → PLAN → WRITE.
Three termination flags (R_a zero unresolved, R_b disputed
unchanged, R_c token budget) plus a max_iterations safety net.
See `docs/loop-design.md`.

**Sequential dispatch (not parallel)**. The substrate's hash-chain
writers explicitly note "single-process; no file lock". Two
subagents in parallel would race the audit chain. Until per-process
locking lands, analyst dispatch is sequential. The wall-time cost
is real (each analyst ~16 min on Rocba), but the architectural
guarantee — every audit / findings / correlations / iterations line
hashes-into the previous one, byte-exactly — is load-bearing for
the demo.

**Re-dispatch on iteration 1**. The orchestrator always dispatches
all matching analysts on iter 1, even if findings already exist
from a prior run. Append-only chains tolerate it; cache-hit
behavior on tier-1 keeps the cost reasonable; detecting "this
analyst has already run" is brittle (different prompt versions,
different tool surfaces). The cost is `findings.jsonl` growth on
every run.

**Rule-of-four hash-chained writers**. With `iterations.jsonl`
landing this PR, the substrate has four append-only hash-chained
logs (audit, findings, correlations, iterations), each with its own
writer module and distinct hash field names. Per the standing
convention, the `HashChainedJsonl` base-class extraction is still
deferred — it lands as a separate post-week-6 commit so the
substrate ships clean. Tracked here so the debt is explicit. The
shared-core extraction is ~50 lines across the four; the cost of
extraction now (re-running the substrate's full test matrix to
prove no regression) outweighs the marginal duplication cost.

## 2026-05-?? — V-C hybrid validated under stress on Rocba

End-to-end loop run on Rocba. First iteration emitted 11 malformed
correlation calls due to incomplete validator prompt (per-type call
shapes not enumerated). All 11 caught by record_correlation
substrate (:rejected_invalid_payload). Zero spurious data on disk.
Loop terminated cleanly. Fix was a one-file validator.md edit — no
substrate change.

This empirically validates the architecture-over-prompt principle
under real failure conditions. The substrate enforced its contract;
the prompt was wrong; the system did not corrupt state. The fix
shipped without architectural debt.

Run 2 outcome: 27 R3 promotions from 11 correlations, 0 rejections,
~160K uncached tokens, 9m 40s, terminated on no_followup_pending
in iteration 2.

Open observation: R1, R2, R4, R5, R6 promotion rules are
unit-tested but not exercised by Rocba (clean dataset, no
contradictions, no benign-explanation findings, no late-iteration
quiescence cases). focus_context flow and request_followup
correlations also not exercised on real evidence. To be addressed
in the accuracy report by referencing unit-test transcripts that
exercise these paths.
