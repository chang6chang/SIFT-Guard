# network_analyst v1 — Rocba experiment results

The first dispatch of the `network_analyst` subagent against the
Rocba memory image. Same architectural hypothesis as the
process_analyst v2 experiment ([results
doc](process-analyst-v2-results.md)): does a minimal-methodology
system prompt + restricted `mcp__sift-guard__*` tool surface elicit
useful network analysis on Rocba, and does it do so without the
probe-finding contamination that v2 produced before the d54636d
audit_line plumbing fix?

This run is also the first end-to-end exercise of the
`audit_line`-on-`ExtractionRef` field on a *fresh* tier-1 path.
v2's tier-1 calls were all cache hits, so its `extraction.audit_line`
came back `None` (legacy semantic). `vol_netscan` was uncached on
Rocba, so this run produced a freshly-written extraction whose
`extraction.audit_line` was populated to the originating tool call's
audit line — which the analyst then cited directly in
`record_finding`.

## Setup

| | |
| --- | --- |
| Date | 2026-05-06 |
| Evidence | `Rocba-Memory.raw` (sha256 `eb33bd…0563`, 19 GB, registered as `6770da81-f562-4643-b1d2-69d78104fb70`) |
| Subagent file | `.claude/agents/network_analyst.md` (v1; tier-1 vol_netscan + tier-2 query_records / group_by) |
| Tool surface granted | `mcp__sift-guard__{register_evidence, vol_netscan, query_records, group_by, record_finding}` (5 tools) |
| Model | `claude-opus-4-7[1m]` |
| Dispatch | `claude -p --agent network_analyst --output-format stream-json --verbose --permission-mode bypassPermissions --max-budget-usd 10` |
| Session id | `f7f47ad2-0991-4c32-ad86-1625b8680963` |
| Transcript | [`network-analyst-v1-rocba.transcript.md`](network-analyst-v1-rocba.transcript.md) |
| Comparison | [process_analyst v2 results](process-analyst-v2-results.md) — same prompt principle, different domain, same architecture (tier-1 + tier-2 + record_finding) |

## Run summary

| | |
| --- | --- |
| Wall clock | 16m 13s (18:10:12Z → 18:26:25Z) |
| API duration | 110.1 s (the remaining 14m 21s is MCP/Volatility wall — `vol_netscan` fresh-run on a 19 GB image) |
| Turns | 14 |
| Cost | $0.51307 |
| Output tokens | 8,382 |
| Cache-creation input tokens | 41,753 |
| Cache-read input tokens | 85,027 |
| Tool calls (total) | 13 |
| Tool-call distribution | 1 `vol_netscan` (fresh) / 6 `query_records` / 2 `group_by` / 4 `record_finding` (all 4 succeeded on first attempt) |
| Audit-chain growth | lines 102-114 (13 new) |
| `findings.jsonl` growth | lines 15-18 (4 new findings; **4 substantive, 0 probe**) |
| `extractions.jsonl` growth | line 4 (1 new — `windows.netscan.NetScan` extraction; `vol_netscan` was uncached) |
| Server-side rejections | **0** of any kind |
| Stop reason | `end_turn` (analyst voluntarily terminated) |
| `permission_denials` | 0 |

## What the analyst caught

For each finding: title, category, severity, confidence,
audit-line back-pointers, and a brief reviewer assessment.

| # | Findings line | Title | Category | Severity / Conf | Refs | Reviewer assessment |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 15 | Inbound RDP (TCP/3389) ESTABLISHED from external public IPs (213.202.233.104, 81.30.144.115) | `network_lateral_movement` | high / HIGH | `vol_netscan:102`, `query_records:105`, `query_records:104` | **Strong call.** ESTABLISHED state to non-RFC1918 foreign_addr on a workstation is the textbook unauthorized-foothold signal. Category and HIGH confidence are defensible from netscan alone; the validator can promote / dispute. |
| 2 | 16 | High-volume RDP connection churn from a narrow set of external IPs (suspected brute-force / repeated logon attempts) | `network_anomaly` | high / HIGH | `query_records:108`, `query_records:107` | **Strong inference.** 124 records on `local_port=3389` (most CLOSED) plus a single SYN_RCVD from a third external IP is consistent with ongoing brute-force activity; HIGH at netscan resolution captures the count anomaly without claiming the higher-fidelity attribution that EVTX would carry. |
| 3 | 17 | Seven UDP endpoints with null owner / null PID | `network_anomaly` | low / LOW | `query_records:106`, `vol_netscan:102` | **Conservative-and-correct.** The analyst noted explicitly that all 7 null-owner records are UDP (orphaned-endpoint shape, not the malicious null-owner-TCP-LISTEN shape). LOW confidence is the right read; bundling rather than enumerating each ephemeral port is appropriate signal/noise. |
| 4 | 18 | SMB (TCP/445) and NetBIOS (TCP/139) exposed; 3389/445/139 listeners co-located on a workstation receiving external RDP | `network_anomaly` | medium / MEDIUM | `query_records:104` (×2) | **Reasonable defensive-context observation.** The finding is policy-shaped (SMB exposure adjacent to a reachable RDP foothold raises blast-radius) rather than direct anomaly. MEDIUM/medium captures that distinction. The validator may dispute as policy commentary rather than detection — that's its role. |

## What the analyst missed

Per the targets the experiment design called out:

- **LISTENING count as elevated (35 listeners).** Surfaced
  qualitatively. The analyst did not commit a "35 listeners is high
  for a workstation" finding directly, but finding #4 reflects the
  exposure pattern (3389/445/139 co-located). It also acknowledged
  the count in the wrap-up. Acceptable.
- **The CLOSED count's churn signal (132 records).** Caught (finding
  #2). The analyst correctly attributed all but a small fraction of
  the CLOSED records to the same `local_port=3389` cohort already
  flagged.
- **Any ESTABLISHED connection to non-RFC1918 addresses.** Caught
  (finding #1). The analyst named the two specific external IPs and
  cited the underlying records.
- **The 7 null-PID kernel endpoints.** Caught (finding #3). Framed
  as "UDP, likely orphaned" rather than "kernel endpoints" — the
  more careful framing, since the records are UDP-only and the
  malicious shape (null-owner TCP listener) was actively confirmed
  to be absent.

Beyond the hint list, what the analyst chose *not* to commit:

- **The 19-distinct-foreign-IP ESTABLISHED distribution.** The
  `group_by(foreign_addr, filter=ESTABLISHED)` result showed top
  IPs `23.197.181.157(5), 23.46.190.35(5), 127.0.0.1(4),
  52.242.211.89(2)`. The analyst did not commit a finding about
  outbound diversity. Correct call: those IPs concentrate in
  Apple/Microsoft IP space (consistent with the `iCloud*`,
  `Teams`, `OneDrive` owners surfaced by the second `group_by`),
  and there's no reasonable beaconing claim from netscan alone.
- **Per-IP enumeration of CLOSE_WAIT (45 records) and CLOSED
  records' foreign-IP set.** The analyst pulled CLOSE_WAIT in turn
  8 but committed no finding from that result. Acceptable: 45
  CLOSE_WAIT entries are not anomalous on their own; the brute-force
  shape is already covered by finding #2.
- **Active DKOM-style network anomalies.** Actively confirmed absent
  in the wrap-up: "No null-owner TCP LISTENERs were observed; the 7
  null-owner endpoints are all UDP." This is the *absence-of-finding*
  the experiment hoped the analyst would actively check — delivered.

## Tool usage analysis

The analyst's pattern, in order:

1. **Tier-1 first** — single `vol_netscan` call. Fresh run, ~9 min
   wall (no cache). The summary's TCP-state distribution surfaced
   the structural shape immediately: `LISTENING=35, ESTABLISHED=33,
   CLOSED=132, CLOSE_WAIT=45, SYN_RCVD=1`. 7 null-owner records
   surfaced from `null_owner_count`.
2. **Distribution shaping next** — `group_by(foreign_addr,
   filter=ESTABLISHED, top_n=60)` was the very next call after
   tier-1. The analyst characterized the foreign-IP distribution
   for the 33 ESTABLISHED endpoints before drilling into specific
   states.
3. **State-by-state drill-in via `query_records`** — six
   consecutive `query_records` calls walking the listener / connection
   states: LISTENING, ESTABLISHED, owner-is-null, SYN_RCVD,
   `local_port=3389`, CLOSE_WAIT. Each filter narrowly targeted; no
   redundant repeats.
4. **Population characterization** — `group_by(field=owner)` (no
   filter) to see how the 430 records distribute across owner
   processes. 29 distinct owners; svchost.exe dominates (190).
5. **Findings commitment** — four sequential `record_finding` calls,
   each on the first try.

The intended tier-1-then-tier-2 workflow was again *discovered
organically from the prompt alone*. The analyst's opening play
differs from process_analyst v2's: process_analyst went straight to
`set_difference` (the cross-plugin primitive) after tier-1; network
has no second plugin to set-diff against, so network_analyst's
opening play is `group_by` to characterize the distribution before
drilling in. Both are correct shape inferences from the available
tools.

Tier-2 tools used at least once each: `query_records`, `group_by`.
Full tier-2 surface coverage on this analyst's narrower tool list.

## Failure modes

| Failure mode | Observed? | Detail |
| --- | --- | --- |
| Probe findings committed | **No** | All 4 committed findings carry meaningful `evidence_refs`; no `probe_*` titles in `findings.jsonl` lines 15-18. The d54636d `audit_line` plumbing eliminated the probe pattern end-to-end on a fresh tier-1 path. |
| `:rejected_invalid_audit_ref` | **No** | All 4 `record_finding` calls succeeded on first attempt; the analyst cited audit lines directly from each tier-1/tier-2 result's `audit_line` field rather than guessing. |
| Prose-instead-of-tool-call | No | All 4 findings went through `record_finding`. |
| Hallucinated tool / argument names | No | All 13 tool calls used valid MCP tool names and well-formed inputs; zero rejections of any class. |
| Findings without `evidence_refs` | No | All 4 carry refs that pass server-side audit-chain validation. |
| Self-marked DISPUTED | No | Highest confidence the analyst self-marked was HIGH. |
| Context exhaustion | No | Stopped at turn 14 with `stop_reason=end_turn`. Cache reads (85 K tokens) saved roughly 2× the input. |
| Tool-result-size deadlock (v1's process_analyst pre-tier-1/tier-2 issue) | **No** | Tier-1 return ≈540 B, tier-2 returns 0.6–8.6 KB. Architecture holds. |
| Re-running tools unnecessarily | **No** | Each filter was distinct; the analyst did not duplicate any state-filter or cohort query. |

The end-to-end empirical confirmation of the audit_line plumbing fix
is the load-bearing observation here: a fresh tier-1 run +
tier-2 drill-in + 4 `record_finding` commitments, all on the first
attempt, with zero probe contamination. The fix shipped in d54636d
is empirically validated; the failure mode #1 in
`docs/accuracy-report.md` is closed for the network analyst path.

## Comparison to process_analyst v2

| | process_analyst v2 (2026-05-06) | network_analyst v1 (2026-05-06) |
| --- | --- | --- |
| Tool surface | 9 tools (3 tier-1, 4 tier-2, register, record) | 5 tools (1 tier-1, 2 tier-2, register, record) |
| Tool calls before stop | 79 | 13 |
| Wall clock | 11m 25s (all tier-1 cached) | 16m 13s (tier-1 fresh ~9m) |
| API duration | 675 s | 110 s |
| Turns | 80 | 14 |
| Output tokens | 56,321 | 8,382 |
| Cost | $2.6110 | $0.5131 |
| Findings committed | 12 (5 substantive, 7 probe) | 4 (4 substantive, **0 probe**) |
| Server-side rejections | 28 (all `record_finding`) | **0** |
| Highest analyst confidence | MEDIUM | **HIGH** (×2) |
| `extraction.audit_line` populated | No (cached/legacy) | **Yes** (fresh write under d54636d) |
| Verdict | A — design works | A — design works (reproduced; probe pattern eliminated) |

network_analyst v1 reproduces process_analyst v2's Verdict A on a
narrower tool surface, with substantially better tool-call efficiency
(13 vs 79), zero rejections (vs 28), zero probe findings (vs 7),
and higher peak confidence (HIGH vs MEDIUM). The cost difference
(5×) and turn difference (5.7×) primarily reflect the absence of
the probe-finding loop; secondarily the smaller tool surface
(`set_difference` and `subtree` are not callable here) and the
narrower domain (one plugin vs three).

## Cross-source observation (data, not implementation)

Both analysts have now written into `case-data/findings.jsonl`
against the same evidence. The two finding sets are correlatable on
the `pid` join key but show no direct anomaly-on-anomaly overlap:

- process_analyst v2 flagged PIDs `7900` (svchost, hidden / pool-tag
  aliased), `4420` and `16480` (SearchFilterHost / SearchProtocolHost
  cohort, exited-but-resident), `29664` (b_only reverse gap),
  `8908`/`11672` (Teams.exe fan-out parent).
- network_analyst v1 pivoted on `1248` (TermService svchost,
  RDP listener + ESTABLISHED + brute-force churn owner),
  `4` (System, owner of TCP/445 + TCP/139 listeners), and
  observed-but-not-flagged owners (Teams, OneDrive, GoogleDrive,
  iCloudPhotos, Slack, WinStore).

No PID appears as an anomaly in *both* findings sets. The validator
(week 6) can compute meaningful cross-source observations from this
join key — for example: process_analyst's hidden PID 7900 should
have *zero* records in the netscan extraction (a hidden process
should not own active sockets); confirming that absence becomes a
cross_plugin HIGH-confidence corroboration. Conversely,
network_analyst's PID 1248 TermService should appear in
process_analyst's `pslist` records as a canonical-position
svchost.exe with `PPID=828=services.exe`; confirming that placement
elevates finding #1 from "host owns the connection" toward "host's
RDP service is canonical, the inbound IPs are the anomaly". Neither
correlation is computed in this PR — that is the validator's job in
week 6. The data is correlatable; the join key is `pid`; nothing
else changes.

## Verdict

**A — Design works.** Probe-finding pattern eliminated; audit_line
plumbing empirically validated end-to-end on a fresh tier-1 path;
two HIGH-confidence findings backed by non-RFC1918 ESTABLISHED RDP
and 124-record CLOSED churn on the same listener.

Justification: the experiment's hypothesis was that the same
minimal-methodology + restricted-MCP-surface pattern that worked for
process_analyst would work for a different artifact-family analyst,
and that the d54636d audit_line plumbing fix would eliminate the
probe-finding contamination from v2. Both held: 4 substantive
findings, 0 probes, 0 rejections of any class, organic
tier-1-then-tier-2 workflow discovered from the prompt alone, peak
confidence HIGH backed by appropriate evidence. The architectural
guardrails-over-prompt-guardrails principle reproduces in a second
analyst-domain instance, on a fresh tier-1 path that was not
exercised in v2.

### What this experiment is *not* evidence of

- It is not evidence that finding #1's "external public IPs" are
  malicious — only that the host has ESTABLISHED RDP from
  non-RFC1918, which is the netscan-resolution observation. Domain
  attribution (organization vs threat actor) is out of scope.
- It is not evidence that the validator will agree with HIGH on
  findings #1 and #2 — that is the validator's week-6 job.
- It is not evidence about beaconing, C2 jitter, or DNS — netscan
  alone cannot answer those questions; the analyst's wrap-up
  correctly refused to claim anything about them.
- It is not evidence that the same prompt would survive an
  adversarial netscan extraction containing prompt-injection
  payloads in `owner` or `foreign_addr` — that is the
  `adversarial-robustness.md` work, deferred.

It *is* evidence that the second analyst-subagent built to this
architecture produces categorized, schema-conformant, audit-back-
pointed DRAFT findings on a different artifact family, with the
probe-finding contamination bounded to zero by the fresh-path
exercise of the d54636d schema.

## Files produced this run

- `.claude/agents/network_analyst.md` (v1) — agent definition
- `case-data/audit/sift-guard-mcp.jsonl` lines 102-114 — 13 audit
  entries (1 fresh tier-1, 8 tier-2, 4 record_finding successes)
- `case-data/findings.jsonl` lines 15-18 — 4 substantive findings
- `case-data/extractions.jsonl` line 4 — 1 new
  `windows.netscan.NetScan` extraction (uncached on Rocba prior to
  this run)
- `case-data/extractions/6770da81-…/windows.netscan.NetScan.json`
  + `.sha256` — typed netscan extraction stored on disk
- `docs/network-analyst-v1-rocba.transcript.md` — turn-by-turn transcript
- `docs/network-analyst-v1-results.md` — this document
