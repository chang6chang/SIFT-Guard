# Demo screencast — shot-by-shot script

> 5 minutes · 3 acts · 1080p · target 1000–1200 narration words (≈240
> wpm conversational pace, with breathing room around terminal beats).
> Source numbers: `docs/accuracy-report.md` (chain-truth totals) and
> the on-disk JSONL chains under `case-data/`. If a number changes
> between the script being written and the screencast being
> recorded, the chains win — re-quote.

## Pre-recording checklist (team, not narration)

- [ ] Pre-record every terminal session — no live typing in the
      screencast. The SRL run takes ~10 hours; show the launch
      command, then cut to results from a completed run.
- [ ] Terminal: bump font size for 1080p readability (Ctrl+= until
      `vim`'s default split pane shows ~80 columns × 24 rows
      legibly at 1080p). Dark theme. Disable shell prompt's
      multi-line right side.
- [ ] OBS settings: 1920×1080, 30fps, MP4 (h264 hardware encode if
      available), CBR ~8 Mbps. Target final file <500 MB for
      Devpost upload.
- [ ] No background music. Judges are forensic practitioners.
- [ ] Speaker: whoever is most comfortable narrating technical
      content in English. Re-record any beat that comes out
      stilted — narration warmth matters more than perfect takes.
- [ ] Mic: pop filter, monitor levels in OBS, gate aggressive
      breath / room noise. One quiet take of the whole script
      before the camera roll catches things you only hear back.
- [ ] Fonts: lower-third overlays in a neutral sans-serif (Inter,
      Helvetica, system-ui). Lower-third dwell ≥3 seconds, fade
      0.3s in / 0.5s out.
- [ ] Browser tabs: pre-open README rendered on GitHub
      (`chang6chang/SIFT-Guard`), the architecture diagram MD
      page rendered to PNG, the accuracy report. Pre-zoom each.
- [ ] Capture jq one-liners ahead of time and dry-run them
      against the live chains (the script gives the queries; the
      output you'll show is whatever your run actually emitted).

## ACT 1 — What is SIFT-Guard (0:00–1:15)

### Beat 1.1 — Title card (0:00–0:05)

🎬 **Visual.** Static title card. Project name, tagline, hackathon
attribution, no logo flash.

📌 **On-screen text.**

```
SIFT-Guard
Autonomous DFIR agent with cross-host self-correction
SANS "Find Evil!" 2026
```

🎙 **Narration (none)** — silent for the first 3 seconds, then voice
fades in over the open transition.

---

### Beat 1.2 — One-sentence pitch (0:05–0:18)

🎬 **Visual.** Cut to the GitHub-rendered README opening section
(repo `chang6chang/SIFT-Guard`, the first ~10 lines visible).

🎙 **Narration (~30 words).**

> SIFT-Guard is an autonomous DFIR agent that analyzes forensic
> evidence across multiple hosts, cross-correlates findings, and
> self-corrects — with every action hash-chained for auditability.

📌 **Lower third.** *"19 typed MCP tools · 4 hash-chained logs · 491
tests"*

---

### Beat 1.3 — Architecture diagram walkthrough (0:18–0:55)

🎬 **Visual.** Cut to the Mermaid architecture diagram from
`docs/architecture-diagram.md` (or its PNG export). Hold static.
Use a soft highlight / animated overlay to call out, in order:

1. The MCP-server subgraph (top-center).
2. The three analyst subagents (blue boxes, left).
3. The validator subagent (orange box).
4. The orchestrator (green box, center-right).
5. The four chain cylinders (bottom).

🎙 **Narration (~85 words).**

> The architecture is four pieces. First, an MCP server — the
> nineteen typed tools at the top. Second, three analyst subagents
> on the left — process, network, disk — each restricted by
> frontmatter to a specific tool surface. Third, a validator
> subagent in orange — a separate agent that can re-query the
> evidence but **cannot write findings.** Finding mutation belongs
> to the green orchestrator: a plain Python process, not an LLM.
> All four write into hash-chained JSONL logs at the bottom.

📌 **Lower third.** *"3 analyst subagents · 1 validator · 1
orchestrator (Python, not LLM)"*

---

### Beat 1.4 — Architectural enforcement claim (0:55–1:05)

🎬 **Visual.** Stay on the diagram. Highlight the **absence** of
arrows from `validator` to `record_finding` and from analysts to
`record_correlation`.

🎙 **Narration (~35 words).**

> The differentiator is which arrows are *absent*. The validator
> has no arrow to record_finding. Analysts have no arrow to
> record_correlation. This is architectural enforcement — it's not
> in the prompt, it's in the tool surface.

---

### Beat 1.5 — RAG flash (1:05–1:15)

🎬 **Visual.** Quick cut to the 19-tool table (architecture-diagram
section "MCP tools by writer role"). Hold for ~3 seconds — long
enough that a viewer who pauses can read it; short enough that
nobody feels lectured. Then cut to a one-line shell command
showing the corpus size:

```
$ ls rag/data/ && wc -l rag/data/attack-enterprise.records.json
attack-enterprise.faiss   attack-enterprise.records.json   meta.json
2844 attack-enterprise.records.json
```

🎙 **Narration (~30 words).**

> A 2844-record RAG index — six hundred ninety-seven MITRE
> ATT&CK techniques plus two thousand one hundred forty-seven
> Sigma detection rules — queried autonomously by the validator
> to ground findings in known TTPs.

📌 **Lower third.** *"RAG corpus: 2844 records · 697 ATT&CK + 2147
Sigma · validator-only access"*

---

## ACT 2 — SRL-2015: Cross-host APT attribution (1:15–4:00)

### Beat 2a — Setup: four hosts, one incident (1:15–1:45)

🎬 **Visual.** Cut to a terminal. Show the multi-host scan-only
launch and its output:

```
$ python -m orchestrator.main run-case \
    --evidence-dir /mnt/srl-2015 \
    --case-dir case-data \
    --scan-only

Host                | Evidence                          | Type   | Size
--------------------+-----------------------------------+--------+-------
nfury               | nfury-Memory.001                  | memory | 13.3 GB
nromanoff           | nromanoff-Memory.001              | memory |  4.2 GB
win2008R2-controller| controller-Memory.001             | memory | 16.3 GB
xp-tdungan          | xp-tdungan-Memory.001             | memory |  2.1 GB
```

Then cut to the run-case launch (no `--scan-only` this time):

```
$ python -m orchestrator.main run-case \
    --evidence-dir /mnt/srl-2015 \
    --case-dir case-data \
    --max-iterations 4 \
    --token-budget 2000000
[orchestrator] dispatching process_analyst on nfury...
```

🎙 **Narration (~70 words).**

> SRL-2015 is four memory images from an enterprise APT incident
> — Windows seven, Windows XP, a Server 2008 R2 domain controller
> — all captured within a three-hour window during active incident
> response. The orchestrator scans the directory, registers each
> file, builds a per-host manifest, and dispatches three analyst
> subagents per host plus the validator. The full run takes about
> ten hours; we cut to results.

📌 **Lower third.** *"SRL-2015 · 4 hosts · captured 2012-04-06 ·
memory-only"*

---

### Beat 2b — Per-host findings: each host alone is suspicious (1:45–2:15)

🎬 **Visual.** Cut to a terminal showing two `jq` queries against
`case-data/findings.jsonl`. The team should run these against the
real chain so what's on screen is genuine output. Suggested
commands and expected shape:

```
$ jq -c 'select(.record_kind=="draft" and .draft.host_id=="nromanoff") |
         {title: .draft.title, category: .draft.category, conf: .draft.confidence}' \
    case-data/findings.jsonl | head -3
{"title":"spinlock.exe loaded under PSEXESVC parent...", "category":"process_anomaly", "conf":"MEDIUM"}
{"title":"svchost.exe in non-standard path C:\\Windows\\System32\\dllhost\\...", "category":"process_masquerade", "conf":"MEDIUM"}
{"title":"TCP outbound 10.3.58.5:49805 → 10.3.58.9:445 ESTABLISHED...", "category":"network_lateral_movement", "conf":"MEDIUM"}

$ jq -c 'select(.record_kind=="draft" and .draft.host_id=="xp-tdungan") |
         {title: .draft.title, category: .draft.category, conf: .draft.confidence}' \
    case-data/findings.jsonl | head -3
{"title":"3 spinlock.exe instances visible only via psscan (DKOM-hidden)...", "category":"process_hidden", "conf":"MEDIUM"}
{"title":"svchost.exe in non-standard path C:\\Windows\\System32\\dllhost\\...", "category":"process_masquerade", "conf":"MEDIUM"}
```

🎙 **Narration (~75 words).**

> Look at nromanoff alone. Spinlock dot exe loaded under a PSEXESVC
> parent. An svchost masquerade in a non-standard path. An
> outbound SMB session. Each finding is interesting but
> ambiguous in isolation — could be sysadmin tooling, could be
> tradecraft.
>
> Now look at xp-tdungan. Three spinlock instances actively
> hidden from pslist. The same svchost masquerade, identical
> path. Single-host analysis can't distinguish coincidence from a
> shared toolkit. Cross-host correlation can.

---

### Beat 2c — Cross-host correlation: the money shot (2:15–3:15)

🎬 **Visual.** Cut to a terminal. Show three `jq` queries pulling
the three `cross_host` correlations from `correlations.jsonl`.
Hold each correlation on screen for a beat while the narration
hits its argument.

Query 1 — `spinlock.exe` cross-host:

```
$ jq -c 'select(.correlation.correlation_type=="cross_host" and
              (.correlation.shared_indicator | contains("spinlock")))' \
    case-data/correlations.jsonl
{
  "correlation_type": "cross_host",
  "host_ids": ["nromanoff", "xp-tdungan"],
  "shared_indicator": "spinlock.exe",
  "strength": "strong",
  "hypothesis": "Same uncommon binary on two independently-acquired
                memory images. On nromanoff: PsExec lateral tool
                transfer (T1570) + service execution (T1569.002).
                On xp-tdungan: three instances DKOM-hidden from
                pslist (T1014). Same toolkit, same operator.",
  "evidence_refs": [...]
}
```

🎙 **Narration block 1 (~50 words).**

> The same uncommon binary on two independently-acquired memory
> images, captured thirty-six hours apart. On nromanoff, delivered
> via PsExec. On xp-tdungan, actively rootkit-hidden. Same toolkit.
> Same operator. The validator emits this as a strong cross-host
> corroboration, citing MITRE T1014 Rootkit and T1569 Service
> Execution.

Query 2 — bidirectional SMB session:

```
$ jq -c 'select(.correlation.correlation_type=="cross_host" and
              (.correlation.shared_indicator | contains("49805")))' \
    case-data/correlations.jsonl
{
  "correlation_type": "cross_host",
  "host_ids": ["nromanoff", "win2008R2-controller"],
  "shared_indicator": "10.3.58.5:49805 ↔ 10.3.58.9:445",
  "strength": "strong",
  "hypothesis": "Same TCP 4-tuple visible from BOTH endpoints
                simultaneously — outbound on nromanoff's netscan,
                inbound on controller's netscan. Source-port match
                across independent images = lateral movement
                T1021.002 in progress at acquisition time.",
  ...
}
```

🎙 **Narration block 2 (~45 words).**

> The exact same TCP session — same source port, port forty-nine
> thousand eight hundred five — visible from both endpoints
> simultaneously. Nromanoff's netscan shows it outbound. The
> controller's netscan shows it inbound. Source-port collisions
> across independent images don't happen by accident. Lateral
> movement caught mid-flight.

Query 3 — `svchost.exe` masquerade:

```
$ jq -c 'select(.correlation.correlation_type=="cross_host" and
              (.correlation.shared_indicator | contains("dllhost")))' \
    case-data/correlations.jsonl
{
  "correlation_type": "cross_host",
  "host_ids": ["nromanoff", "xp-tdungan"],
  "shared_indicator": "C:\\Windows\\System32\\dllhost\\svchost.exe",
  "strength": "strong",
  "hypothesis": "Identical non-standard path on two hosts.
                Legitimate svchost.exe lives in System32 and
                always carries -k. T1036.005 Match Legitimate
                Name or Location, linking both incidents to the
                same operator toolkit.",
  ...
}
```

🎙 **Narration block 3 (~30 words).**

> And an svchost.exe masquerade — identical non-standard path on
> two hosts. T1036.005, Match Legitimate Name or Location. None
> of these conclusions are possible from single-host analysis.

📌 **Lower third (visible during the three queries).** *"10
cross_host correlations · 3 strong lateral movement · 4 strong
shared infrastructure · 3 moderate"*

---

### Beat 2d — Self-correction + RAG grounding (3:15–3:45)

🎬 **Visual.** Cut to `jq` against `iterations.jsonl` showing the
two iterations and the request_followup that drove iter 2:

```
$ jq -c '{iter: .payload.iteration_number,
         analysts_dispatched: .payload.analysts_dispatched,
         followups: .payload.followups_emitted}' \
    case-data/iterations.jsonl
{"iter": 1, "analysts_dispatched": ["process_analyst","network_analyst"], "followups": [{"target": "process_analyst", "host": "nfury", "pids": [1780, 2508]}]}
{"iter": 2, "analysts_dispatched": ["process_analyst on nfury (focused)"], "followups": []}
```

Then a quick cut to a `rag_query` audit line linked to a
correlation:

```
$ jq -c 'select(.tool_name=="rag_query") | .input_args.technique_id' \
    case-data/audit/sift-guard-mcp.jsonl | tail -3
"T1014"
"T1036.005"
"T1569.002"
```

Finally, the iteration record showing termination:

```
$ jq '.payload.termination_check.flags' case-data/iterations.jsonl | tail -1
{
  "R_a_zero_unresolved": false,
  "R_b_disputed_set_unchanged": true,
  "R_c_token_budget_exceeded": false,
  "max_iterations_reached": false
}
```

🎙 **Narration (~80 words).**

> Iteration one produced thirty-nine findings and a
> request_followup pointing at two suspicious PIDs on nfury.
> Iteration two re-dispatched process_analyst with focus context;
> six new findings, twenty new correlations.
>
> The validator made eight autonomous rag_query calls — querying
> the merged ATT&CK and Sigma corpus — to ground its
> correlations in named TTPs. T1014 Rootkit. T1036.005 Match
> Legitimate Name. T1569 Service Execution.
>
> The loop terminated when the disputed set stabilized. Not after
> a fixed iteration count — when convergence was detected.

📌 **Lower third.** *"Termination: R_b_disputed_set_unchanged · 2
of 4 iterations · 648K uncached tokens"*

---

### Beat 2e — Audit integrity (3:45–4:00)

🎬 **Visual.** One terminal command verifying the hash chain:

```
$ python -m server.audit verify case-data/audit/sift-guard-mcp.jsonl
[OK] audit chain: 612 lines verified · genesis prev_hash=000...0
[OK] no hash mismatches · chain head: 4f8c1...d3e
```

(If the team doesn't have a one-liner verifier yet, run a small
inline Python snippet via `python -c` that walks the chain and
asserts every line's `prev_line_hash == previous.this_line_hash`
— same outcome, slightly less polished. Either is fine.)

🎙 **Narration (~30 words).**

> Every tool call. Every finding. Every correlation. Every
> promotion. Hash-chained. Tamper with any line and every
> subsequent hash breaks. The chain is the audit trail.

📌 **Lower third.** *"4 hash-chained JSONL logs · audit-replay
fully reproduces every promotion"*

---

## ACT 3 — What we built, what we learned (4:00–5:00)

### Beat 3.1 — Numbers (4:00–4:25)

🎬 **Visual.** Cut to a slide / over-laid card showing the
headline numbers, populated from the v0.9 accuracy report:

```
SIFT-Guard at v0.9
─────────────────────────
19    typed MCP tools
491   tests, all green
120   findings across 3 evidence corpora
89    CONFIRMED (78 HIGH + 11 MEDIUM)
10    cross-host correlations
2844  RAG records (697 ATT&CK + 2147 Sigma)
11    documented failure modes
```

🎙 **Narration (~50 words).**

> Nineteen typed MCP tools. Four hundred ninety-one tests, all
> green. One hundred twenty findings across three evidence
> corpora. Eighty-nine confirmed, six disputed. Ten cross-host
> correlations. A twenty-eight-hundred-record RAG index. Eleven
> documented failure modes — because the rubric explicitly
> rewards them.

---

### Beat 3.2 — Honest limitations (4:25–4:45)

🎬 **Visual.** Stay on the same slide; fade in a "Known
limitations" panel underneath, three concise bullets.

```
Known and documented
─────────────────────────
· Disk-side tools are built and tested — not yet exercised on
  real evidence (memory↔disk cross-source pending)
· Windows XP vol_netscan unsupported by upstream Volatility 3
· Validator subprocess hung 9.5h on one large correlation pass
  (deferred fix: Popen with non-blocking pipe drain)
All in docs/accuracy-report.md, failure modes #8–#11.
```

🎙 **Narration (~50 words).**

> Honest limitations. The disk-side tools are built and tested
> but haven't been exercised on real disk evidence yet. Windows
> XP netscan is unsupported upstream. The validator once hung
> for nine and a half hours on a large correlation pass — a
> classic subprocess pipe deadlock, mitigation deferred. All
> documented in the accuracy report.

---

### Beat 3.3 — Differentiator (4:45–4:55)

🎬 **Visual.** Cut back to the architecture diagram. Hold static.

🎙 **Narration (~50 words).**

> Other submissions analyze one image at a time, with human
> guidance. SIFT-Guard analyzes multiple hosts autonomously,
> cross-correlates across them, self-corrects when the evidence
> contradicts itself, and produces an auditable evidence chain
> — with architectural guardrails that prevent the agent from
> modifying evidence or hallucinating tool invocations.

---

### Beat 3.4 — Close (4:55–5:00)

🎬 **Visual.** Closing card. Project name, repo URL, hackathon
attribution.

📌 **On-screen text.**

```
SIFT-Guard
github.com/chang6chang/SIFT-Guard
SANS "Find Evil!" 2026
```

🎙 **Narration (~20 words).**

> SIFT-Guard. Autonomous cross-host forensic analysis with
> self-correction. Built for the SANS Find Evil hackathon.

---

## Narration word count budget (running total)

| Beat | Words | Cumulative |
|---|---|---|
| 1.2 pitch | 30 | 30 |
| 1.3 architecture | 85 | 115 |
| 1.4 enforcement | 35 | 150 |
| 1.5 RAG flash | 30 | 180 |
| 2a setup | 70 | 250 |
| 2b per-host | 75 | 325 |
| 2c cross-host (3 blocks) | 125 | 450 |
| 2d self-correction | 80 | 530 |
| 2e audit | 30 | 560 |
| 3.1 numbers | 50 | 610 |
| 3.2 limitations | 50 | 660 |
| 3.3 differentiator | 50 | 710 |
| 3.4 close | 20 | 730 |

**Total ≈ 730 spoken words** in 4 minutes 55 seconds of narrated
runtime (the title card and closing card add ~10 seconds of
silence). At 730 words / 4.9 min = **149 wpm** — comfortable
conversational pace, leaves headroom for natural pauses on
terminal beats. If a take feels rushed, slow down on the
cross-host narration in Beat 2c; that's the central argument and
deserves to land.

## Post-production checklist

- [ ] First pass: cut to length. If overrun, trim Beat 2b
      (per-host findings) before trimming the cross-host beat —
      2c is the headline argument and shouldn't be shortened.
- [ ] Verify all on-screen JSON is from the actual chain, not a
      mock. Spot-check two cross_host correlations against
      `correlations.jsonl` line-by-line.
- [ ] Lower-third overlays don't cover terminal output. Anchor
      bottom-center; max two lines.
- [ ] No emoji in lower-thirds.
- [ ] Verify no API keys / personal paths leak in any terminal
      capture. Common offenders: `ANTHROPIC_API_KEY` env-dump,
      `~/.zsh_history` previews, `/home/<your-user>/...` in
      paths. Mask with sed before publishing.
- [ ] Export: 1080p, h264, AAC audio, MP4. Confirm <500 MB.
- [ ] Caption track: auto-generate via OBS/CapCut, then proofread
      every technical term (T1014, T1569.002, evidence_id, the
      tool names). The auto-captioner mangles "MITRE", "TTPs",
      and "psscan" reliably.

## Sources for narration content

This script quotes numbers and phrasings from:

- `docs/accuracy-report.md` § "Multi-host cross-source validation
  — SRL-2015" (the three smoking guns; aggregate run results;
  termination rule)
- `docs/accuracy-report.md` § "Quantitative metrics from the
  chains" (120 findings, 89 CONFIRMED, 10 cross_host, 11 failure
  modes, 491 tests)
- `docs/architecture-diagram.md` § "MCP tools by writer role"
  (19 tools, validator-only RAG access)
- `docs/confidence-methodology.md` § "Promotion rules" (R_b
  termination, cross_host feeds R3)
- `README.md` § "Multi-host case (advanced)" (run-case command,
  scan-only preview)
- `docs/adversarial-robustness.md` § "Defense layers" (the
  architectural-enforcement framing in Beat 1.4)

If any of these documents change between script-write and
recording, re-quote — the script is downstream of the docs, not
parallel to them.
