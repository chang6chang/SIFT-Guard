# Protocol SIFT — assessment

## Source pin

| Field | Value |
|---|---|
| Repo | https://github.com/teamdfir/protocol-sift |
| Upstream HEAD inspected | `40bed7a96bfd986ea048c3b2aeb9d788b2f3400c` |
| Author (per README) | Rob Lee |
| License | **NO LICENSE FILE** in upstream — hard blocker for adoption / forking |
| Date inspected | 2026-05-05 |
| Inspected by | Claude Code session on WSL host (`GT1Mega`), via SSH to `siftworkstation` |
| install.sh SHA-256 | TODO — captured in prior session, paste here |

Total upstream commit history (4 commits): `40bed7a` Update README.md → `6eda0ed` fix: set execute bit on install.sh → `b6ab23f` fix: do not clone if zip used → `e2b6e4e` feat: protocol-sift. Young repo.

---

## On-disk state at time of assessment

- `~/.claude/` on `siftworkstation` populated **2026-05-05 20:49:27 UTC** (all install-manifest files within ~1 second of each other).
- Diff vs upstream HEAD `40bed7a`: **EMPTY** across CLAUDE.md, settings.json, settings.local.json, all 5 SKILL.md files, generate_pdf_report.py, and case-templates/CLAUDE.md. Full diff at `/tmp/protocol-sift-ondisk-vs-upstream.diff` (16 lines, all section headers — zero content lines). On-disk install is byte-identical to upstream HEAD.
- Extra directories beyond install.sh manifest:
  - `backups/` — `.claude.json.backup.1778014141311` (50 B), 2026-05-05 **20:49:01** UTC. This is a Claude Code runtime backup of `~/.claude.json` (the user-level config), **not** an install.sh artifact.
  - `cache/` — `changelog.md` (272 KB), 2026-05-05 **20:49:01** UTC. Claude Code runtime artifact.
  - `downloads/` — empty. Claude Code runtime directory.
- The 26-second gap between the 20:49:01 timestamps (Claude Code dirs) and the 20:49:27 timestamps (install.sh files) implies: Claude Code initialized first, then install.sh ran shortly after.
- No `.bak-<timestamp>` files in `backups/` — install.sh was run once, against a fresh `~/.claude/`. No re-installs.
- `claude` CLI not in PATH at inspection time (`command -v claude` → not found). settings.local.json references `~/.local/bin/claude`, suggesting prior install under `~/.local/`.

**Tentative conclusion about install history:** single fresh install on 2026-05-05, performed shortly after Claude Code was initialized on this VM. No drift, no re-install, no local edits. Identity of the installer (team member vs. SIFT OVA preload) **unknown**.

---

## Provenance — open questions for the team

- Who ran `install.sh` on this VM at 2026-05-05 20:49:27 UTC? Was it deliberate or auto-run by another process?
- Does the SIFT OVA ship Claude Code preinstalled? Confirm by reverting to OVA snapshot and `ls -la ~/.claude/`. (Out of scope today.)
- `claude` not currently in PATH — was it uninstalled, or installed only under `~/.local/bin/`? Run `ls -la ~/.local/bin/claude*` and `npm ls -g @anthropic-ai/claude-code` next session.

---

## What it actually is

Protocol SIFT is a **Claude Code skills-and-config package**, not an MCP framework. The hackathon brief's framing of it as "an MCP framework that connects AI to 200+ forensic tools" is **incorrect for this repository**. Evidence:

- `grep -r -i "mcp"` across `*.md *.json *.py *.sh *.toml *.yaml *.yml`: **zero matches**
- No `server.py`, `mcp_server*`, `*.mcp.json`
- No Python file imports `mcp`, `fastmcp`, or uses `@mcp.tool`
- README.md: "Claude Code + SANS SIFT Workstation Setup" — describes itself as a config replication guide
- README contains no mention of "MCP", "Model Context Protocol", "JSON-RPC", or "stdio"

The "AI connects to forensic tools" claim is delivered via Claude Code's standard `Bash` tool with a permissive `permissions.allow` list. There is no typed tool surface, no schema validation, no audit log of tool invocations, no daemon. The agent runs raw shell commands; the architectural posture is "trust the LLM to construct correct command lines, told via prompt to be careful."

---

## What install.sh installs

- `~/.claude/CLAUDE.md` (3506 B) — global system prompt: "Principal DFIR Orchestrator", evidence-integrity rules (prompt-level), tool path table, `NEVER ask questions during a task` autonomous mode
- `~/.claude/settings.json` (3132 B) — Claude Code permissions; pre-approves Bash for every common SIFT forensic CLI; Stop hook appends to `./analysis/forensic_audit.log`
- `~/.claude/settings.local.json` (170 B) — local sudo apt + psort.py + `~/.local/bin/claude` overrides
- `~/.claude/skills/{memory-analysis,plaso-timeline,sleuthkit,windows-artifacts,yara-hunting}/SKILL.md` — five domain skill files, ~10–17 KB each
- `~/.claude/case-templates/CLAUDE.md` (6472 B) — per-case template
- `~/.claude/analysis-scripts/generate_pdf_report.py` (27937 B) — WeasyPrint executive PDF generator
- Optional: `pip3 install weasyprint` — **not run in this assessment**

Per README, install.sh backs up any pre-existing `~/.claude/{CLAUDE.md,settings.json,settings.local.json}` to `.bak-<timestamp>` before overwriting. None observed in `backups/`, confirming a fresh install.

---

## Topology

**No MCP server. No daemon. No persistent process. No transport.**

Architecture: `claude` (the binary) → its built-in `Bash` tool → directly invokes SIFT CLI binaries in shell. Permissions gated by allow-list in `settings.json`. There is no separate server because there is no separate process. There is no typed tool surface — every "tool" is a free-form Bash command. There is no server-side input validation, hash registration, mount-validation, or audit chain.

---

## Skills inventory

| Skill | What it tells the agent | Shell tools invoked | Uses `Bash` directly |
|---|---|---|---|
| `memory-analysis` | Volatility 3 + Memory Baseliner; psscan/pslist diff for hidden processes; malfind/vadinfo for injection; 6-step methodology | `vol`, `python3 /opt/memory-baseliner/baseline.py`, `strings`, `mactime` | yes |
| `plaso-timeline` | Super-timeline creation (log2timeline → psort), `--vss-stores all`, parser presets (`win10`, `win7`, `webhist`), filter syntax | `log2timeline.py`, `psort.py`, `pinfo.py`, `psteal.py`, `image_export.py` | yes |
| `sleuthkit` | E01 verify → ewfmount → mmls → mount loop offset → fls → icat; bodyfile → mactime; bulk_extractor / photorec carving | `ewfinfo`, `ewfverify`, `ewfmount`, `mmls`, `fsstat`, `fls`, `icat`, `mactime`, `bulk_extractor`, `photorec` | yes |
| `windows-artifacts` | EZ Tools via `dotnet`; Prefetch / Shimcache / Amcache / MFT / UsnJrnl / Registry batch / Shellbags / SRUM / EvtxECmd; Autorunsc CSV triage | `dotnet /opt/zimmermantools/<X>.dll` for ~14 EZ tools | yes |
| `yara-hunting` | YARA rule structure, PE/math/hash modules, IOC sweeps, Velociraptor VQL reference (enterprise) | `yara`, `yarac` | yes |

Every skill instructs the agent to run forensic CLIs directly via the Bash tool. None reference `mcp__`, an MCP server, or a typed tool interface. The skill files are well-organized methodology + flag-reference documents — high-quality DFIR content, low-quality from an architectural-guardrail standpoint.

---

## Hallucination and architectural-guardrail observations

Protocol SIFT is **almost entirely prompt-level guardrails**. The hackathon rubric criterion #4 (Constraint Implementation) explicitly favors architectural over prompt guardrails. Protocol SIFT scores poorly on this dimension.

**Prompt-level rules in CLAUDE.md (agent-compliance only, not enforced):**
- "Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory"
- "Always output in UTC"
- "No hallucinations — never guess, assume, or fabricate"
- "Verify tool success after every run"

**Architectural mechanisms actually present:**
- `permissions.deny` blocks `rm -rf:*`, `dd:*`, `wget:*`, `curl:*`, `ssh:*`, `WebFetch`. Real protection against destruction and exfiltration.
- `permissions.allow` starts with **`"Bash(*)"`** — a wildcard that auto-approves *every* bash command. The ~50 per-tool entries that follow are functionally redundant. In practice, anything not explicitly in `deny` is allowed. So `cat > /cases/srl/foo.txt` (overwriting evidence) is allowed; `cp /cases/srl/x.E01 /tmp/y.E01` (copying evidence elsewhere) is allowed; `tar -czf /tmp/exfil.tgz /cases/` is allowed.
- The `Stop` hook appends ONE line per session (`$DATE: $CONVERSATION_SUMMARY`) to `./analysis/forensic_audit.log` at end-of-conversation, on the agent's own terms. Not a tamper-evident audit log; not a per-tool-call record; no hash chain.

**Specifically, Protocol SIFT does NOT:**
- Hash evidence files at registration time
- Re-hash evidence at end-of-run to detect tampering (the demo-tampering moment in our plan)
- Validate that mounts are read-only (told the agent "always mount RO" — agent compliance)
- chmod evidence to 444 / parent dir 555
- Audit each tool invocation with structured input + output + exit code
- Treat evidence-derived strings as untrusted (no `<evidence>` delimiters, no prompt-injection isolation — registry values, EVTX message strings, browser history all flow into the LLM context as raw text)
- Confine file paths — agent can `cat /etc/passwd`, `cat ~/.ssh/id_rsa`, etc., since those are allowed by `Bash(*)` and not in deny
- Enforce a typed tool schema — agent invents command lines, can pass any flag combination

**Pre-loaded case context — major architectural conflict with SIFT-Guard:**

`case-templates/CLAUDE.md` ships with the **complete ground-truth narrative for a SANS FOR508 / Stark Research Labs case**:

- Threat actor name (`CRIMSON OSPREY`), incident date, IR consultant role
- Specific evidence file paths (`/cases/srl/base-rd01-cdrive.E01` etc.)
- Network topology with exact subnets and host names
- Domain account list with roles
- **Confirmed malware table:** `STUN.exe` PID 1912 parent svchost.exe PID 1244, `msedge.exe` masquerading (Trojan:Win32/PowerRunner.A), `pssdnsvc.exe`, `atmfd.dll`
- **Lateral movement command:** `net use H: \\172.16.6.12\c$\Users` — net.exe PID 9128
- **Exact UTC timestamps** for the attack chain (2023-01-25 14:52:04 lateral movement, etc.)

An agent that loads this template has been pre-loaded with the answer key. This is exactly the scenario SIFT-Guard's "Ground truth isolation" hard rule was written to forbid. **Protocol SIFT's design philosophy is the opposite of ours**: theirs is "give the agent the case briefing"; ours is "the agent operates from evidence alone." This is the wedge.

(Note: the template lives at `~/.claude/case-templates/CLAUDE.md`, not at `~/.claude/CLAUDE.md`. So it isn't auto-injected globally — it's a template the user is meant to copy into a per-case working directory. Still, the design intent is "the agent should know the case scenario in advance.")

---

## Integration options

### Option A — adopt their skills, adapted to call `mcp__sift-guard__*` tools

**What we'd do:** Take the well-organized SKILL.md content (methodology, plugin reference tables, anomaly indicator lists), strip the raw Bash invocations, replace each with a reference to the equivalent typed `mcp__sift-guard__<plugin>` tool. Adapt the resulting skill files into the SIFT-Guard analyst-subagent prompts.

**Cost:** ~6–10 person-hours per skill × 5 = 30–50 person-hours. Roughly 1–2 weeks of one person at our 10 hr/week budget.

**Risk:** **License blocker.** No LICENSE file in upstream means we cannot legally adopt or paraphrase their text. Would require getting TeamDFIR to add a license. If they decline or it's restrictive, this option is dead. There is also a methodology-coupling risk: if our typed-tool surface diverges from Protocol SIFT's flag conventions, the adapted skills could go stale.

**Rubric story:** "We rebuilt the methodology shipped by the leading published example, with the architectural guardrails the rubric demands." Strong **Breadth & Depth (#3)**, modest **Constraint Implementation (#4)** uplift. Does **not** advance **Autonomous Execution (#1)** — that's the iterate loop, separate work.

### Option B — install alongside, use only as accuracy benchmark baseline

**What we'd do:** Keep Protocol SIFT installed on the SIFT VM as-is (already done — verified clean install today). Run BOTH systems against the Rocba memory image. Compare findings: Protocol SIFT (one-shot, prompt-guardrail, no validator) vs SIFT-Guard (iterative, typed tools, hash-chained audit, cross-plugin validator). Document the deltas in `docs/accuracy-report.md`.

**Cost:** ~8 person-hours total. Need a documented run procedure on the VM, results-comparison spreadsheet, prose write-up. No code work.

**Risk:** Low. Read-only on the VM. License irrelevant — using a tool as a black-box benchmark is not derivative work.

**Rubric story:** Strongest of the three. Drives **#1 Autonomous Execution** (Protocol SIFT lacks a self-correction loop entirely — head-to-head shows our wedge), **#2 IR Accuracy** (numbers, not claims), **#4 Constraint Implementation** (point to a specific finding where prompt-guardrails failed and architectural guardrails caught it), **#5 Audit Trail** (one-line-per-session vs hash-chained per-tool-call), and **#6 Documentation** (failure-mode catalog).

### Option C — fork, replace shell-out pattern with our typed MCP tools

**What we'd do:** Hard fork upstream into the SIFT-Guard org. Keep SKILL.md structure and methodology. Replace every `Bash(vol -f ...)` invocation with `mcp__sift-guard__vol_pslist(...)` etc. Add our audit chain, evidence registration, and validator. Rebrand.

**Cost:** ~80–120 person-hours. Effectively reorganizes Weeks 3–4 around Protocol SIFT's structure rather than ours.

**Risk:** **Same license blocker as A, only worse.** Forking unlicensed code is even less defensible than adapting individual phrases. Also: locks us to upstream's structural decisions; harder to evolve our typed tool surface independently. Reputational framing is "the SIFT-Guard fork of Protocol SIFT" — derivative.

**Rubric story:** Weakest. Looks derivative. Cedes the **Autonomous Execution** narrative because we'd have to add the loop after forking, and the framing dilutes the wedge.

---

## Recommendation

**Option B — install alongside as accuracy benchmark baseline.**

Protocol SIFT is already cleanly installed on the SIFT VM (validated by byte-identical diff against upstream HEAD `40bed7a`). It is a Claude Code skills package, not an MCP framework, and its design philosophy — prompt guardrails, pre-loaded case context, end-of-session single-line audit — is fundamentally opposed to ours. **That contrast is the story the rubric asks us to tell.**

Running both systems against Rocba lets us produce a side-by-side comparison in our accuracy report, demonstrating concretely where SIFT-Guard's typed tools, hash-chained audit, evidence delimiters, and cross-plugin validator catch things Protocol SIFT misses or hallucinates. This serves rubric criteria #1, #4, #5, and #6 simultaneously.

Adopting (A) or forking (C) is blocked anyway — upstream ships **without a LICENSE file**. Until TeamDFIR adds one, we cannot legally adopt their text. Option B uses Protocol SIFT only as a black-box comparison baseline (running it, observing outputs), which is permitted regardless of license.

---

## Open questions

- **Provenance:** Who installed Claude Code (20:49:01 UTC) and Protocol SIFT (20:49:27 UTC) on this VM today? Was the SIFT OVA shipped with either? Test by reverting to OVA snapshot.
- **License:** Open a polite GitHub issue asking TeamDFIR to add a LICENSE file (MIT or Apache-2.0). This unlocks Option A as a future fallback.
- **install.sh SHA-256:** Captured in prior session; paste into "Source pin" table above. (TODO)
- **Claude binary location:** `claude` not in PATH; settings.local.json suggests `~/.local/bin/claude`. Confirm with `ls -la ~/.local/bin/claude*` and `npm ls -g @anthropic-ai/claude-code` next session.
- **`Bash(*)` allow wildcard:** Confirm whether the per-tool allow entries below it are intentional documentation or vestigial — the wildcard makes them functionally redundant. Worth a comment in our `docs/decisions-log.md` so we don't accidentally repeat the pattern.
- **Stop-hook side effects:** The `./analysis/forensic_audit.log` Stop hook writes to whatever directory `claude` was launched from. Not a concern for SIFT-Guard runs (those happen on WSL where Protocol SIFT is NOT installed) but flag it.
- **Velociraptor reference in `yara-hunting/SKILL.md`:** Skill assumes a Velociraptor server. Irrelevant to memory-only Rocba. Note for any future enterprise-data case.
- **Pre-loaded case context risk:** If a future Protocol SIFT user copies `case-templates/CLAUDE.md` into a new case directory and forgets to scrub the SRL/STUN.exe IOC table, the agent gets the wrong-case answer key. Useful failure-mode example for our `docs/dataset-inventory.md` write-up.
