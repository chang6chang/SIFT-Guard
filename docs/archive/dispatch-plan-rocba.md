# Dispatch plan — Rocba (memory-only)

Day-1 action #3 from CLAUDE.md. This document encodes the analyst
roster, plugin ownership, and validator contradiction rules for the
Rocba case. The plan is **generic to any memory-only Windows case** —
no scenario-specific facts (target identity, suspect window, narrative,
or expected findings) are encoded here. Those live in
`docs/dataset-inventory.md` and are off-limits to the agent at runtime
(CLAUDE.md "Ground truth isolation").

## Inputs (what the orchestrator sees)

The orchestrator's dispatch decision is driven by `CASE.yaml` and the
artifact-class detector only:

| Field | Value | Source |
|---|---|---|
| Artifact classes present | `{memory_image}` | `register_evidence` magic-byte + extension detection |
| Image OS family | Windows 10 (Major/Minor 15.19041, NtProductWinNt) | `windows.info.Info` smoke test, `docs/volatility-smoke-test.md` |
| Capture wall-clock | `SystemTime` field of `windows.info.Info` | same |
| Validation modes available | `cross_plugin`, `single_source` | derived: only one artifact, so `cross_source` and `cross_artifact` are unavailable |

`windows.info.Info` is run once at case-init by the orchestrator (not
owned by any analyst) to populate the kernel-profile context that
downstream analysts share.

## Analyst roster

### Active (memory_image present)

| Analyst | Plugins owned (exact Volatility 3 names) |
|---|---|
| `process_analyst` | `windows.pslist.PsList`, `windows.psscan.PsScan`, `windows.pstree.PsTree`, `windows.cmdline.CmdLine`, `windows.handles.Handles` |
| `network_analyst` | `windows.netscan.NetScan`, `windows.netstat.NetStat` |
| `injection_analyst` | `windows.malfind.Malfind`, `windows.dlllist.DllList`, `windows.ldrmodules.LdrModules`, `windows.modules.Modules`, `windows.modscan.ModScan` |
| `validator` | no plugins owned; consumes DRAFT findings from the three above and emits CONFIRMED / SINGLE_SOURCE / CONTRADICTION verdicts |

### Dormant (no compatible artifact)

`disk_analyst`, `registry_analyst`, `eventlog_analyst` — silent for
this case. The orchestrator must explicitly log them as "skipped: no
qualifying artifact" in `iterations.json` so the audit trail shows
the dispatch decision was deterministic, not accidental.

### Plugin scope deliberately not assigned

`windows.filescan.FileScan`, `windows.sessions.Sessions`, and the
`windows.registry.*` family read genuinely useful data from the
memory image, but no analyst in CLAUDE.md's table currently owns them.
This is a recognized gap — see Open Question #1.

## Validation mode for this case

Per CLAUDE.md "Validation modes":

- **`cross_plugin`** is the primary mode. Two or more plugins on the
  same image agreeing — or disagreeing — about the same host artifact.
- **`single_source`** is the fallback when only one plugin can speak
  to a finding (e.g. command line text, since only `windows.cmdline.CmdLine`
  emits it).
- `cross_source` and `cross_artifact` are **structurally unavailable**
  — there is no second artifact class. The orchestrator must reject any
  finding tagged `cross_source HIGH` for this case.

Confidence calibration follows CLAUDE.md "Confidence methodology":

| Tag | Mode | Rule |
|---|---|---|
| HIGH | cross_plugin | ≥ 2 plugins agree, no contradictions, RAG-retrieved MITRE TTP matches |
| MEDIUM | single_source | high-fidelity plugin for the finding type, RAG-corroborated |
| LOW | single_source or resolved-contradiction | low-fidelity source, or contradiction resolved during loop |
| DISPUTED | cross_plugin contradiction | unresolved at termination; both sides + hypothesis chain emitted for human review |

## Validator: cross-plugin contradiction rules

The validator groups DRAFT findings by **host artifact key** before
applying these rules:

- Process: `(PID, ImageFileName)` from `_EPROCESS`
- Connection: `(LocalAddr, LocalPort, ForeignAddr, ForeignPort, Proto)`
- Code region: `(PID, BaseVA, Size)`
- Module: normalized DLL path

### Rule 1 — `pslist` vs `psscan` (DKOM detection)

`windows.pslist.PsList` walks the active `_EPROCESS` doubly-linked
list. `windows.psscan.PsScan` finds `_EPROCESS` structures by
pool-tag scan, including unlinked or recently exited.

| Pattern | Severity | Action |
|---|---|---|
| `(PID, Name)` in `psscan`, NOT in `pslist`, `psscan.ExitTime` is null | **HIGH** — DKOM unlink hypothesis | Re-run dispatch: `windows.thrdscan.ThrdScan` filtered to PID, `windows.handles.Handles --pid <PID>`, `windows.cmdline.CmdLine --pid <PID>` |
| `(PID, Name)` in `psscan`, NOT in `pslist`, `psscan.ExitTime` is set | INFORMATIONAL — process exited normally, scanner found pool remnant | Log only |
| `(PID, Name)` in `pslist`, NOT in `psscan` | INFORMATIONAL — possible scanner miss or very-recent process | Log; flag for the run summary |

### Rule 2 — `malfind` vs `dlllist` / `ldrmodules` (injection corroboration)

`windows.malfind.Malfind` reports VAD regions that are
`PAGE_EXECUTE_READWRITE` and not file-backed. The user-named
corroboration plugin is `windows.dlllist.DllList` (DLLs from the PEB
loader lists). `windows.ldrmodules.LdrModules` is a stronger signal:
it cross-checks the three loader lists (`InLoadOrderModuleList`,
`InMemoryOrderModuleList`, `InInitializationOrderModuleList`) against
each other and against the VAD, flagging unlinks.

| Pattern | Severity | Action |
|---|---|---|
| `malfind` hit at `(PID, BaseVA)` AND `ldrmodules` shows an entry mapped at `BaseVA` is missing from one or more of the three loader lists | **HIGH** — confirmed loader-unlink injection | Re-run: dump the region (Volatility 3 `--dump` for malfind), `windows.handles.Handles --pid <PID>`, RAG-search for matching technique |
| `malfind` hit at `(PID, BaseVA)` AND no `dlllist` entry covers `BaseVA` AND `ImageFileName` is NOT in the JIT-host allowlist (`chrome.exe`, `msedge.exe`, `firefox.exe`, `java.exe`, `javaw.exe`, `dotnet.exe`, `powershell.exe`, `w3wp.exe`, plus image-derived additions per Open Question #2) | **HIGH** — strong injection signal in non-JIT process | Re-run: dump region, `windows.thrdscan.ThrdScan` for the PID to find any thread with start-address inside the region |
| `malfind` hit in a JIT-host process AND no `ldrmodules` discrepancy | INFORMATIONAL — single_source LOW (legitimate JIT is the dominant cause) | Log only |
| `dlllist` shows DLL loaded from a path outside `C:\Windows`, `C:\Program Files*`, AND not present in any `windows.modules.Modules` / `windows.modscan.ModScan` for kernel-level cross-check | INFORMATIONAL — user-mode unsigned-path DLL, suspicious but not necessarily injection | Promote to MEDIUM if RAG matches a known DLL-search-order or sideloading TTP |

### Rule 3 — `netscan` owner PID vs `pslist` / `psscan` (orphaned connections)

`windows.netscan.NetScan` reports each `_TCPE` / `_UDPE`'s owning PID.

| Pattern | Severity | Action |
|---|---|---|
| Connection in `netscan`, state `ESTABLISHED` or `LISTENING`, owner PID not in `pslist` AND not in `psscan` | **HIGH** — live socket owned by a hidden process | Re-run: `windows.psscan.PsScan` (verbose), `windows.thrdscan.ThrdScan` for the PID, hex-dump the `_TCPE` to confirm it's not a stale pool match |
| Connection state `ESTABLISHED`, owner PID in `psscan` but not `pslist` | **HIGH** (cross-references Rule 1 — same DKOM hypothesis) | Same re-run as Rule 1 |
| Connection state `CLOSED` / `TIME_WAIT` / `CLOSE_WAIT`, owner PID not in either list | INFORMATIONAL — typical teardown remnant | Log only |
| `netscan` and `netstat` disagree on whether a connection exists | INFORMATIONAL — `netscan` is signature-scan (broader), `netstat` is partition-walk (current) | Log; treat `netscan` as authoritative for the case file |

### Rule 4 — `pstree` parent anomalies

`windows.pstree.PsTree` is built from `pslist` output via `ParentPid`.

| Pattern | Severity | Action |
|---|---|---|
| Child process with `CreateTime` later than its `ParentPid`-resolved parent's `ExitTime` (where the parent appears in `psscan` with an exit time) | **HIGH** — temporal impossibility, likely PPID spoofing | Re-run: `windows.cmdline.CmdLine --pid <child>` and `--pid <parent>` if parent still resolvable, RAG-search for PPID-spoofing TTPs |
| Child whose `ParentPid` does not resolve to any process in `pslist` OR `psscan` | INFORMATIONAL — orphaned child (parent reaped before capture); common for service-spawn patterns | Log only; promote to MEDIUM if child is itself anomalous (e.g. a shell binary) |
| Spawn-pair anomaly: child `ImageFileName` is in the high-risk-shell set (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`) AND parent `ImageFileName` is in the unusual-parent set (Office binaries, browsers, `lsass.exe`, `services.exe` outside its known service whitelist) | **HIGH** — known living-off-the-land spawn pattern | Re-run: `windows.cmdline.CmdLine` for both, RAG-search for the specific spawn pair |
| Reasonable parent-child tree with no temporal or spawn-pair anomalies | INFORMATIONAL | Log only |

## Memory baseline characteristics

Live measurements from the registered Rocba memory image
(`evidence_id 6770da81-…`) anchored against the tier-1 / tier-2
architecture (week 5). The validator uses these as the reference
shape for the case; deviation from these counts at re-run time is
itself a signal.

- `vol_pslist` extraction: 2186 records, 75 unique image names,
  PPID set of 33, PID range [4, 30328], all with non-null
  `CreateTime`, 1980 with non-null `ExitTime`. Top-10 image-name
  fan-out is dominated by Teams.exe (1901 records — see Open
  Question #4 below).
- `vol_psscan` extraction: 2212 records, 78 unique image names,
  2001 with non-null `ExitTime`. Wall time on the SIFT VM: ~10 min.
- `vol_pstree` extraction: 58 top-level roots, max depth 8,
  largest subtree rooted at PID 8908 (1730 descendants — Teams.exe
  again), 55 orphan roots (PPID not in active list).
- `psscan` vs `pslist` set difference (`set_difference` tool,
  `key="pid"`):
  - **11 PIDs in `psscan`, not in `pslist`.**
    - 1 still active (PID 7900, `svchost.exe`, 2 pool aliases) —
      DKOM candidate, validator priority.
    - 10 exited, `ExitTime` within capture window (2020-11-13 to
      2020-11-16) — normal lifecycle, INFORMATIONAL per Rule 1.
  - **1 PID in `pslist`, not in `psscan`** — likely linked-list
    churn between the two scan phases (psscan's wall time is ~10 min;
    a process that arrived after the psscan walk completed but
    before pslist ran will appear in pslist only). INFORMATIONAL
    per Rule 1.
  - Intersection: 2185 PIDs.
  - Pool-tag aliasing across the whole psscan extraction:
    `a_duplicate_key_count = 16` (16 records whose PID has been
    seen earlier in the extraction). Of those, 15 are intersection
    PIDs (same EPROCESS rediscovered across pool boundaries —
    benign), 1 is the PID 7900 alias above.
  - The simple record-count delta (`|psscan| − |pslist| = 26`) is
    NOT a set-difference metric; it conflates entity-set
    differences with pool-tag aliasing. Surfaced as
    `a_record_count` / `b_record_count` for audit-style sanity
    checks; the entity-anomaly signal is `a_only_count = 11`. See
    `decisions-log.md` 2026-05-06.

These numbers are baseline shape, not ground truth. The validator's
job is to determine which of the 11 a_only PIDs and the 16
duplicate-keyed records are real anomalies vs. expected pool-scan
artifacts of a long-running Windows session.

## Severity → re-run dispatch (summary)

The orchestrator turns each **HIGH** verdict into a targeted re-run.
Re-runs are issued to the analyst that owns the most relevant plugin —
the same dispatch routing as Triage, just with narrower scope (a PID
filter, a memory range, a single connection tuple).

| Triggering rule | Re-run plugins (in order) | Owning analyst |
|---|---|---|
| Rule 1 HIGH (DKOM) | `windows.thrdscan.ThrdScan --pid`, `windows.handles.Handles --pid`, `windows.cmdline.CmdLine --pid` | process_analyst |
| Rule 2 HIGH (injection) | `windows.malfind.Malfind --dump --pid`, `windows.thrdscan.ThrdScan --pid`, `windows.handles.Handles --pid` | injection_analyst → process_analyst for `handles` |
| Rule 3 HIGH (orphan socket) | `windows.psscan.PsScan` (verbose), `windows.thrdscan.ThrdScan --pid` | process_analyst |
| Rule 4 HIGH (pstree anomaly) | `windows.cmdline.CmdLine --pid` for both parent and child | process_analyst |

INFORMATIONAL contradictions are logged in `correlations.json` and
counted in the iteration summary, but **do not** trigger a re-run.
This keeps the loop's termination condition meaningful — "two
iterations with identical contradiction sets" must be measured against
unresolved HIGH cases only, not against noise.

## Loop termination interaction

Per CLAUDE.md "Self-correction loop", the loop terminates on the first
of: (a) zero unresolved HIGH contradictions, (b) two iterations with
identical HIGH contradiction sets, (c) 200K-token global cap.
INFORMATIONAL contradictions are out of scope for (a) and (b) by
design.

## Open questions for the team

1. **Plugin-scope gap.** `windows.filescan.FileScan`,
   `windows.sessions.Sessions`, and the `windows.registry.*` family
   are not owned by any analyst in CLAUDE.md's dispatch table, but
   they read directly from the memory image and would materially
   improve coverage on memory-only cases. Two viable resolutions:
   add a fifth `memory_artifacts_analyst` for these plugins, or
   extend the existing analysts (filescan → process_analyst, registry
   → registry_analyst even on memory-only). Decision needed before
   Week 3 tool-wrapper work begins.

2. **JIT-host allowlist.** Rule 2 (injection corroboration) currently
   uses a static allowlist of known JIT-emitting processes
   (`chrome.exe`, `firefox.exe`, etc.). On any given image, processes
   unique to that environment may also legitimately produce
   `malfind` hits (game launchers, niche dev tools, custom
   instrumented apps). Should the allowlist be (a) static and curated,
   (b) augmented at run-time from the image's own
   `cmdline`/`pslist` patterns, or (c) bypassed entirely in favor of
   purely structural signals (`ldrmodules` unlink + thread-start in
   region)? Affects HIGH-vs-INFORMATIONAL precision.

3. **RAG-corroboration matching criterion.** The
   `single_source MEDIUM` confidence rule requires "RAG-corroborated"
   — but what counts? "Process name appears anywhere in MITRE ATT&CK"
   is too loose (it matches almost everything). A tighter rule
   candidate: the RAG hit must contain at least one of the same
   structural facts the finding rests on (PID-name + behavior pair,
   or specific module path, or specific spawn-pair). Needs concrete
   matching criterion before Week 6 validator work.
