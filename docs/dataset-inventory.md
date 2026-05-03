# Dataset Inventory — Rocba Case (Day-1 Brief)

Day-1 reference. Source: `case-data/evidence/ROCBA-BACKGROUND.pptx`
(7 slides + speaker notes). Initial extraction 2026-05-03 via
`python-pptx`; re-verified 2026-05-03 by unzipping the `.pptx` and
parsing slide + notes XML directly with the stdlib (no third-party
dependency). This document is a briefing summary only — it contains
no evidence-derived strings that have crossed the `<evidence>`
boundary.

## Source materials present

| File | Size | Status |
|---|---|---|
| `case-data/evidence/ROCBA-BACKGROUND.pptx` | ~40 MB | read for this doc; `register_evidence` not yet run (MCP server doesn't exist yet) |
| `case-data/evidence/Rocba-Memory.zip` | ~5.6 GB | **NOT YET DECOMPRESSED**. CLAUDE.md references the decompressed `Rocba-Memory.raw` (~19 GB) — the `.zip` is what's actually shipped |

Follow-up actions (not for week 1, but tracked here):
1. Decompress `Rocba-Memory.zip` into `case-data/extractions/` (NOT
   `evidence/`). Keep the zip in `evidence/` for hash provenance.
2. `register_evidence` both the `.zip` and the resulting `.raw` once
   the MCP server's `register_evidence` exists (Week 2).
3. Verify decompressed image is the expected ~19 GB and has the magic
   bytes Volatility 3 expects for a raw memory dump.

## Scenario summary

Fred Rocba is a technical engineer hired by **Stark Research Labs (SRL)**
on **2020-10-24**. He was issued a Microsoft Surface and worked from
home via RDP and SaaS apps (O365, Dropbox, OneDrive, Google Drive,
iCloud). On **2020-11-10 EDT** he and his family left for a planned
vacation to Disney World, Florida. On the **evening of 2020-11-13 EDT**,
intruders broke into his home, forced the front door, and used his SRL
Surface — which had been **left logged in** — to access SRL files.
Fred returned, noticed the forced entry, called police (police report:
nothing physically stolen), then noticed signs of use on the laptop.
SRL was notified and instructed Fred to **leave the laptop powered on**
so the remote IR team could capture live state.

This is therefore a **physical break-in followed by hands-on-keyboard
activity on a pre-authenticated, live Windows session** — not a remote
network intrusion. The memory capture is the live IR snapshot.

The briefing's stated motivation for a physical attack vector (slide 4
notes): SRL recently completed a major security upgrade that reduced
external intrusions, so an adversary opted for direct hands-on access
to an employee's home system instead. Treat this as briefing context,
not as a finding.

Two pieces of baseline framing the validator must know before tagging
anything in the break-in window as suspicious:

- **The corporate Surface was set up with Fred's *personal* MS
  account** (slide 3 notes: "Fred uses his own MS account and installs
  similar applications"). Personal OneDrive and corporate OneDrive may
  therefore be co-resident on the same box. A file appearing under a
  personal cloud-sync root is not automatically attacker exfil — it
  could be Fred's own setup.
- **Vacation photos are expected to be syncing INTO the system during
  the entire break-in window** (slide 6 title + notes: "Pictures
  synced to Fred's home system" while in Florida). Inbound iCloud /
  Google Photos / OneDrive Camera Roll traffic during 2020-11-10 →
  2020-11-14 EDT is baseline, not IOC. Outbound bulk uploads of
  non-photo content are the attacker signal.

## Host / system profile (from briefing — not from the image)

- **OS:** Windows 10, fully patched (per briefing; verify with
  `windows.info.Info`)
- **Form factor:** Microsoft Surface, employer-provisioned by SRL
- **Single-user system**
- **Microsoft account on the device:** Fred's *personal* MS account, not
  a corporate AAD/Entra account (slide 3 notes). Implication: personal
  and corporate cloud-sync clients coexist on the same profile.
- **Time zone:** EST5EDT (US Eastern). All briefing dates are EDT;
  normalize to UTC during analysis and label every timestamp.
- **Hostname:** NOT GIVEN in briefing. Recover via
  `windows.info.Info` and `windows.registry.printkey` against
  `ControlSet001\Control\ComputerName\ComputerName`.
- **Corporate identity:** `frocba@stark-research-labs.com` (O365 Exchange)
- **Personal identities co-resident on the box:**
  - `fred.rocba@gmail.com`
  - `fred.rocba@outlook.com`
  - Apple ID tied to phone `339-223-3317`
- **Cloud/sync clients installed:** Dropbox (personal), OneDrive,
  Google Drive, iCloud, locally-installed O365
- **Browsers installed:** Microsoft Edge, Mozilla Firefox, Google Chrome
- **Comms / productivity:** Outlook (managing gmail + outlook.com),
  Zoom, O365

These identifiers are Fred's own — they are baseline activity, NOT
IOCs. When fed to an analyst LLM they should be wrapped in
`<evidence source="briefing" untrusted="false">…</evidence>` so the
analyst can reference them, but the baseline-vs-attacker distinction is
the validator's job.

## Key dates (briefing) — all EDT

| Date (EDT) | Event |
|---|---|
| 2020-10-24 | Job interview, offer accepted, Surface shipped |
| 2020-10-26 → 2020-11-10 | Fred working from home, normal activity |
| 2020-11-10 (morning) | Fred + family fly to Florida, **vacation begins** |
| **2020-11-13 (evening)** | **Break-in. Attacker uses live Surface session.** |
| ~2020-11-14+ | Fred returns, calls police, IR engaged, memory captured |

The 2020-11-10 → 2020-11-14 EDT window is the **forensic window of
interest**. Any interactive user activity inside this window — and
especially on the evening of 2020-11-13 EDT — is a candidate for
attacker activity. Cloud-sync clients running in the background are
expected; user-driven foreground actions are not.

## Suspected attack chain

The briefing does not name a TTP chain. The following is the working
hypothesis derived from the attacker model (physical, on-keyboard, on a
pre-authenticated session). Each item is an item to **test**, not a
claim:

1. **Initial access — physical, T1078 Valid Accounts (existing logged-in
   session).** No exploit needed. (T1200 Hardware Additions if a USB
   was inserted — testable.)
2. **Discovery — T1083 / T1217 / T1518.** File system browse for
   SRL-marked content; checking Desktop, Documents, Downloads, OneDrive
   / Dropbox / Google Drive sync roots; recent-files lists.
3. **Collection — T1005 / T1074.001 / T1213.** Copy of SRL R&D files
   into a staging location or directly to an exfil channel.
4. **Exfiltration** — three viable channels, all testable:
   - **T1052.001** — copy to attached USB / removable media
   - **T1567** — upload to attacker-controlled webmail or cloud storage
     via the running browsers
   - **T1567.002** — push into Fred's *personal* Dropbox / Google Drive
     / iCloud already authenticated on the box (most stealthy)
5. **Anti-forensics (possible).** Closing browser tabs, clearing
   recents, ejecting media. Timeline gaps in the break-in window are
   themselves evidence.

The briefing does NOT describe persistence or malware. Treat
"attacker dropped malware / persistence" as a hypothesis to confirm or
refute via `windows.malfind.Malfind` / `windows.modules.Modules` vs
`windows.modscan.ModScan`, not as an assumption.

## Ground-truth artifacts to look for

Memory-only case. Volatility 3 plugin names below — verify each on the
SIFT VM during the smoke test before invoking from code:

**Active sessions / logon state**
- `windows.sessions.Sessions`
- `windows.registry.userassist` (cached registry in memory)

**Process state during the break-in window**
- `windows.pslist.PsList`
- `windows.psscan.PsScan` (catches DKOM-hidden / exited)
- `windows.pstree.PsTree`
- `windows.cmdline.CmdLine`
- `windows.handles.Handles --object-types File`

**File access traces**
- `windows.filescan.FileScan` — cached `_FILE_OBJECT`s, especially
  under `\Users\<fred>\…`, Desktop / Documents / Downloads, and the
  sync roots for OneDrive / Dropbox / Google Drive / iCloud
- `windows.handles.Handles` filtered to File for processes alive at
  capture

**USB / removable-media traces**
- `windows.registry.printkey` against `SYSTEM\CurrentControlSet\Enum\USBSTOR`
- `windows.registry.printkey` against `MountedDevices`
- `windows.devicetree.DeviceTree` for currently-attached devices

**Network state at capture**
- `windows.netscan.NetScan`
- `windows.netstat.NetStat`
- Cross-reference connections back to processes; flag any non-sync-client
  outbound

**Browser / webmail / cloud-upload activity**
- Process check for `chrome.exe`, `firefox.exe`, `msedge.exe` alive at
  capture
- String search across browser working sets for: `mail.google.com`,
  `outlook.live.com`, `dropbox.com`, `drive.google.com`,
  `icloud.com`, plus any unusual domains
- Memory-resident URL fragments via Volatility's string/yarascan support
  (verify exact plugin invocation on SIFT)

**Injection / unusual code regions**
- `windows.malfind.Malfind`
- `windows.dlllist.DllList`
- `windows.ldrmodules.LdrModules`
- `windows.modules.Modules` vs `windows.modscan.ModScan`

**Recent-document / shell-history equivalents (registry-in-memory)**
- `NTUSER.DAT` keys: `RecentDocs`, `TypedPaths`,
  `ComDlg32\OpenSavePidlMRU`, `RunMRU`, `UserAssist`

**Clipboard / console history**
- Clipboard contents — hands-on-keyboard adversaries copy-paste
  (verify exact Volatility 3 plugin name on SIFT; do not invoke from
  memory)
- PowerShell `ConsoleHost_history.txt` strings if any PowerShell
  process was alive

## Indicators of compromise present in the briefing

The briefing is a **scenario narrative, not an IOC list**. It contains:

- **No IP addresses**
- **No hashes**
- **No malware names**
- **No specific filenames** said to have been stolen
- **No domain names** other than `stark-research-labs.com` (Fred's
  legitimate employer)

The only attacker-related indicator the briefing provides is **temporal**:

> Suspect window: **evening of 2020-11-13 EDT**, while Fred was in
> Florida. Broader window of interest: **2020-11-10 → 2020-11-14 EDT**.

This temporal IOC is the foothold the validator should use for every
correlation: "did this artifact occur inside the suspect window?"

## SRL project-domain priors (slide 4 notes)

These are briefing-level hints about what kinds of files the attacker
would have been after, and therefore what naming patterns the
`process_analyst` and string-sweep passes should weight when scanning
RecentDocs, `filescan`, browser history, and clipboard / console
history. The briefing does NOT name specific projects; these are
*domains* SRL works in:

- Biotech
- Metals research
- Advanced alloy generation
- Soldier / battlefield protection
- Heavy-space-lift rockets
- Advanced weapons

Use these as a keyword expansion seed for the search of file paths,
filenames, browser tabs, and pasted/typed strings (e.g. `alloy`,
`biotech`, `rocket`, `weapon`, plus stemmed/abbreviated variants). Hits
are *candidates* for "Fred had access to project X" — they need
artifact corroboration (a `_FILE_OBJECT` cached in memory, a recent-doc
entry, an open handle) before being promoted out of DRAFT.

Treat the SRL legitimate domain `stark-research-labs.com` (slide 4
notes) as the only briefing-supplied benign domain. Anything else is
unattested by the briefing.

## Investigative success criteria (slide 7 — the rubric)

The final report must answer these five questions. Track them as the
top-level structure of `findings.json` and grade against them in
`accuracy-report.md`.

1. What key projects did Fred Rocba have access to?
2. What was stolen?
3. Where was it transferred to?
4. How was it stolen?
5. When did the activity occur?

## Open questions to resolve during the smoke test

| # | Question | Resolves via |
|---|---|---|
| 1 | Exact hostname / NETBIOS name | `windows.info.Info`; `windows.registry.printkey -k 'ControlSet001\Control\ComputerName\ComputerName'` |
| 2 | Local user accounts and last-login times | SAM-hive parse; `windows.registry.userassist` |
| 3 | Memory capture timestamp (vs. 2020-11-13 break-in) | `windows.info.Info` `SystemTime` field |
| 4 | System time zone (confirm EST5EDT from the image, not the briefing) | `windows.registry.printkey -k '…\TimeZoneInformation'` |
| 5 | Was the system idle, screensaver-locked, or active at capture? | `pstree`, screensaver / lock-screen processes, recent-input timestamps |
| 6 | Any cloud-sync activity in the break-in window? | `netscan` + sync-client process strings |

## Validation mode for this case

Memory-only → CLAUDE.md's `cross_source` mode is **not available**. The
validator runs in:

- **`cross_plugin`** — disagreements between Volatility 3 plugins on
  the same image (e.g. process in `psscan` but not `pslist` →
  potential DKOM hiding hypothesis)
- **`single_source`** — finding rests on one plugin, no validation
  available; confidence capped at MEDIUM unless RAG-corroborated

Active analysts for Rocba (per CLAUDE.md dispatch table):
`process_analyst`, `network_analyst`, `injection_analyst`,
`validator`. Disk / registry / eventlog analysts stay dormant.
