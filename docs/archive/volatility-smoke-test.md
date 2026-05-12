# Volatility 3 smoke test — Rocba memory image

Day-1 action #2 from CLAUDE.md. Verifies that Volatility 3 reads
`Rocba-Memory.raw` end-to-end and produces a usable kernel profile.

## Result

**PASS.** Volatility 3 framework loaded the image, completed page-map
stacking and PDB scanning to 100%, identified the kernel as Windows 10
build 19041 (x64), and emitted `windows.info.Info` cleanly in 1.662 s
wall (symbols were already cached locally — no download stall).

## Provenance

| Field | Value |
|---|---|
| Date executed (UTC) | 2026-05-03T23:55:17Z |
| Plugin runtime | real 0m1.662s, user 0m1.014s, sys 0m0.560s |
| Operator | galvarino (this repo's working directory), via SSH from WSL2 host into the SIFT VM |
| Volatility 3 framework version | 2.27.0 (`from volatility3.framework import constants; constants.PACKAGE_VERSION`) |
| Volatility 3 venv interpreter | `/opt/volatility3/bin/python3` (CPython 3.12), wrapper at `/usr/local/bin/vol` |
| SIFT VM kernel | `Linux siftworkstation 6.8.0-110-generic #110-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 15:09:20 UTC 2026 x86_64` |
| Image path on VM | `/mnt/rocba/Rocba-Memory.raw` |
| Image size | 19,050,528,768 bytes (19.05 GB) |
| Image SHA-256 | `eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563` |
| Hash compute time | real 2m24.349s on the VM (vboxsf-mounted) |

The operator-restated hash carried a single-character first-pair
transposition (`be…` instead of `eb…`); confirmed as a typo, not a
file divergence. The value above is the one computed against the file
on disk and is authoritative for this run.

## Mount caveat (architectural follow-up, not a failure)

`mount | grep -i rocba` returned:

```
Rocba-Memory on /mnt/rocba type vboxsf (rw,nodev,relatime,iocharset=utf8,uid=0,gid=980,dmode=0770,fmode=0770,tag=VBoxAutomounter)
```

Two issues for the Week-2 `register_evidence` work:

1. The mount is `rw`, not `ro`. CLAUDE.md "Architectural enforcement
   of evidence integrity" requires `-o ro` mounts and a
   `/proc/mounts` check before every read.
2. `vboxsf` does not honor POSIX `chmod 444` from the guest — file
   modes are controlled by the host share's `dmode`/`fmode`. The
   `chmod 444 / 555` requirement cannot be satisfied on this share
   layout. Either share the image read-only from the VirtualBox host
   side, or stage a copy onto the VM's native filesystem and register
   that.

This does not invalidate the smoke test (the plugin only reads), but
it must be resolved before the MCP server reads from this path in
production.

## Exact command

Run from the WSL2 working directory of this repo:

```
ssh -p 2222 sansforensics@$(ip route show | grep -i default | awk '{print $3}') \
  'time vol -f /mnt/rocba/Rocba-Memory.raw windows.info.Info'
```

The default-gateway resolution (`172.28.48.1` at the time of this
run) targets the Windows host that bridges to the VirtualBox VM via a
forwarded port on 2222. Hash was computed in a separate SSH
invocation: `time sha256sum /mnt/rocba/Rocba-Memory.raw`.

## Full output (verbatim)

```
smoke-test start: 2026-05-03T23:55:17Z
Progress:    0.00		Updating caches for 1 files...
Progress:    0.00		Scanning FileLayer using PageMapScanner
Progress:   23.33		Scanning FileLayer using PageMapScanner
Progress:  100.00		Stacking attempts finished
Progress:    0.00		Scanning layer_name using PdbSignatureScanner
Progress:    0.00		Scanning layer_name using PdbSignatureScanner
Progress:  100.00		PDB scanning finished
Volatility 3 Framework 2.27.0

Variable	Value

Kernel Base	0xf8025d600000
DTB	0x1ad000
Symbols	file:///opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/15B12C74F0E177581B6B27DD4C5022C2-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf8025e20f340
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	4
SystemTime	2020-11-16 02:32:38+00:00
NtSystemRoot	C:\WINDOWS
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Sun Aug 27 22:21:11 2023

real	0m1.662s
user	0m1.014s
sys	0m0.560s
```

## Facts established (from this output, no inference)

- Kernel build: Win10 `Major/Minor 15.19041` → Windows 10 version 2004
  (a.k.a. 20H1).
- 64-bit kernel (`Is64Bit True`), no PAE, AMD64 (`MachineType 34404`,
  `0x8664`).
- 4 processors (`KeNumberProcessors 4`).
- Product type: `NtProductWinNt` — workstation, **not** Server. This
  refines CLAUDE.md's prior "Win10 OR Server 2016+" hypothesis to
  Win10 confirmed.
- System root: `C:\WINDOWS` (default).
- Kernel symbol PDB GUID: `15B12C74F0E177581B6B27DD4C5022C2-1`,
  resolved against a locally-cached `ntkrnlmp.pdb` json.xz under
  `/opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows/`.
  No external symbol fetch was required.
- **Image-internal capture time (`SystemTime`):
  `2020-11-16 02:32:38+00:00` UTC.**
- `PE TimeDateStamp` of the kernel image is 2023-08-27. This is the
  PE-header timestamp, which Microsoft has long since stopped using
  as a meaningful build date for Windows kernels (reproducible-build
  hashing). It is not a contradiction with the 2020-era capture.

## Interpretation: capture timestamp vs. incident window

The image's `SystemTime` of **2020-11-16 02:32:38 UTC** corresponds to
**2020-11-15 21:32:38 US Eastern (EST = UTC−5; daylight saving ended
2020-11-01)**. Per `docs/dataset-inventory.md`, the break-in occurred
during the evening of **2020-11-13 (US Eastern)**, with the broader
window of interest **2020-11-10 → 2020-11-14**. The memory was
therefore captured **approximately 48 hours after the break-in** and
roughly one to two days after Fred's earliest possible return home —
consistent with the briefing's narrative that he returned, called
police, notified SRL, and was instructed to leave the laptop powered
on so the remote IR team could capture live state. Practical
implication for the analyst plan in `docs/dispatch-plan-rocba.md`:
process state at capture (`windows.pslist.PsList`) reflects the
post-incident system, so attacker-window activity will be recovered
primarily through `windows.psscan.PsScan` (pool-resident exited
processes), cached `_FILE_OBJECT`s via `windows.filescan.FileScan`,
network artifacts in `windows.netscan.NetScan`, and string / yara
sweeps over working sets and pagefile-backed regions — not from the
foreground process list alone.

## Open items (none blocking, all tracked)

1. Read-only mount + `chmod` enforcement on the vboxsf share
   (architectural, Week 2). See "Mount caveat" above.
2. `register_evidence` will need to record both the SHA-256 above
   and the file size, and re-hash at run end per CLAUDE.md "Audit
   log integrity".
3. `dispatch-plan-rocba.md` (Day-1 action #3) remains to be written;
   it depends on the artifact-class detector, which can use this
   smoke test's confirmed `memory_image` class.
