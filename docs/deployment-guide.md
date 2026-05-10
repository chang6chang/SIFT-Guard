# Standalone SIFT-VM deployment guide

> Planning document for the `deploy/standalone-vm` branch. The
> hackathon submission lives on `main` and assumes the WSL2-host →
> SIFT-VM-guest split with port-forwarded SSH. This branch refactors
> SIFT-Guard into a single-host appliance: everything (orchestrator,
> MCP server, Volatility, plaso, RegRipper, mounts, Claude Code CLI)
> runs inside one SIFT VM. No SSH, no path translation, no bind mounts.
>
> No code is changed yet — this document is the design + migration
> checklist.

## Why

The submission architecture optimizes for the hackathon judging
criteria, where the orchestrator naturally lives where the operator
typed `claude` (WSL2) and Volatility lives where the SIFT toolset is
already installed (the SIFT VM). That split adds two things that pay
no rent in a single-machine internal deployment:

1. SSH transport (`server/runners/sift_vm.py`) — `ssh ... vol ...` per
   plugin, plus the WSL2 default-gateway auto-detection trick.
2. Path translation (`server/tools/memory.py:translate_to_vm_path`) —
   `<case_dir>/evidence/X.raw` → `/mnt/rocba/X.raw` because the host
   path and the VM path differ.

For internal use we want operators to clone the repo on a SIFT VM,
`pip install -e .`, set `ANTHROPIC_API_KEY`, and run. The two pieces
above become friction with no benefit.

## 1. Files that reference SSH / remote execution

The SSH surface area is narrow and contained to one runner module
plus its callers. The orchestrator and the agent prompts have no SSH
references — by design, every evidence access goes through MCP tools
keyed by `evidence_id`.

| File | Lines | What it does today | What it changes to |
|---|---|---|---|
| `server/runners/sift_vm.py` | 1–442 (entire module) | Wraps `ssh -p 2222 sansforensics@<host> vol -f <vm_path> -r json <plugin>` for every Volatility 3 plugin invocation. Also `get_vol_version` (probes `volatility3.framework.constants.PACKAGE_VERSION` over SSH) and `_detect_default_gateway` (WSL2 trick to find the host that runs VirtualBox). | Becomes a thin shim that re-exports symbols from the new `local_runner.py`. Keep the module name so existing imports do not break, but the `argv = ["ssh", "-p", ..., "vol", ...]` lists collapse to `argv = ["vol", "-f", path, "-r", "json", plugin]` (no `ssh` prefix, no port, no user@host). |
| `server/tools/memory.py` | 76–77 (imports), 308–310 (`_resolve_and_translate`) | Imports `SIFT_VM_EVIDENCE_PREFIX` and calls `translate_to_vm_path(record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX)` before invoking `run_vol_plugin`. | When runner=local, skip translation entirely: `vm_path = record.absolute_path`. The same path the operator registered is the path Volatility opens. The cache-key, audit chain, and `command_executed` string all shrink accordingly. |
| `README.md` | 284–289 (SIFT VM env vars), 297–298 ("9 min over SSH" perf note) | Documents `SIFT_VM_HOST` / `SIFT_VM_USER` / `SIFT_VM_SSH_PORT` defaults and explains the port-forward setup. | Standalone install replaces this with a "clone the repo inside the SIFT VM, set `ANTHROPIC_API_KEY`, run" three-liner. Reference the hackathon mode for operators reproducing the submission. |

`orchestrator/main.py`, `orchestrator/dispatch.py`, `orchestrator/loop.py`,
`orchestrator/manifest.py`, `orchestrator/inventory.py`, and all four
files under `.claude/agents/` have **zero** SSH / VM / path-translation
references. The architectural guardrail (agents only see `evidence_id`,
the MCP server resolves to a path) means the refactor stops at the
runner and the memory-tool wrapper.

## 2. Files that reference path translation

| File | Lines | Current behavior | New behavior |
|---|---|---|---|
| `server/tools/memory.py` | 190–207 (`translate_to_vm_path`) | `host_path` → `vm_path` substitution with prefix-boundary check. Public symbol re-exported via `__all__`. | When `SIFT_GUARD_RUNNER=local` (the new default), the function becomes the identity function for inputs under `<case_dir>/evidence/`: returns `host_path` unchanged. When runner=ssh, behavior is unchanged. Keep the symbol exported so tests can still pin the SSH-mode behavior. |
| `server/tools/memory.py` | 308–310 (`_resolve_and_translate`) | Computes `host_prefix = case_dir/evidence`, calls `translate_to_vm_path(record.absolute_path, host_prefix, SIFT_VM_EVIDENCE_PREFIX)`. | In runner=local, returns `record.absolute_path` directly. In runner=ssh, unchanged. |
| `server/runners/sift_vm.py` | 35 (`SIFT_VM_EVIDENCE_PREFIX` default `/mnt/rocba`), 178–180 (prefix check inside `run_vol_plugin`) | Validates `image_path_in_vm` lives under the VM-side prefix. | Local runner has no equivalent prefix to enforce — the evidence path is already an absolute path under `<case_dir>/evidence/` and `register_evidence` enforces that boundary. Drop the prefix check in local mode; keep it in SSH mode for backwards compat. |
| `server/schemas.py` | ~103 (docstring example) | Example `absolute_path` value `/mnt/rocba/Rocba-Memory.raw`. | Update example to a host-relative path like `/home/sansforensics/cases/rocba/evidence/Rocba-Memory.raw`. Cosmetic; no runtime effect. |

## 3. Target architecture

- **Everything in one SIFT VM.** The operator clones the repo inside
  the VM and runs `pip install -e ".[rag,dev]"`. Orchestrator, MCP
  server, Claude Code CLI, Volatility 3, plaso, RegRipper, python-evtx,
  and pf2json all share a single filesystem and a single process tree.
- **No SSH.** `server/runners/sift_vm.py` is repurposed as a thin
  re-export shim over the new local runner; no new SSH dependencies.
- **No path translation.** `<case_dir>/evidence/X.raw` is the path
  Volatility opens. `register_evidence`'s read-only enforcement
  (`chmod 444` / parent `chmod 555`) still applies.
- **No bind mounts for evidence.** Disk images are still mounted via
  `ewfmount` / `mount -o ro,loop` / `guestmount --ro` from
  `disk_mount.py`, but those calls already run as local subprocesses
  in the existing code — nothing changes there for the deployment
  refactor.
- **Evidence directory is configurable.** Default `<case_dir>/evidence/`
  (matches today). Override via `SIFT_GUARD_EVIDENCE_DIR` env var or
  `--evidence-dir` CLI flag.
- **Output directory is configurable.** Default `./case-data/`
  (matches today). Override via `--output-dir`.
- **Volatility / plaso / RegRipper called via direct subprocess.** No
  `shell=True`. The `/proc/mounts` read-only validation in
  `disk_mount.py` stays — it's even simpler in the local case because
  the mount is on the same kernel that the validator reads.
- **Claude Code + MCP server via stdio.** Unchanged — the orchestrator
  spawns `claude -p --agent <name>` and the MCP server runs as a
  stdio child of `claude`. Both live in the SIFT VM.
- **Single external dependency: `ANTHROPIC_API_KEY`.** Anthropic API
  access for Claude Code's analyst / validator subagent dispatch.
  Nothing else needs network at runtime. RAG is local FAISS.

## 4. New runner: `server/runners/local_runner.py`

Replace `sift_vm.py`'s SSH transport with a local subprocess runner.
Same public surface so memory-tool callers do not change.

```python
# server/runners/local_runner.py
"""Local Volatility 3 runner. No SSH; everything in-VM."""

import os
import re
import shlex
import subprocess
import time

VOL_BIN = os.environ.get("SIFT_GUARD_VOL_BIN", "vol")
VOL_PYTHON = os.environ.get("SIFT_GUARD_VOL_PYTHON", "/opt/volatility3/bin/python3")

# Same plugin-name regex as sift_vm.py — defense-in-depth.
_PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[A-Z][A-Za-z0-9]*$")

_VERSION_PROBE_SCRIPT = (
    "from volatility3.framework import constants; print(constants.PACKAGE_VERSION)"
)


def get_vol_version(timeout_seconds: int = 10) -> str:
    result = subprocess.run(
        [VOL_PYTHON, "-c", _VERSION_PROBE_SCRIPT],
        capture_output=True, text=True, timeout=timeout_seconds, check=True,
    )
    return result.stdout.strip()


def run_vol_plugin(
    plugin_name: str,
    image_path: str,
    timeout_seconds: int = 300,
) -> tuple[str, str, float]:
    """Run a Volatility 3 plugin against a local image. Same return
    shape as sift_vm.run_vol_plugin: (stdout, command_string, runtime).
    """
    if not _PLUGIN_NAME_RE.match(plugin_name):
        raise ValueError("plugin_name failed validation")
    # No prefix check — the caller (memory.py wrapper) has already
    # resolved the path through CASE.yaml and verified it lives under
    # <case_dir>/evidence/.

    argv = [VOL_BIN, "-f", image_path, "-r", "json", plugin_name]
    start = time.monotonic()
    result = subprocess.run(
        argv, capture_output=True, text=True,
        timeout=timeout_seconds, check=True,
    )
    elapsed = time.monotonic() - start
    return result.stdout, shlex.join(argv), elapsed
```

The four parsers (`parse_volatility_json`, `parse_pstree_json`,
`parse_netscan_json`, `parse_cmdline_json`, `parse_malfind_json`) move
into `local_runner.py` unchanged — they parse Volatility's JSON output
which is identical regardless of transport.

`sift_vm.py` becomes:

```python
# Backwards compat. SSH-mode runner kept for the hackathon submission
# path; local_runner is the default for internal deployments.
from server.runners.local_runner import (
    get_vol_version as _local_get_vol_version,
    run_vol_plugin as _local_run_vol_plugin,
    parse_volatility_json,
    parse_pstree_json,
    parse_netscan_json,
    parse_cmdline_json,
    parse_malfind_json,
)
# ... existing SSH-specific bodies remain available behind the
# SIFT_GUARD_RUNNER=ssh env-var toggle ...
```

The same read-only mount validation (`/proc/mounts` check) in
`disk_mount.py` is unchanged — it already runs locally.

## 5. Installation on the SIFT VM

1. **Clone the repo on the SIFT VM** (not the host).
   ```bash
   git clone https://github.com/chang6chang/SIFT-Guard.git
   cd SIFT-Guard
   git checkout deploy/standalone-vm
   ```
2. **Install Python 3.11+ if SIFT ships older.** SIFT 2026.1 ships
   Python 3.10 as the system interpreter. SIFT-Guard requires 3.11+.
   ```bash
   pyenv install 3.11.9
   pyenv local 3.11.9
   # or: uv venv --python 3.11
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```
3. **`pip install -e ".[rag,dev]"`.** Pulls `mcp`, `pydantic`,
   `pyyaml`, plus `sentence-transformers` + `faiss-cpu` for the RAG
   index and `pytest` + `ruff` for development.
4. **Verify forensic tools are on PATH.**
   ```bash
   which vol log2timeline.py rip.pl evtx_dump.py pf2json
   ```
   On a clean SIFT 2026.1, `vol` is at `/usr/local/bin/vol` (symlink
   into `/opt/volatility3/bin/vol`); `log2timeline.py` and `rip.pl`
   are in `/usr/local/bin`. `evtx_dump.py` ships with the
   `python-evtx` pip package; `pf2json` ships with `python-prefetch`.
   Override per-tool with `SIFT_GUARD_VOL_BIN`,
   `SIFT_DISK_LOG2TIMELINE_BIN`, `SIFT_DISK_REGRIPPER_BIN`,
   `SIFT_DISK_PREFETCH_CMD`, `SIFT_DISK_EVTX_DUMP_CMD` if your install
   diverges.
5. **Set the API key.**
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```
6. **(Optional) Build the RAG index.** Skips re-download on subsequent
   runs (idempotent at pinned tags).
   ```bash
   python -m rag.build_index
   ```
   Or copy a pre-built `rag/data/attack-enterprise.{faiss,records.json,meta.json}`
   tree from another VM.
7. **Smoke test.**
   ```bash
   sift-guard analyze --help
   ```
   The wrapper script (see §6) prints subcommand help; if Python /
   PATH / API-key setup is wrong this is where it surfaces.

## 6. Simplified CLI wrapper: `bin/sift-guard`

A thin shell script that wraps `python -m orchestrator.main` with
sane defaults and one detection rule (single-file vs directory).

```bash
#!/usr/bin/env bash
# bin/sift-guard
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${SIFT_GUARD_PYTHON:-${REPO_ROOT}/.venv/bin/python}"

cmd="${1:-help}"; shift || true

case "$cmd" in
  analyze)
    target="${1:?usage: sift-guard analyze <path> [--output-dir DIR]}"; shift
    output_dir=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --output-dir) output_dir="$2"; shift 2 ;;
        *) extra+=("$1"); shift ;;
      esac
    done
    case_dir="${output_dir:-./case-data}"

    if [[ -d "$target" ]]; then
      "$PYTHON" -m orchestrator.main run-case \
        --case-dir "$case_dir" --evidence-dir "$target" "${extra[@]:-}"
    elif [[ -f "$target" ]]; then
      eid=$("$PYTHON" -c "
from server.tools.evidence import register_evidence
print(register_evidence('$target', case_dir='$case_dir').evidence_id)
")
      "$PYTHON" -m orchestrator.main run \
        --case-dir "$case_dir" --evidence-id "$eid" "${extra[@]:-}"
    else
      echo "error: $target is neither a file nor a directory" >&2; exit 2
    fi ;;
  verify)
    case_dir="${1:?usage: sift-guard verify <case-dir>}"
    "$PYTHON" -m server.audit_verify --case-dir "$case_dir" ;;
  report)
    case_dir="${1:?usage: sift-guard report <case-dir>}"
    "$PYTHON" -m orchestrator.report --case-dir "$case_dir" ;;
  help|--help|-h|"")
    cat <<EOF
usage: sift-guard <subcommand> [options]
  analyze <path> [--output-dir DIR]   detect single file vs directory
  verify <case-dir>                   run hash chain verification
  report <case-dir>                   generate human-readable summary
EOF
    ;;
  *) echo "unknown subcommand: $cmd" >&2; exit 2 ;;
esac
```

Two new entrypoints to wire up:

- `server.audit_verify` — small CLI module that walks
  `case-data/audit/sift-guard-mcp.jsonl` (and the three other
  hash-chained logs), recomputes `prev_line_hash` / `this_line_hash`,
  and prints OK/FAIL plus the first divergent line number. The
  hash-chain algorithm already lives in `server/audit.py`; this
  module is a thin verifier loop.
- `orchestrator.report` — see §7 (deferred).

## 7. Summary report generator (future scope)

After a run completes, generate a markdown report from the four
hash-chained logs.

Sections:

1. **Executive summary** — host count, finding count, confirmed /
   disputed / draft breakdown, termination reason, total iterations,
   wall-clock, uncached-token total.
2. **Per-host findings** — one table per host, sorted by confidence
   (HIGH → MEDIUM → LOW → DISPUTED), columns: `finding_id` (8 chars),
   `category`, `confidence`, `state`, `description` (first 80 chars),
   `mitre_techniques`.
3. **Cross-host correlations** — for `correlation_type=cross_host`,
   list the involved `host_ids`, the `shared_indicator`, the
   `correlation_strength`, and which findings on each host are tied.
4. **Iteration timeline** — one row per iteration: dispatched analysts,
   new findings, new correlations, promotions made, termination
   flags fired, tokens spent.
5. **Audit chain verification** — output of the verifier from §6:
   "OK" plus chain length, or "FAIL at line N" with diff.

Inputs: `case-data/findings.jsonl` (last-write-wins per
`finding_id`), `case-data/correlations.jsonl`,
`case-data/iterations.jsonl`, `case-data/audit/sift-guard-mcp.jsonl`.
Output: `case-data/report.md` plus a print-to-stdout convenience for
piping.

Estimate: 4–6h. Not on the critical path for the runner refactor;
slot after the migration is stable.

## 8. What stays the same

- **MCP server architecture** — 19 typed pydantic tools, hash-chained
  JSONL logs, evidence-id-only addressing, `<evidence>` delimiter
  wrapping for untrusted strings. None of this changes.
- **Subagent triad** — `process_analyst`, `network_analyst`,
  `disk_analyst`, `validator`. The `.claude/agents/*.md` files do not
  reference SSH / paths / the VM, so they need zero edits.
- **Orchestrator loop** — 5 steps (ANALYZE → CORRELATE → PROMOTE →
  PLAN → WRITE), R1–R6 promotion rules, R_a / R_b / R_c termination
  flags, sequential analyst dispatch. Unchanged.
- **RAG index + `rag_query` tool** — local FAISS at
  `rag/data/attack-enterprise.faiss`. Already self-contained;
  nothing to change.
- **Evidence integrity enforcement** — SHA-256 at registration,
  `chmod 444` on the file plus `chmod 555` on the parent, `/proc/mounts`
  read-only validation for disk mounts, mount-cache invalidation on
  external `umount`, end-of-run re-hash. All unchanged.
- **Tests** — 477 unit tests stay. The runner mocks change shape
  (`subprocess.run` against a local argv vector instead of
  `["ssh", ..., "vol", ...]`), but the test contract per tool is
  preserved.

## 9. Migration checklist

| # | Task | Estimate |
|---|---|---|
| 1 | Create `server/runners/local_runner.py` (subprocess `vol`, identical parser exports). | ~2h |
| 2 | Add `SIFT_GUARD_RUNNER=local|ssh` env-var toggle. Default `local`. `sift_vm.py` re-exports from `local_runner` when the toggle is `local`; keeps the SSH path when `ssh`. | ~1h |
| 3 | Refactor `server/tools/memory.py` so `_resolve_and_translate` skips path translation when runner=local. Tests cover both branches. | ~2h |
| 4 | Refactor `server/runners/disk_mount.py` — only docstring + privilege-model section needs updating; no SSH was ever in this file. Confirm `SIFT_DISK_PREMOUNTED_PATH` env var still works as a CI escape hatch. | ~2h |
| 5 | Create `bin/sift-guard` wrapper script + new `server/audit_verify` CLI module for the `verify` subcommand. | ~1h |
| 6 | Update tests: `tests/test_*` mocks of `run_vol_plugin` switch from SSH-argv assertions to local-argv assertions. Add a test pinning `runner=local` skips `translate_to_vm_path`. | ~3h |
| 7 | Write summary report generator (`orchestrator/report.py`). | ~4–6h |
| 8 | Update `README.md` — add a "Standalone SIFT VM" section above the existing hackathon section. The hackathon path stays as a documented mode for reproducing the submission. | ~2h |
| **Total** | | **~15–20h** |

Order matters: 1–4 land first as a coherent runner refactor (PR 1).
5–6 are tooling and test coverage (PR 2). 7–8 are deferred and can
ship independently.

## 10. What to drop for internal use

These are submission-facing artifacts that exist to score against the
hackathon rubric. None of them affect the runtime behavior of the
analyzer.

- **Devpost-specific deliverables** — `docs/demo-script.md`,
  `docs/devpost-description.md`, `docs/execution-logs/*` (kept on
  `main`, not deleted; just not referenced from the standalone
  install instructions).
- **Synthetic adversarial demo seeding** — `scripts/seed_synthetic_demo.py`
  and the synthetic-image quick-start in `README.md`. Internal users
  analyze real evidence; the synthetic image is a screencast prop.
  Keep the file in the tree (it's small) but drop it from the
  standalone README.
- **Hackathon judging criteria references in prompts** — none of the
  agent files (`.claude/agents/*.md`) actually reference the rubric
  by name; nothing to change there. CLAUDE.md does, but CLAUDE.md is
  developer-facing and stays as-is.
- **Protocol SIFT comparison mentions** — `docs/protocol-sift/` and
  any "vs Protocol SIFT" framing. Keep the directory on `main`; do
  not reference from standalone docs.

These items remain on `main`. The internal deployment branch simply
doesn't surface them in the install path or README.
