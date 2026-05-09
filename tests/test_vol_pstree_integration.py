"""End-to-end integration test for vol_pstree against the live SIFT VM.

Marked ``@pytest.mark.integration``. Excluded by default per
pyproject.toml's ``addopts = ["-m", "not integration"]``. Opt in with
``pytest -m integration``.

⚠ WARNING — this test MODIFIES the on-disk audit chain. Same
justification as `test_vol_pslist_integration.py` /
`test_vol_psscan_integration.py`: the audit line is genuine evidence
that the system ran end-to-end, and belongs in the chain.

⚠ COST — pstree against Rocba is ~30s observed (much faster than
psscan's 6m36s; comparable to pslist's ~5s but on the slow side
because the runner does the recursive children walk in addition to
the active-list traversal).

Pre-flight requirements (skips cleanly if any are missing):
  - SIFT VM reachable via VirtualBox host:2222 → guest:22
  - Volatility 3 at SIFT_VM_VOL_BIN
  - Rocba registered in case-data/CASE.yaml
  - SSH key auth (no password prompt)
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ON_DISK_CASE_YAML = PROJECT_ROOT / "case-data" / "CASE.yaml"
ON_DISK_AUDIT_LOG = PROJECT_ROOT / "case-data" / "audit" / "sift-guard-mcp.jsonl"


@pytest.mark.integration
def test_vol_pstree_against_live_rocba(monkeypatch):
    """Real SSH, real Volatility 3, real Rocba memory image, real chain."""
    from server.runners import sift_vm
    from server.schemas import AuditLogEntry, ProcessTreeRecord, PstreeResult
    from server.tools.memory import vol_pstree

    # ---- Step 1: detect the real WSL2 default gateway. ----
    try:
        real_host = sift_vm._detect_default_gateway()
    except RuntimeError as exc:
        pytest.skip(f"SIFT_VM_HOST not detectable: {exc}")
    monkeypatch.setattr(sift_vm, "SIFT_VM_HOST", real_host)

    # ---- Step 2: SSH+vol smoke check. ----
    try:
        sift_vm.get_vol_version()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        pytest.skip(f"SSH/vol unavailable on SIFT VM at {real_host}: {exc}")

    # ---- Step 3: find the registered Rocba entry. ----
    if not ON_DISK_CASE_YAML.exists():
        pytest.skip("case-data/CASE.yaml not present")
    doc = yaml.safe_load(ON_DISK_CASE_YAML.read_text(encoding="utf-8")) or {}
    rocba = next(
        (
            entry
            for entry in doc.get("evidence", [])
            if entry.get("original_filename") == "Rocba-Memory.raw"
            and entry.get("artifact_class") == "memory_image"
        ),
        None,
    )
    if rocba is None:
        pytest.skip("Rocba not registered yet (run register_evidence first)")
    rocba_evidence_id = rocba["evidence_id"]

    # ---- Step 4: snapshot the audit log. ----
    if ON_DISK_AUDIT_LOG.exists():
        before_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    else:
        before_lines = []
    before_count = len(before_lines)
    expected_prev_hash = (
        json.loads(before_lines[-1])["this_line_hash"] if before_lines else "0" * 64
    )

    # ---- Step 5: the real call. ----
    result = vol_pstree(rocba_evidence_id, case_dir=str(PROJECT_ROOT / "case-data"))

    # ---- Step 6: result assertions. ----
    assert isinstance(result, PstreeResult)
    assert result.plugin_name == "windows.pstree.PsTree"
    assert result.evidence_id == rocba_evidence_id

    # Top-level entries: roots, orphans, and System. On Rocba this is
    # 58. Lower bound stays conservative for portability across smaller
    # test images.
    assert len(result.processes) >= 5, (
        f"too few top-level processes: {len(result.processes)} — expected roots/orphans + System"
    )

    # Sanity bound. Rocba observed 29.5s; 120s gives ~4× headroom.
    assert result.runtime_seconds < 120.0, (
        f"runtime {result.runtime_seconds:.1f}s exceeds 120s sanity "
        "bound — pstree should not take this long"
    )

    # PID 4 is always "System" on Windows, and it must be at the top
    # level (PPID 0). If pstree silently nested it under something,
    # the parent-child reconstruction is broken.
    system_top = [p for p in result.processes if p.pid == 4 and p.image_file_name == "System"]
    assert len(system_top) == 1, (
        f"PID 4 (System) must be a top-level node; found {len(system_top)} "
        f"in the top-level list of {len(result.processes)}"
    )

    # Walk the recursive structure. At least one descendant must exist
    # (System has children: smss.exe, MemCompression, Registry on a
    # real Windows host) — this confirms the recursive parse landed.
    def walk(nodes, depth=0):
        for n in nodes:
            yield depth, n
            yield from walk(n.children, depth + 1)

    flat = list(walk(result.processes))
    assert len(flat) > len(result.processes), (
        "no descendants below the top level — recursive parse failed "
        "or pstree returned only orphans (unlikely on a real image)"
    )

    # Every node in the tree must be a typed ProcessTreeRecord, not a
    # raw dict. Catches accidental leakage of unmapped fields.
    assert all(isinstance(n, ProcessTreeRecord) for _, n in flat)

    # Reproducibility metadata captured.
    assert re.match(r"^\d+\.\d+", result.volatility_version), (
        f"volatility_version should look like a dotted version; got {result.volatility_version!r}"
    )

    # ---- Step 7: audit chain assertions. ----
    after_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    assert len(after_lines) == before_count + 1, (
        f"audit log grew by {len(after_lines) - before_count}, expected +1"
    )

    new_entry = json.loads(after_lines[-1])
    assert new_entry["tool_name"] == "vol_pstree", (
        f"new line tool_name should be 'vol_pstree' (no colon suffix); "
        f"got {new_entry['tool_name']!r}"
    )
    assert new_entry["evidence_id"] == rocba_evidence_id
    assert new_entry["line_number"] == before_count + 1
    assert new_entry["prev_line_hash"] == expected_prev_hash, (
        "new audit line failed to link to the prior chain — chain is broken"
    )

    entry_obj = AuditLogEntry.model_validate(new_entry)
    recomputed = AuditLogEntry.compute_this_line_hash(
        line_number=entry_obj.line_number,
        timestamp=entry_obj.timestamp,
        tool_name=entry_obj.tool_name,
        evidence_id=entry_obj.evidence_id,
        input_hash=entry_obj.input_hash,
        output_hash=entry_obj.output_hash,
        prev_line_hash=entry_obj.prev_line_hash,
    )
    assert recomputed == new_entry["this_line_hash"], (
        "stored this_line_hash does not match recomputation"
    )
