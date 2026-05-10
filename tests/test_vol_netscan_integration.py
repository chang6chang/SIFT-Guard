"""End-to-end integration test for vol_netscan against the live SIFT VM.

Marked ``@pytest.mark.integration``. Excluded by default per
pyproject.toml's ``addopts = ["-m", "not integration"]``. Opt in with
``pytest -m integration``.

⚠ WARNING — this test MODIFIES the on-disk audit chain. Same
justification as the other vol_* integration tests: the audit line
is genuine evidence the system ran end-to-end.

⚠ COST — netscan against Rocba is ~9 minutes observed (slower than
psscan's 6m36s; pool-scans more network object families). The runner
timeout is bumped to 1200s in vol_netscan; this test's sanity bound
is 720s with a small headroom buffer.

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
def test_vol_netscan_against_live_rocba(monkeypatch):
    """Real SSH, real Volatility 3, real Rocba memory image, real chain."""
    from server.runners import ssh_remote as sift_vm
    from server.schemas import AuditLogEntry, NetscanResult, NetworkRecord
    from server.tools.memory import vol_netscan

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

    # ---- Step 5: the real call. ~9 minutes. ----
    result = vol_netscan(rocba_evidence_id, case_dir=str(PROJECT_ROOT / "case-data"))

    # ---- Step 6: result assertions. ----
    assert isinstance(result, NetscanResult)
    assert result.plugin_name == "windows.netscan.NetScan"
    assert result.evidence_id == rocba_evidence_id

    # Rocba observed 430 connections. Lower bound stays conservative
    # (~50) for portability.
    assert len(result.connections) >= 50, (
        f"too few connections: {len(result.connections)} "
        "— expected dozens of TCP/UDP endpoints on a normal Windows host"
    )

    # Sanity bound. Rocba observed 8m57s (~537s); 720s gives ~33%
    # headroom over that.
    assert result.runtime_seconds < 720.0, (
        f"runtime {result.runtime_seconds:.1f}s exceeds 720s sanity bound"
    )

    # All four protocol families should be present on a normal Windows
    # host. Asserting at least 3 distinct families to leave a sliver of
    # room for tightly-firewalled images that genuinely have only TCPv4.
    protos = {c.proto for c in result.connections}
    assert len(protos) >= 3, f"expected ≥3 distinct protocol families; got {sorted(protos)}"
    # TCPv4 must always be present — Windows always has at least one
    # listener (RPC, SMB, or similar).
    assert "TCPv4" in protos, "TCPv4 must be present on any Windows host"

    # At least one TCP record should be in LISTENING state — Windows
    # always has services bound. If this fails the parser dropped State
    # or netscan produced empty output.
    listening_tcp = [
        c for c in result.connections if c.proto.startswith("TCP") and c.state == "LISTENING"
    ]
    assert listening_tcp, (
        "no TCP LISTENING records — either State field was dropped "
        "by the parser or netscan returned only ESTABLISHED"
    )

    # Reproducibility metadata.
    assert re.match(r"^\d+\.\d+", result.volatility_version), (
        f"volatility_version should look like a dotted version; got {result.volatility_version!r}"
    )

    # Every record is a typed NetworkRecord.
    assert all(isinstance(c, NetworkRecord) for c in result.connections)

    # ---- Step 7: audit chain assertions. ----
    after_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    assert len(after_lines) == before_count + 1, (
        f"audit log grew by {len(after_lines) - before_count}, expected +1"
    )

    new_entry = json.loads(after_lines[-1])
    assert new_entry["tool_name"] == "vol_netscan", (
        f"new line tool_name should be 'vol_netscan' (no colon suffix); "
        f"got {new_entry['tool_name']!r}"
    )
    assert new_entry["evidence_id"] == rocba_evidence_id
    assert new_entry["line_number"] == before_count + 1
    assert new_entry["prev_line_hash"] == expected_prev_hash, (
        "new audit line failed to link to the prior chain"
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
