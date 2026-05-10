"""End-to-end integration test for vol_psscan against the live SIFT VM.

Marked ``@pytest.mark.integration``. Excluded by default per
pyproject.toml's ``addopts = ["-m", "not integration"]``. Opt in with
``pytest -m integration``.

⚠ WARNING — this test MODIFIES the on-disk audit chain. Running it
appends one real line to ``case-data/audit/sift-guard-mcp.jsonl``.
Same justification as `test_vol_pslist_integration.py`: the audit
line it produces is genuine evidence that the system ran end-to-end,
and belongs in the chain. Suppressing it because "it was a test"
would itself be a tampering pattern.

⚠ COST — psscan against Rocba is ~6m36s observed (vs vol_pslist's
~5s). The integration test sanity bound is 600s; the underlying
runner timeout is bumped to 900s in `vol_psscan`. Plan for a coffee
when running ``pytest -m integration tests/test_vol_psscan_integration.py``.

Pre-flight requirements (skips cleanly if any are missing):

  - The SIFT VM is running and reachable from WSL2 (VirtualBox
    forwards host:2222 → guest:22).
  - Volatility 3 is installed in the VM at ``SIFT_VM_VOL_BIN``.
  - The Rocba memory image is registered in ``case-data/CASE.yaml``.
  - SSH key auth is configured (no password prompt).

Same skip-on-missing-VM behavior as the pslist integration test.
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
def test_vol_psscan_against_live_rocba(monkeypatch):
    """Real SSH, real Volatility 3, real Rocba memory image, real chain.

    Reads the actual ``case-data/CASE.yaml``, finds the Rocba entry,
    invokes ``vol_psscan`` via the real runner (~6m), validates the
    result, and asserts the on-disk audit chain extended by exactly
    one line linked to the prior ``this_line_hash`` and recomputable
    from its other fields.
    """
    # Imports inside the test: this file is collected on every default
    # pytest run (the marker only excludes execution, not collection),
    # and module-level collection should be a stdlib-only no-op.
    from server.runners import ssh_remote as sift_vm
    from server.schemas import AuditLogEntry, PsscanResult
    from server.tools.memory import vol_psscan

    # ---- Step 1: detect the real WSL2 default gateway. ----
    try:
        real_host = sift_vm._detect_default_gateway()
    except RuntimeError as exc:
        pytest.skip(f"SIFT_VM_HOST not detectable: {exc}")

    monkeypatch.setattr(sift_vm, "SIFT_VM_HOST", real_host)

    # ---- Step 2: SSH+vol smoke check via PACKAGE_VERSION probe. ----
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

    # ---- Step 4: snapshot the audit log before the call. ----
    if ON_DISK_AUDIT_LOG.exists():
        before_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    else:
        before_lines = []
    before_count = len(before_lines)
    expected_prev_hash = (
        json.loads(before_lines[-1])["this_line_hash"] if before_lines else "0" * 64
    )

    # ---- Step 5: the real call. SSH → vol3 → 19 GB Rocba image. ----
    # ~6 minutes of pool-tag scanning. The runner's timeout was bumped
    # to 900s by vol_psscan; this test does not need to override it.
    result = vol_psscan(rocba_evidence_id, case_dir=str(PROJECT_ROOT / "case-data"))

    # ---- Step 6: result assertions. ----
    assert isinstance(result, PsscanResult)
    assert result.plugin_name == "windows.psscan.PsScan"
    assert result.evidence_id == rocba_evidence_id

    # psscan returns MORE processes than pslist on a normal Windows
    # host because pool-tag scanning surfaces terminated/exited
    # processes the active EPROCESS list has dropped. Rocba observed:
    # 2212 (vs pslist's 2186, delta +26). Lower bound stays at 50 to
    # stay portable across smaller test images.
    assert len(result.processes) >= 50, (
        f"too few processes: {len(result.processes)} "
        "— Windows usually has 80+, psscan typically more"
    )

    # Sanity bound. Rocba observed 6m36s; 600s leaves ~10% headroom and
    # an over-30-minute run signals a structural problem (transport
    # hang, runaway pool scan) rather than a real workload.
    assert result.runtime_seconds < 600.0, (
        f"runtime {result.runtime_seconds:.1f}s exceeds 600s sanity bound "
        "— psscan should not take this long even on a 19 GB image"
    )

    # PID 4 is always "System" on Windows. psscan finds it via pool tag,
    # so this also smoke-tests that pool-scan is hitting EPROCESS at all.
    pid_4_names = [p.image_file_name for p in result.processes if p.pid == 4]
    assert "System" in pid_4_names, f"PID 4 should be 'System' on Windows; got {pid_4_names!r}"

    # psscan's defining feature relative to pslist: it surfaces
    # terminated processes with a non-null ExitTime. Asserting the set
    # is non-empty confirms we're getting psscan output, not a
    # silently-mis-routed pslist response. Empirically ~90% of psscan
    # rows on Rocba have a populated ExitTime; assertion is the weakest
    # form (>=1) for portability.
    exited = [p for p in result.processes if p.exit_time is not None]
    assert len(exited) >= 1, (
        "psscan returned zero exited processes — either the parser "
        "dropped ExitTime or this isn't actually psscan output"
    )

    # Reproducibility metadata captured.
    assert re.match(r"^\d+\.\d+", result.volatility_version), (
        f"volatility_version should look like a dotted version; got {result.volatility_version!r}"
    )

    # ---- Step 7: audit chain assertions on the live chain. ----
    after_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    assert len(after_lines) == before_count + 1, (
        f"audit log grew by {len(after_lines) - before_count}, expected +1 "
        "(success path: no rejection or warning lines)"
    )

    new_entry = json.loads(after_lines[-1])
    assert new_entry["tool_name"] == "vol_psscan", (
        f"new line tool_name should be 'vol_psscan' (no colon suffix); "
        f"got {new_entry['tool_name']!r}"
    )
    assert new_entry["evidence_id"] == rocba_evidence_id
    assert new_entry["line_number"] == before_count + 1
    assert new_entry["prev_line_hash"] == expected_prev_hash, (
        "new audit line failed to link to the prior chain — chain is broken"
    )

    # this_line_hash must be recomputable from the rest of the entry.
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
        "stored this_line_hash does not match recomputation — "
        "the audit-log writer is producing un-verifiable lines"
    )
