"""End-to-end integration test for vol_pslist against the live SIFT VM.

Marked ``@pytest.mark.integration``. Excluded by default per
pyproject.toml's ``addopts = ["-m", "not integration"]``. Opt in with
``pytest -m integration``.

⚠ WARNING — this test MODIFIES the on-disk audit chain. Running it
appends one real line to ``case-data/audit/sift-guard-mcp.jsonl``.
Unlike the unit tests in ``test_vol_pslist.py``, it does NOT use a
``tmp_path``-isolated chain. Justification: this is the proof-of-life
check that the real stack — SSH transport, Volatility 3, parser,
schema, audit writer — works end-to-end against real evidence. The
audit line it produces is genuine evidence that the system ran, and
belongs in the chain. The audit log is supposed to record what
really happened; suppressing the line because "it was a test" would
itself be a tampering pattern.

Pre-flight requirements (skips cleanly if any are missing):

  - The SIFT VM is running and reachable from WSL2 (VirtualBox
    forwards host:2222 → guest:22).
  - Volatility 3 is installed in the VM at ``SIFT_VM_VOL_BIN``.
  - The Rocba memory image is registered in ``case-data/CASE.yaml``.
  - SSH key auth is configured (no password prompt).

It is safe to include this test in ``pytest -m integration`` runs on
machines without the VM — the skip path covers every prerequisite.
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
def test_vol_pslist_against_live_rocba(monkeypatch):
    """Real SSH, real Volatility 3, real Rocba memory image, real chain.

    Reads the actual ``case-data/CASE.yaml``, finds the Rocba entry by
    ``original_filename == "Rocba-Memory.raw"`` AND
    ``artifact_class == "memory_image"``, invokes ``vol_pslist`` via
    the real runner, validates the result, and asserts the on-disk
    audit chain extended by exactly one line linked to the prior
    ``this_line_hash`` and recomputable from its other fields.
    """
    # Imports inside the test: this file is collected on every default
    # pytest run (the marker only excludes execution, not collection),
    # and we want module-level collection to be a stdlib-only no-op.
    from server.runners import sift_vm
    from server.schemas import AuditLogEntry, PslistResult
    from server.tools.memory import vol_pslist

    # ---- Step 1: detect the real WSL2 default gateway. ----
    # conftest.py pinned SIFT_VM_HOST to the sentinel "test.invalid" so
    # module-load detection wouldn't shell out during unit-test
    # collection. For this integration test we want the actual gateway.
    try:
        real_host = sift_vm._detect_default_gateway()
    except RuntimeError as exc:
        pytest.skip(f"SIFT_VM_HOST not detectable: {exc}")

    # Patch the module constant so run_vol_plugin / get_vol_version
    # build SSH argv against the real host. monkeypatch reverts on
    # teardown so a later test (in a re-run) still sees the sentinel.
    monkeypatch.setattr(sift_vm, "SIFT_VM_HOST", real_host)

    # ---- Step 2: SSH+vol smoke check via `vol --version`. ----
    # Cheaper than a full plugin call (~0.5 s) and gives a precise
    # skip reason if SSH key auth, port forward, or vol install is the
    # problem rather than the plugin itself.
    try:
        sift_vm.get_vol_version()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            OSError) as exc:
        pytest.skip(f"SSH/vol unavailable on SIFT VM at {real_host}: {exc}")

    # ---- Step 3: find the registered Rocba entry. ----
    if not ON_DISK_CASE_YAML.exists():
        pytest.skip("case-data/CASE.yaml not present")
    doc = yaml.safe_load(ON_DISK_CASE_YAML.read_text(encoding="utf-8")) or {}
    rocba = next(
        (
            entry for entry in doc.get("evidence", [])
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
        before_lines = ON_DISK_AUDIT_LOG.read_text(
            encoding="utf-8"
        ).splitlines()
    else:
        before_lines = []
    before_count = len(before_lines)
    expected_prev_hash = (
        json.loads(before_lines[-1])["this_line_hash"]
        if before_lines else "0" * 64
    )

    # ---- Step 5: the real call. SSH → vol3 → 19 GB Rocba image. ----
    result = vol_pslist(
        rocba_evidence_id, case_dir=str(PROJECT_ROOT / "case-data")
    )

    # ---- Step 6: result assertions. ----
    assert isinstance(result, PslistResult)
    assert result.plugin_name == "windows.pslist.PsList"
    assert result.evidence_id == rocba_evidence_id

    # Windows 10/11 typically runs 80–200 processes. Fewer than 50
    # signals a structural failure (parser, SSH truncation, incomplete
    # plugin run) — not a real "small" image.
    assert len(result.processes) >= 50, (
        f"too few processes: {len(result.processes)} "
        "— Windows usually has 80+"
    )

    # Sanity bound; the user's earlier hand-run measured ~4.9 s.
    assert result.runtime_seconds < 30.0, (
        f"runtime {result.runtime_seconds:.1f}s exceeds 30 s sanity bound"
    )

    # PID 4 is always "System" on Windows. If the parser dropped the
    # field or mis-mapped the key, this catches it.
    pid_4_names = [p.image_file_name for p in result.processes if p.pid == 4]
    assert "System" in pid_4_names, (
        f"PID 4 should be 'System' on Windows; got {pid_4_names!r}"
    )

    # Reproducibility metadata captured. Vol3's bare PACKAGE_VERSION
    # is a dotted version string ("2.27.0" on the SIFT 2026.1 build);
    # we assert version-shape rather than a specific prefix to stay
    # forward-compatible with future Volatility releases.
    assert re.match(r"^\d+\.\d+", result.volatility_version), (
        f"volatility_version should look like a dotted version; "
        f"got {result.volatility_version!r}"
    )

    # ---- Step 7: audit chain assertions on the live chain. ----
    after_lines = ON_DISK_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    assert len(after_lines) == before_count + 1, (
        f"audit log grew by {len(after_lines) - before_count}, expected +1 "
        "(success path: no rejection or warning lines)"
    )

    new_entry = json.loads(after_lines[-1])
    assert new_entry["tool_name"] == "vol_pslist", (
        f"new line tool_name should be 'vol_pslist' (no colon suffix); "
        f"got {new_entry['tool_name']!r}"
    )
    assert new_entry["evidence_id"] == rocba_evidence_id
    assert new_entry["line_number"] == before_count + 1
    assert new_entry["prev_line_hash"] == expected_prev_hash, (
        "new audit line failed to link to the prior chain — chain is broken"
    )

    # this_line_hash must be recomputable from the rest of the entry —
    # this is the tamper-evident-chain property at the line level.
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
