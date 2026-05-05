"""SIFT-Guard MCP server — stdio entrypoint.

Exposes typed, evidence-safe forensic tools to Claude Code over the
Model Context Protocol. Single-process; binds to stdio by default.

Per CLAUDE.md "Ground truth isolation" rule 3, MCP tools never accept
arbitrary case paths. `CASE_DIR` is a module-level constant resolved
by the server, not a parameter the agent can set — the agent can only
name evidence by `evidence_id` registered through `register_evidence`.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from server.schemas import EvidenceRecord, PslistResult, PsscanResult
from server.tools.evidence import register_evidence as _register_evidence_impl
from server.tools.memory import (
    vol_pslist as _vol_pslist_impl,
    vol_psscan as _vol_psscan_impl,
)


# Fixed at server startup. The agent does NOT control where the case
# directory lives. See CLAUDE.md rule 3.
CASE_DIR = "case-data"


mcp = FastMCP("sift-guard")


@mcp.tool()
def register_evidence(filepath: str) -> EvidenceRecord:
    """Register an evidence file with SIFT-Guard.

    Computes SHA-256, detects artifact class, sets the file to read-only (chmod 444),
    records the entry in case-data/CASE.yaml, and writes a hash-chained audit line.

    IRREVERSIBLE: this sets the source file to read-only. The agent cannot un-register
    evidence. Returns the registered EvidenceRecord with evidence_id, hash, and metadata.
    """
    return _register_evidence_impl(filepath, case_dir=CASE_DIR)


@mcp.tool()
def vol_pslist(evidence_id: str) -> PslistResult:
    """Run windows.pslist.PsList against a registered memory image.

    Resolves evidence_id via case-data/CASE.yaml. Validates the evidence is a
    memory image. Invokes Volatility 3 in the SIFT VM via SSH. Returns the full
    process list with provenance metadata (Volatility version, command executed,
    runtime seconds).

    Errors are sanitized: invalid evidence_id, wrong artifact_class, or path
    translation failures all raise ValueError with generic messages, while the
    on-disk audit chain captures the original evidence_id for operator review.

    Cost: typically 5-15 seconds per call against a 19GB Windows 10 image.
    """
    return _vol_pslist_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_psscan(evidence_id: str) -> PsscanResult:
    """Run windows.psscan.PsScan against a registered memory image.

    Pool-tag scans memory directly for _EPROCESS allocations rather than walking
    the active linked list. Surfaces processes vol_pslist cannot see by
    construction: terminated processes whose EPROCESS still lingers in the pool,
    DKOM-hidden processes (unlinked from the active list while the pool tag
    persists), and processes the kernel marked exited but not yet reaped. The
    set difference between psscan and pslist is the cross-plugin contradiction
    the validator surfaces.

    Same evidence_id-only contract as vol_pslist; same sanitized rejection
    messages and audited rejection lines under the `vol_psscan:rejected_*`
    prefix.

    Cost: typically 5-10 minutes per call against a 19GB Windows 10 image
    (Rocba: 6m36s observed). About 30-50x slower than vol_pslist — pool-tag
    scanning walks the full memory layer. Do not call back-to-back redundantly.
    """
    return _vol_psscan_impl(evidence_id, case_dir=CASE_DIR)


if __name__ == "__main__":
    mcp.run()
