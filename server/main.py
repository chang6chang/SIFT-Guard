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

from server.schemas import EvidenceRecord, PslistResult
from server.tools.evidence import register_evidence as _register_evidence_impl
from server.tools.memory import vol_pslist as _vol_pslist_impl


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


if __name__ == "__main__":
    mcp.run()
