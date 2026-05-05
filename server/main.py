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

from server.schemas import EvidenceRecord
from server.tools.evidence import register_evidence as _register_evidence_impl


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


if __name__ == "__main__":
    mcp.run()
