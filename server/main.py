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

from server.schemas import (
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    NetscanResult,
    PslistResult,
    PsscanResult,
    PstreeResult,
)
from server.tools.evidence import register_evidence as _register_evidence_impl
from server.tools.findings import record_finding as _record_finding_impl
from server.tools.memory import (
    vol_netscan as _vol_netscan_impl,
    vol_pslist as _vol_pslist_impl,
    vol_psscan as _vol_psscan_impl,
    vol_pstree as _vol_pstree_impl,
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


@mcp.tool()
def vol_pstree(evidence_id: str) -> PstreeResult:
    """Run windows.pstree.PsTree against a registered memory image.

    Reconstructs the parent-child process hierarchy from each EPROCESS's
    InheritedFromUniqueProcessId. Returns a recursive tree of ProcessTreeRecord
    nodes — top-level entries are roots, orphans (PPID no longer in the active
    list), or System (PID 4 / PPID 0); descendants are nested in each node's
    `children` field. Pstree-specific resolved fields (audit, cmd, path) are
    populated when Volatility can read RTL_USER_PROCESS_PARAMETERS, which on
    Rocba was ~9% of records — most rows have these as null because the
    parameters block was paged out.

    Same evidence_id-only contract as vol_pslist; same sanitized rejection
    messages and audited rejection lines under the `vol_pstree:rejected_*`
    prefix. The week-6 validator uses this tree shape to detect masquerading
    (svchost.exe with non-services.exe parent) and unusual process depth.

    Cost: typically 25-45 seconds per call against a 19GB Windows 10 image
    (Rocba: 29.5s observed). Comparable to vol_pslist's runtime — pstree walks
    the same active EPROCESS list, just with hierarchy reconstruction.
    """
    return _vol_pstree_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_netscan(evidence_id: str) -> NetscanResult:
    """Run windows.netscan.NetScan against a registered memory image.

    Pool-tag scans the network object table for TCP/UDP endpoints across IPv4
    and IPv6. Returns a flat list of connections — one record per endpoint
    with proto, local_addr/port, foreign_addr/port, state, pid, and owner
    image name. UDP records use empty-string state and "*" foreign_addr per
    netstat convention. PID and owner can both be null for kernel-only
    endpoints.

    Same evidence_id-only contract as the other vol_* tools; same sanitized
    rejection messages and audited rejection lines under
    `vol_netscan:rejected_*`.

    Cross-source value: combined with vol_pslist / vol_psscan, the validator
    can flag ports bound by PIDs that don't appear in the active-list walk —
    a DKOM-hiding signature.

    Cost: typically 5-12 minutes per call against a 19GB Windows 10 image
    (Rocba: 8m57s observed). Slower than vol_psscan because netscan pool-scans
    more object families. Do not call back-to-back redundantly.
    """
    return _vol_netscan_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def record_finding(
    evidence_id: str,
    analyst: str,
    category: FindingCategory,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: str,
    description: str,
    evidence_refs: list[EvidenceRef],
    hypothesis: str | None = None,
) -> DraftFinding:
    """Commit a DRAFT finding to the case.

    Analyst subagents call this to record what they found, with back-pointers
    into the audit chain so every claim resolves to the tool calls that fed it.
    The schema's Literal-validated category, severity, and confidence keep the
    finding surface bounded; self-marking DISPUTED is rejected — that state
    is set by the validator, not the analyst.

    Required: a registered evidence_id; an analyst from {process_analyst,
    network_analyst, validator}; at least one EvidenceRef whose audit_line
    points at a real line in case-data/audit/sift-guard-mcp.jsonl AND whose
    source_tool matches that line's tool_name. Server fills finding_id (UUIDv4),
    created_at (UTC now), state ("DRAFT"), and tool_invocations (derived from
    evidence_refs).

    Errors are sanitized — invalid evidence_id, unknown analyst, DISPUTED
    self-mark, mismatched audit refs, and pydantic constraint failures all
    raise ValueError with generic messages while the audit chain captures the
    full rejection context for operator review.
    """
    return _record_finding_impl(
        evidence_id=evidence_id,
        analyst=analyst,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence_refs=evidence_refs,
        hypothesis=hypothesis,
        case_dir=CASE_DIR,
    )


if __name__ == "__main__":
    mcp.run()
