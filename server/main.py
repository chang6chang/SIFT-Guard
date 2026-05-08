"""SIFT-Guard MCP server — stdio entrypoint.

Exposes typed, evidence-safe forensic tools to Claude Code over the
Model Context Protocol. Single-process; binds to stdio by default.

Per CLAUDE.md "Ground truth isolation" rule 3, MCP tools never accept
arbitrary case paths. `CASE_DIR` is a module-level constant resolved
by the server, not a parameter the agent can set — the agent can only
name evidence by `evidence_id` registered through `register_evidence`.

Tool surface as of week 8 (19 tools):
  Tier-0  register_evidence (read-only catalog)
  Tier-1  vol_pslist, vol_psscan, vol_pstree, vol_netscan,
          vol_cmdline, vol_malfind  (memory)
          disk_mft_timeline, disk_prefetch, disk_evtx, disk_registry
          — invoke Volatility / SIFT disk parsers, persist full
            output to extractions/, return a small Summary
  Tier-2  query_records, group_by, set_difference, subtree
          — read stored extractions, compose narrowed answers
  Writes  record_finding       (analyst → DRAFT entry on findings.jsonl)
          record_correlation   (validator → entry on correlations.jsonl)
          update_finding       (orchestrator → UPDATE entry on findings.jsonl)
  RAG     rag_query            (validator-only at the agent surface;
                                 queries the ATT&CK enterprise corpus
                                 by technique_id or semantic_query)
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from typing import Any, Literal

from server.schemas import (
    CmdLineSummary,
    ContradictionSeverity,
    ContradictsCorrelation,
    CorrelationStrength,
    CorroboratesCorrelation,
    CrossHostCorrelation,
    DraftFinding,
    EvidenceRecord,
    EvidenceRef,
    EvtxSummary,
    FieldFilter,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FindingUpdate,
    FollowupTargetAnalyst,
    GroupByResult,
    MalfindSummary,
    MftTimelineSummary,
    NetscanSummary,
    PluginName,
    PrefetchSummary,
    PromotionRule,
    PslistSummary,
    PsscanSummary,
    PstreeSummary,
    QueryRecordsResult,
    RagQueryResult,
    RegistrySummary,
    RequestFollowupCorrelation,
    SetDifferenceResult,
    StrengthensCorrelation,
    SubtreeResult,
    WeakensCorrelation,
)
from server.tools.analytical import (
    group_by as _group_by_impl,
    query_records as _query_records_impl,
    set_difference as _set_difference_impl,
    subtree as _subtree_impl,
)
from server.tools.correlations import (
    record_correlation as _record_correlation_impl,
)
from server.tools.evidence import register_evidence as _register_evidence_impl
from server.tools.findings import (
    record_finding as _record_finding_impl,
    update_finding as _update_finding_impl,
)
from server.tools.disk import (
    disk_evtx as _disk_evtx_impl,
    disk_mft_timeline as _disk_mft_timeline_impl,
    disk_prefetch as _disk_prefetch_impl,
    disk_registry as _disk_registry_impl,
)
from server.tools.memory import (
    vol_cmdline as _vol_cmdline_impl,
    vol_malfind as _vol_malfind_impl,
    vol_netscan as _vol_netscan_impl,
    vol_pslist as _vol_pslist_impl,
    vol_psscan as _vol_psscan_impl,
    vol_pstree as _vol_pstree_impl,
)
from server.tools.rag import rag_query as _rag_query_impl


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
def vol_pslist(evidence_id: str) -> PslistSummary:
    """Run windows.pslist.PsList against a registered memory image.

    Tier-1 tool. Resolves evidence_id via case-data/CASE.yaml. Validates
    the evidence is a memory image. On first call: invokes Volatility 3
    in the SIFT VM via SSH, persists the full PslistResult to
    case-data/extractions/<evidence_id>/windows.pslist.PsList.json,
    appends one line to case-data/extractions.jsonl, and returns a
    PslistSummary (≤10 KB) carrying an ExtractionRef plus distribution
    signal (unique image names, top-10 image-name counts, distinct
    PPIDs, etc.). On re-invocation against the same evidence_id: serves
    the recomputed summary from disk without re-running Volatility,
    audited as `vol_pslist:cached` with `cached=True` and
    `runtime_seconds=null`.

    Errors are sanitized: invalid evidence_id, wrong artifact_class, or
    path translation failures all raise ValueError with generic
    messages, while the audit chain captures the original evidence_id
    for operator review. Cache-integrity failures (stored bytes do not
    match the chain's recorded sha256 or the .sha256 sidecar) raise
    ValueError and audit `vol_pslist:hash_mismatch`.

    Cost: typically 5-15 seconds per first call against a 19 GB Windows
    10 image. Cache hits are essentially instant.
    """
    return _vol_pslist_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_psscan(evidence_id: str) -> PsscanSummary:
    """Run windows.psscan.PsScan against a registered memory image.

    Tier-1 tool. Pool-tag scans memory directly for _EPROCESS allocations
    rather than walking the active linked list. Surfaces processes
    vol_pslist cannot see by construction: terminated processes whose
    EPROCESS still lingers in the pool, DKOM-hidden processes (unlinked
    from the active list while the pool tag persists), and processes
    the kernel marked exited but not yet reaped. The cross-plugin diff
    is what `set_difference` exposes for the validator.

    Same cache contract as vol_pslist: persists to
    case-data/extractions/<evidence_id>/windows.psscan.PsScan.json on
    first call; serves recomputed PsscanSummary from disk on
    re-invocation; same sanitized rejection messages and audited
    rejection lines under the `vol_psscan:rejected_*` /
    `vol_psscan:hash_mismatch` / `vol_psscan:cached` prefixes.

    Cost: typically 5-10 minutes per first call against a 19 GB Windows
    10 image (Rocba: 6m36s observed). About 30-50x slower than
    vol_pslist — pool-tag scanning walks the full memory layer. Do not
    call back-to-back redundantly. Cache hits are instant.
    """
    return _vol_psscan_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_pstree(evidence_id: str) -> PstreeSummary:
    """Run windows.pstree.PsTree against a registered memory image.

    Tier-1 tool. Reconstructs the parent-child process hierarchy from
    each EPROCESS's InheritedFromUniqueProcessId. Returns a
    PstreeSummary (≤10 KB) with shape signal — top-level root count,
    max depth, depth distribution, largest subtree by descendant
    count, orphan count. The recursive tree itself lives in the stored
    extraction; tier-2's `subtree` tool reads it.

    Same cache contract as vol_pslist. Per-record validation is
    coarser here: pydantic validates whole subtrees when constructing
    a top-level ProcessTreeRecord, so a malformed descendant skips its
    entire top-level subtree (one
    `vol_pstree:record_validation_warning` line per skipped subtree).

    Cost: typically 25-45 seconds per first call against a 19 GB
    Windows 10 image (Rocba: 29.5s observed). Cache hits are instant.
    """
    return _vol_pstree_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_netscan(evidence_id: str) -> NetscanSummary:
    """Run windows.netscan.NetScan against a registered memory image.

    Tier-1 tool. Pool-tag scans the network object table for TCP/UDP
    endpoints across IPv4 and IPv6. Returns a NetscanSummary (≤10 KB)
    with protocol distribution, TCP-state distribution, listening /
    established / null-owner counts, and distinct foreign-address
    count. The full NetscanResult (every endpoint row) lives in the
    stored extraction; specific endpoints come from
    `query_records(plugin_name="windows.netscan.NetScan", ...)`.

    Same cache contract as vol_pslist. UDP records use empty-string
    state and "*" foreign_addr per netstat convention; the validator
    treats `state == ""` as "no TCP-style state, this is a UDP
    endpoint". `pid` and `owner` may both be null for kernel-only
    endpoints — same recovery semantic as psscan's exited rows.

    Cost: typically 5-12 minutes per first call against a 19 GB
    Windows 10 image (Rocba: 8m57s observed). Slower than vol_psscan
    because netscan pool-scans more object families. Do not call
    back-to-back redundantly. Cache hits are instant.
    """
    return _vol_netscan_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_cmdline(evidence_id: str) -> CmdLineSummary:
    """Run windows.cmdline.CmdLine against a registered memory image.

    Tier-1 tool. Reads the user-space command line for each process
    out of `_RTL_USER_PROCESS_PARAMETERS.CommandLine`. Returns a
    CmdLineSummary (≤10 KB) with `null_cmdline_count` /
    `with_cmdline_count` (the gap signal — pslist alone reports
    image names but not arguments; this tool tells you how much of
    the parameters block actually paged in), `distinct_cmdlines`,
    `top_process_names` (top 10 process names by record count), and
    `pid_range`. The full CmdLineResult lives in the stored
    extraction at
    `case-data/extractions/<evidence_id>/windows.cmdline.CmdLine.json`;
    specific command lines come from
    `query_records(plugin_name="windows.cmdline.CmdLine", ...)`.

    Same cache contract and sanitized rejection paths as vol_pslist:
    `vol_cmdline:rejected_*`, `vol_cmdline:cached`,
    `vol_cmdline:hash_mismatch`, `vol_cmdline:record_validation_warning`.

    Cost: typically 25-60 seconds per first call against a 19 GB
    Windows 10 image; cmdline reads the same paged structures as
    pstree's `cmd` projection. Cache hits are instant.
    """
    return _vol_cmdline_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def vol_malfind(evidence_id: str) -> MalfindSummary:
    """Run windows.malfind.Malfind against a registered memory image.

    Tier-1 tool. Walks each process's VAD tree and flags regions
    whose page protection includes both write and execute (typically
    PAGE_EXECUTE_READWRITE) AND whose contents look like code rather
    than zero-fill. Returns a MalfindSummary (≤10 KB) with
    `unique_process_names`, `detections_by_process` (top 10 process
    names by detection count), `protection_distribution` (the
    load-bearing field — non-zero `PAGE_EXECUTE_READWRITE` count is
    the classic shellcode marker), `vad_tag_distribution`, and
    `pid_range`. The full MalfindResult lives in the stored
    extraction; specific PIDs / hex dumps / disassembly come from
    `query_records(plugin_name="windows.malfind.Malfind", ...)`.

    Result-list field is named `detections` not `processes` — a
    single PID can produce multiple rows (one per suspicious VAD
    region). Same cache contract and sanitized rejection paths as
    vol_pslist: `vol_malfind:rejected_*`, `vol_malfind:cached`,
    `vol_malfind:hash_mismatch`,
    `vol_malfind:record_validation_warning`.

    Cost: bounded by the number of injected regions, not the total
    process count. Typically completes in seconds-to-minutes against
    a 19 GB Windows 10 image. Cache hits are instant.
    """
    return _vol_malfind_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def disk_mft_timeline(evidence_id: str) -> MftTimelineSummary:
    """Run plaso's MFT-only timeline against a registered disk image.

    Tier-1 tool. Two-step plaso pipeline (`log2timeline.py
    --parsers mft` writes a .plaso storage file; `psort.py -o
    json_line` converts to JSON-line records). Returns a
    `MftTimelineSummary` (≤10 KB) with `entry_type_distribution`
    (created / modified / accessed / mft_modified counts),
    `earliest_timestamp` / `latest_timestamp` bracketing the timeline,
    `top_paths` (top 10 paths by entry count), and `distinct_paths`.
    The full MftTimelineResult lives in the stored extraction at
    `case-data/extractions/<evidence_id>/disk.mft.MftTimeline.json`;
    specific timeline rows come from
    `query_records(plugin_name="disk.mft.MftTimeline", ...)`.

    Mount: invoked through the disk-mount utility, which honors
    `SIFT_DISK_PREMOUNTED_PATH` for dev environments where root is
    not available. Same cache contract and sanitized rejection
    paths as `vol_pslist`:
    `disk_mft_timeline:rejected_*`, `disk_mft_timeline:cached`,
    `disk_mft_timeline:hash_mismatch`,
    `disk_mft_timeline:record_validation_warning`,
    `disk_mft_timeline:rejected_mount_failed`.

    Cost: variable — plaso's MFT parser is the cheapest plaso
    pipeline, but still scales with $MFT entry count. Tens of
    seconds to several minutes depending on disk size. Cache hits
    are instant.
    """
    return _disk_mft_timeline_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def disk_prefetch(evidence_id: str) -> PrefetchSummary:
    """Parse `Windows/Prefetch/*.pf` on a registered disk image.

    Tier-1 tool. Each .pf file describes one executable's launch
    history (Windows tracks up to 8 last-run timestamps per
    executable in modern formats). Returns a `PrefetchSummary`
    (≤10 KB) with `distinct_executables`, `total_run_count`,
    `top_executables` (top 10 by run count), and earliest/latest
    run-time bracketing. Specific prefetch entries (run counts,
    last-run-time lists, referenced files) come from
    `query_records(plugin_name="disk.prefetch.Prefetch", ...)`.

    Cross-validation: prefetch proves execution. A binary present
    in pslist + prefetch run_count > 0 + recent last_run_time is
    high-confidence "ran on this host"; binary present in pslist
    only is weaker (could be a recent injected/never-launched
    process).

    Same cache contract and sanitized rejection paths as
    `disk_mft_timeline`. Cache hits are instant.
    """
    return _disk_prefetch_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def disk_evtx(evidence_id: str) -> EvtxSummary:
    """Parse Security and System EVTX logs on a registered disk image.

    Tier-1 tool. Reads `Windows/System32/winevt/Logs/Security.evtx`
    and `System.evtx` via the python-evtx parser; merges into one
    extraction with each record carrying its source `channel`.
    Returns an `EvtxSummary` (≤10 KB) with `event_id_distribution`
    (top 10 EventIDs by count), `channel_distribution`, distinct
    event-id count, and timestamp range. Specific events
    (timestamps, sources, message summaries, logon types) come
    from `query_records(plugin_name="disk.evtx.EventLog", ...)`.

    Cross-validation: Event 4624/4625 (logon success/fail) +
    netscan RDP connections from memory grounds an RDP brute-force
    finding. Event 7045 (service install) + a service in the
    registry's Services key + a running process by that name
    grounds a persistence finding.

    `message_summary` is treated as untrusted evidence content —
    truncated to 500 characters in the parser. Same cache contract
    and sanitized rejection paths as `disk_mft_timeline`.
    """
    return _disk_evtx_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def disk_registry(evidence_id: str) -> RegistrySummary:
    """Run RegRipper across SYSTEM / SOFTWARE / SAM / NTUSER.DAT
    on a registered disk image.

    Tier-1 tool. Enumerates the four canonical hives plus per-user
    NTUSER.DAT files under `Users/*/`; merges into one extraction
    with each record carrying its source `hive_name`. Returns a
    `RegistrySummary` (≤10 KB) with `hive_distribution`,
    `interesting_paths_distribution` (per-key-path-prefix bucket
    over Run / RunOnce / Services / Policies / other), distinct
    key count, and a top-N list of key paths. Specific values
    come from
    `query_records(plugin_name="disk.registry.Registry", ...)`.

    Cross-validation: persistence keys (Run, RunOnce, Services)
    cross-validate with running processes from pslist and with
    binaries in MFT timeline / prefetch.

    `value_data` is treated as untrusted evidence content —
    truncated to 500 characters in the parser. Same cache contract
    and sanitized rejection paths as `disk_mft_timeline`.
    """
    return _disk_registry_impl(evidence_id, case_dir=CASE_DIR)


@mcp.tool()
def query_records(
    evidence_id: str,
    plugin_name: PluginName,
    filters: list[FieldFilter] | None = None,
    fields: list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> QueryRecordsResult:
    """Project + filter records from a stored extraction.

    Tier-2 analytical tool. Reads `case-data/extractions/<evidence_id>/
    <plugin_name>.json` (verifying its hash chain), applies AND-combined
    filters, applies projection, applies offset/limit, returns the
    bounded record set with the pre-limit `matched_count`.

    The agent uses tier-1 Summary fields to decide WHERE to query
    (e.g., "psscan has 26 more records than pslist; query the diff");
    query_records is HOW to retrieve specific rows.

    Filter ops: eq, ne, lt, le, gt, ge, contains, starts_with,
    is_null, is_not_null. AND-combined. Hard cap: limit ≤ 200 records.
    Asking for more is rejected as `query_records:rejected_limit_too_large`.
    Field references that are not in the plugin's schema are rejected
    as `query_records:rejected_unknown_field`.

    The result stays under 10 KB by construction: the limit cap × the
    per-record projection size keeps the JSON return bounded.
    """
    return _query_records_impl(
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        filters=filters,
        fields=fields,
        limit=limit,
        offset=offset,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def group_by(
    evidence_id: str,
    plugin_name: PluginName,
    field: str,
    filters: list[FieldFilter] | None = None,
    top_n: int = 50,
) -> GroupByResult:
    """Aggregate records by a single field; return descending counts.

    Tier-2 analytical tool. Useful for "what process names are most
    common" (group_by image_file_name on pslist), "what foreign IPs
    do we talk to" (group_by foreign_addr on netscan), or "what
    parents have spawned the most children" (group_by ppid on
    pslist).

    `groups` is sorted by count descending and capped at `top_n`
    (hard max 200). `distinct_values` is the post-filter cardinality
    of the field; if it exceeds `len(groups)`, truncation is hiding
    tail values and the agent can re-query with a higher top_n or
    add filters.

    Same field validation and audited rejections as `query_records`.
    """
    return _group_by_impl(
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        field=field,
        filters=filters,
        top_n=top_n,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def set_difference(
    evidence_id: str,
    plugin_a: PluginName,
    plugin_b: PluginName,
    key: str,
    direction: str = "a_minus_b",
    fields: list[str] | None = None,
    limit: int = 200,
) -> SetDifferenceResult:
    """Compute the cross-plugin set difference on a join key.

    Tier-2 analytical tool. The primary cross-plugin primitive — the
    week-6 validator's "find PIDs in psscan that aren't in pslist
    (DKOM-hidden candidates)" rule is one
    `set_difference(plugin_a="windows.psscan.PsScan",
    plugin_b="windows.pslist.PsList", key="pid",
    direction="a_minus_b")` call.

    `direction`:
      - `a_minus_b` — keys in a but not in b (hidden-candidate set
        when a=psscan, b=pslist)
      - `b_minus_a` — keys in b but not in a
      - `symmetric` — keys in exactly one of a or b

    `key` must be a valid field on BOTH plugins. Hard cap: limit ≤
    500 records. Same plugin on both sides is rejected as
    `set_difference:rejected_same_plugin` (no useful self-diff).
    Missing extraction on either side is rejected as
    `set_difference:rejected_extraction_not_found` — the agent must
    have invoked the matching tier-1 tool first.
    """
    return _set_difference_impl(
        evidence_id=evidence_id,
        plugin_a=plugin_a,
        plugin_b=plugin_b,
        key=key,
        direction=direction,
        fields=fields,
        limit=limit,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def subtree(
    evidence_id: str,
    plugin_name: PluginName,
    root_pid: int,
    max_depth: int = 3,
    fields: list[str] | None = None,
) -> SubtreeResult:
    """Extract a subtree of process descendants rooted at `root_pid`.

    Tier-2 analytical tool. Pstree-only — only pstree carries
    parent-child structure. Returns a flat node list; each node has
    its `depth` field added so the agent can reconstruct hierarchy
    from `(pid, ppid, depth)` without the recursive shape blowing
    the budget.

    Hard cap: max_depth ≤ 10. The 200-node truncation is the final
    size guard for wide subtrees (e.g., a process with thousands of
    direct children — drops nodes past the 200th and sets
    `truncated=True`).

    Rejects `subtree:rejected_root_not_found` if `root_pid` is not
    in the extraction. Rejects `subtree:rejected_invalid_key` if
    plugin_name is not pstree (defense-in-depth — the MCP-level
    Literal should normally catch this).
    """
    return _subtree_impl(
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        root_pid=root_pid,
        max_depth=max_depth,
        fields=fields,
        case_dir=CASE_DIR,
    )


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
    host_id: str | None = None,
) -> DraftFinding:
    """Commit a DRAFT finding to the case.

    Analyst subagents call this to record what they found, with back-pointers
    into the audit chain so every claim resolves to the tool calls that fed it.
    The schema's Literal-validated category, severity, and confidence keep the
    finding surface bounded; self-marking DISPUTED is rejected — that state
    is set by the validator, not the analyst.

    Required: a registered evidence_id; an analyst from {process_analyst,
    network_analyst, disk_analyst, validator}; at least one EvidenceRef
    whose audit_line points at a real line in
    case-data/audit/sift-guard-mcp.jsonl AND whose source_tool matches
    that line's tool_name. Server fills finding_id (UUIDv4), created_at
    (UTC now), state ("DRAFT"), and tool_invocations (derived from
    evidence_refs).

    `host_id` is optional and used in multi-evidence (run-case) mode
    where the orchestrator hands each analyst dispatch a host context.
    The orchestrator's user-prompt names the host; the analyst passes
    that identifier through as `host_id` so the finding can later be
    grouped by host for cross-host correlation. Single-evidence
    (run --evidence-id) mode leaves it None.

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
        host_id=host_id,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def record_correlation(
    case_id: str,
    iteration_number: int,
    correlation_type: Literal[
        "corroborates",
        "contradicts",
        "strengthens",
        "weakens",
        "request_followup",
        "cross_host",
    ],
    evidence_refs: list[EvidenceRef],
    hypothesis: str,
    target_finding_ids: list[str] | None = None,
    finding_a_id: str | None = None,
    finding_b_id: str | None = None,
    target_finding_id: str | None = None,
    strength: CorrelationStrength | None = None,
    severity: ContradictionSeverity | None = None,
    resolvable_by_followup: bool | None = None,
    target_analyst: FollowupTargetAnalyst | None = None,
    related_finding_ids: list[str] | None = None,
    focus_context: dict[str, Any] | None = None,
    rationale: str | None = None,
    host_ids: list[str] | None = None,
    shared_indicator: dict[str, Any] | None = None,
) -> (
    CorroboratesCorrelation
    | ContradictsCorrelation
    | StrengthensCorrelation
    | WeakensCorrelation
    | RequestFollowupCorrelation
    | CrossHostCorrelation
):
    """Commit a correlation entry to the case.

    The validator subagent calls this to record what it observed across
    findings: corroboration (≥2 findings agree), contradiction (two
    findings make incompatible claims), strengthens / weakens (one new
    piece of evidence shifts an existing finding's confidence), or a
    request_followup (validator asks the orchestrator to dispatch an
    analyst with a focus context). Five `correlation_type` values
    dispatch to five typed pydantic models; per-type required-field
    check happens at construction time.

    Required: a registered case_id; a correlation_type from
    {corroborates, contradicts, strengthens, weakens, request_followup};
    at least one EvidenceRef whose audit_line + source_tool match a
    real audit-chain entry; every referenced finding_id must resolve
    to an entry in case-data/findings.jsonl. Server fills
    correlation_id (UUIDv4), created_at (UTC now), and audit_line.

    Errors are sanitized — invalid case_id, unknown correlation_type,
    mismatched audit refs, payload-shape errors (e.g., corroborates
    without strength), and unresolvable finding-ids all raise
    ValueError with generic messages while the audit chain captures
    the rejection context for operator review.
    """
    return _record_correlation_impl(
        case_id=case_id,
        iteration_number=iteration_number,
        correlation_type=correlation_type,
        evidence_refs=evidence_refs,
        hypothesis=hypothesis,
        target_finding_ids=target_finding_ids,
        finding_a_id=finding_a_id,
        finding_b_id=finding_b_id,
        target_finding_id=target_finding_id,
        strength=strength,
        severity=severity,
        resolvable_by_followup=resolvable_by_followup,
        target_analyst=target_analyst,
        related_finding_ids=related_finding_ids,
        focus_context=focus_context,
        rationale=rationale,
        host_ids=host_ids,
        shared_indicator=shared_indicator,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def update_finding(
    finding_id: str,
    iteration_number: int,
    new_state: Literal["DRAFT", "CONFIRMED"],
    new_confidence: FindingConfidence,
    promotion_rule: PromotionRule,
    driving_correlation_ids: list[str],
    orchestrator_version: str,
) -> FindingUpdate:
    """Record an orchestrator promotion event against an existing
    finding.

    The orchestrator (NOT analysts, NOT the validator) calls this to
    promote a finding's state and confidence based on the
    correlations the validator produced. Reads the most recent
    record for finding_id (DRAFT or prior UPDATE, last-write-wins) to
    derive previous_state / previous_confidence — server-derived,
    not agent-supplied. Validates the transition (DRAFT → DRAFT or
    CONFIRMED; CONFIRMED → CONFIRMED; backward moves rejected).
    Validates each driving_correlation_id resolves to a real entry
    in correlations.jsonl. Validates promotion_rule against R1..R6.
    Appends a FindingUpdate entry to findings.jsonl in the SAME
    chain as DRAFT entries, distinguished by record_kind="update".

    Errors are sanitized — unknown finding_id, unknown correlation,
    unknown rule, invalid state transition, and pydantic constraint
    failures all raise ValueError with generic messages while the
    audit chain captures the rejection context for operator review.
    """
    return _update_finding_impl(
        finding_id=finding_id,
        iteration_number=iteration_number,
        new_state=new_state,
        new_confidence=new_confidence,
        promotion_rule=promotion_rule,
        driving_correlation_ids=driving_correlation_ids,
        orchestrator_version=orchestrator_version,
        case_dir=CASE_DIR,
    )


@mcp.tool()
def rag_query(
    technique_id: str | None = None,
    semantic_query: str | None = None,
    top_k: int = 5,
) -> RagQueryResult:
    """Query the MITRE ATT&CK enterprise corpus.

    Validator-only tool surface at the agent layer (process_analyst
    and network_analyst do not have this tool listed in their
    frontmatter). Routes to the week-3 FAISS index of 697 ATT&CK
    techniques (CC-BY 4.0).

    Exactly one of `technique_id` and `semantic_query` MUST be set.
    `technique_id` accepts canonical ATT&CK form (`T1055` /
    `T1055.001`) and routes to the retriever's exact-ID
    short-circuit when the ID is in the corpus (rank-1 score=1.0
    with vector neighbors filling the remaining slots up to top_k);
    when the ID matches the regex but is NOT in the corpus, the
    tool returns `hits=[]` rather than falling through to vector
    search. `semantic_query` is passed through to vector search;
    capped at 500 characters. `top_k` defaults to 5, capped at 20.

    The promotion rules R1-R6 do NOT mechanically use RAG hits to
    compute confidence. Citing techniques in a correlation's
    hypothesis grounds the validator's reasoning for human review;
    it does not affect promotion. Reference the call's `audit_line`
    in `EvidenceRef.audit_line` (with `source_tool="rag_query"`)
    to make the citation traceable through the audit chain.
    """
    return _rag_query_impl(
        technique_id=technique_id,
        semantic_query=semantic_query,
        top_k=top_k,
        case_dir=CASE_DIR,
    )


if __name__ == "__main__":
    mcp.run()
