"""Pydantic v2 schemas for SIFT-Guard.

Pure data-model module. No I/O, no logging, no side effects on import.
The MCP server, the audit writer, and the evidence-registration tool all
import from here — schemas are the typed boundary between the agent and
the rest of the system, so this file must stay free of runtime concerns.
"""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


_HEX64_PATTERN = r"^[0-9a-f]{64}$"
_GENESIS_PREV_HASH = "0" * 64
_TRUNCATION_SUFFIX = "[truncated, full content in extractions/]"
_CONTENT_LIMIT = 500


class ArtifactClass(StrEnum):
    """Artifact families produced by `register_evidence`'s magic-byte detector.

    Drives the artifact-driven analyst dispatch logic per CLAUDE.md.
    """

    MEMORY_IMAGE = "memory_image"
    DISK_IMAGE = "disk_image"
    REGISTRY_HIVE = "registry_hive"
    EVENT_LOG = "event_log"
    PCAP = "pcap"
    TRIAGE_ZIP = "triage_zip"
    UNKNOWN = "unknown"


def _enforce_utc(name: str, v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware (UTC)")
    if v.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be UTC (offset 00:00)")
    return v


def _json_default(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, StrEnum):
        return obj.value
    return str(obj)


class EvidenceRecord(BaseModel):
    """One row in the case evidence registry. Produced by `register_evidence`.

    `evidence_id` is the agent-visible handle. The MCP server resolves it to
    `absolute_path` internally — the agent cannot construct paths.
    """

    evidence_id: str
    original_filename: str = Field(min_length=1)
    absolute_path: str = Field(min_length=1)
    sha256: str = Field(pattern=_HEX64_PATTERN)
    size_bytes: int = Field(gt=0)
    artifact_class: ArtifactClass
    registered_at: datetime
    file_mode_after_registration: str = Field(min_length=1)

    @field_validator("evidence_id")
    @classmethod
    def _validate_uuid4(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"evidence_id must be a UUID string, got {v!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"evidence_id must be UUID version 4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("registered_at")
    @classmethod
    def _validate_registered_at(cls, v: datetime) -> datetime:
        return _enforce_utc("registered_at", v)

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
                    "original_filename": "Rocba-Memory.raw",
                    "absolute_path": "/mnt/rocba/Rocba-Memory.raw",
                    "sha256": (
                        "eb33bdf63730858a805463d171245b233335dd6d"
                        "89ed458bc681f7d282e10563"
                    ),
                    "size_bytes": 19_050_528_768,
                    "artifact_class": "memory_image",
                    "registered_at": "2026-05-05T00:00:00+00:00",
                    "file_mode_after_registration": "0o444",
                }
            ]
        }
    )


class AuditLogEntry(BaseModel):
    """One JSONL line of the hash-chained MCP audit log.

    `prev_line_hash` is the previous record's `this_line_hash`, or 64 zeros
    for the genesis line. `this_line_hash` is sha256 over a canonical JSON
    serialization of every other field (sorted keys, ISO timestamps).
    Tampering with any field of any line breaks every subsequent line's
    chain — this is the "tamper-evident hash chain" property.
    """

    line_number: int = Field(ge=1)
    timestamp: datetime
    tool_name: str = Field(min_length=1)
    evidence_id: str | None = None
    input_hash: str | None = Field(default=None, pattern=_HEX64_PATTERN)
    output_hash: str = Field(pattern=_HEX64_PATTERN)
    prev_line_hash: str = Field(pattern=_HEX64_PATTERN)
    this_line_hash: str = Field(pattern=_HEX64_PATTERN)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        return _enforce_utc("timestamp", v)

    @classmethod
    def compute_this_line_hash(cls, **fields: Any) -> str:
        """Deterministic sha256 over all fields except `this_line_hash`.

        Canonical form: JSON-serialize the dict with `sort_keys=True`, ISO
        timestamps, enum values rendered as strings. The same input always
        yields the same hash; passing `this_line_hash` is a no-op so the
        helper can be fed `entry.model_dump()` without filtering first.
        """
        payload = {k: v for k, v in fields.items() if k != "this_line_hash"}
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class UntrustedString(BaseModel):
    """Wrapper for evidence-derived strings that must be quarantined from
    instruction interpretation.

    Per CLAUDE.md's prompt-injection defense: registry values, command lines,
    browser history, and event-log strings can carry attacker-controlled
    content. The MCP server wraps every such string in `<evidence>` delimiters
    and analyst system prompts treat anything inside the delimiters as data,
    not instructions.

    Content over 500 chars is truncated in the model itself — the full
    content is preserved in `case-data/extractions/` for analysts that
    explicitly request it.
    """

    source: str = Field(min_length=1)
    evidence_hash: str = Field(pattern=_HEX64_PATTERN)
    content: str

    @field_validator("content")
    @classmethod
    def _truncate(cls, v: str) -> str:
        if len(v) <= _CONTENT_LIMIT:
            return v
        keep = _CONTENT_LIMIT - len(_TRUNCATION_SUFFIX)
        return v[:keep] + _TRUNCATION_SUFFIX

    def to_evidence_block(self) -> str:
        """Render as the canonical `<evidence ...>...</evidence>` wrapper.

        Content is HTML-escaped so a hostile string containing `</evidence>`
        cannot break out of the wrapper and present itself as instructions.
        Source and hash are server-controlled but escaped defensively in case
        a future code path passes user-influenced values.
        """
        safe_source = html.escape(self.source, quote=True)
        safe_hash = html.escape(self.evidence_hash, quote=True)
        safe_content = html.escape(self.content, quote=False)
        return (
            f'<evidence source="{safe_source}" '
            f'hash="{safe_hash}" '
            f'untrusted="true">{safe_content}</evidence>'
        )


class ProcessRecord(BaseModel):
    """One process row from a Volatility memory plugin (pslist/psscan/pstree).

    `image_file_name` is the raw evidence-derived string. The
    `<evidence>`-delimited UntrustedString wrap happens at the tool's
    return boundary where the analyst sees the value, NOT here. Storing
    the raw string in the audit chain lets a future audit-replay
    recompute the wrap deterministically; if the schema wrapped at
    construction time, audit verification would couple to the wrap
    function's stability across releases.
    """

    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    image_file_name: str
    offset_v: int = Field(ge=0)
    threads: int = Field(ge=0)
    handles: int | None = Field(default=None, ge=0)
    session_id: int | None = None
    wow64: bool
    create_time: datetime | None = None
    exit_time: datetime | None = None

    @field_validator("create_time", "exit_time")
    @classmethod
    def _validate_optional_utc(cls, v: datetime | None, info) -> datetime | None:
        if v is None:
            return v
        return _enforce_utc(info.field_name, v)


class PslistResult(BaseModel):
    """Result envelope for the `windows.pslist.PsList` Volatility plugin.

    Carries the rows plus everything needed to reproduce the run from the
    audit log: the pinned plugin name, the Volatility version captured at
    runtime, the full command string. Volatility plugin output formats
    drift between releases — recording the version with each result is
    what lets the audit chain be replayed years later against the same
    binary.
    """

    evidence_id: str
    plugin_name: Literal["windows.pslist.PsList"]
    volatility_version: str = Field(min_length=1)
    processes: list[ProcessRecord]
    command_executed: str = Field(min_length=1)
    runtime_seconds: float = Field(ge=0)
    invoked_at: datetime

    @field_validator("evidence_id")
    @classmethod
    def _validate_evidence_id(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"evidence_id must be a UUID string, got {v!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"evidence_id must be UUID version 4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("invoked_at")
    @classmethod
    def _validate_invoked_at(cls, v: datetime) -> datetime:
        return _enforce_utc("invoked_at", v)


# Type alias. windows.psscan.PsScan emits an EPROCESS row with the same
# 12-key shape as windows.pslist.PsList — verified empirically on the
# SIFT 2026.1 / Volatility 3 2.27.0 build against Rocba (2026-05-05):
# identical {PID, PPID, ImageFileName, Offset(V), Threads, Handles,
# SessionId, Wow64, CreateTime, ExitTime, File output, __children} key
# set across all 2212 records. Aliasing keeps a plugin-named type at
# the boundary without forking schema definitions; if a future Vol
# release ever diverges (e.g. adds a "File offset" field unique to
# psscan), this alias becomes a real subclass at a one-line cost.
ProcessScanRecord = ProcessRecord


class PsscanResult(BaseModel):
    """Result envelope for the `windows.psscan.PsScan` Volatility plugin.

    Same shape as PslistResult — different `plugin_name` Literal. Pool-tag
    scanning surfaces processes the EPROCESS linked-list walk in pslist
    misses (terminated, hidden, unlinked). Most psscan rows on a normal
    Windows host have non-null ExitTime (~90% on Rocba); the load-bearing
    finding for the week-6 cross-plugin validator is the *delta* between
    the two plugins' result sets, not the raw counts. See `vol_psscan` in
    `server.tools.memory` for the docstring on cost and runtime profile.
    """

    evidence_id: str
    plugin_name: Literal["windows.psscan.PsScan"]
    volatility_version: str = Field(min_length=1)
    processes: list[ProcessScanRecord]
    command_executed: str = Field(min_length=1)
    runtime_seconds: float = Field(ge=0)
    invoked_at: datetime

    @field_validator("evidence_id")
    @classmethod
    def _validate_evidence_id(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"evidence_id must be a UUID string, got {v!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"evidence_id must be UUID version 4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("invoked_at")
    @classmethod
    def _validate_invoked_at(cls, v: datetime) -> datetime:
        return _enforce_utc("invoked_at", v)


class ProcessTreeRecord(BaseModel):
    """One node in a `windows.pstree.PsTree` recursive tree.

    Fields divide into three groups:

    1. EPROCESS basics shared with ProcessRecord (pid, ppid,
       image_file_name, offset_v, threads, handles, session_id,
       wow64, create_time, exit_time). Pstree builds on the same
       active-list walk as pslist; these carry the same semantics.
    2. Pstree-specific resolved metadata (audit, cmd, path). Volatility
       reads ``_RTL_USER_PROCESS_PARAMETERS`` to surface the full image
       path, command line, and kernel-side audit name. Most rows have
       these as null — the parameters block is paged out for ~91% of
       processes on a typical Windows snapshot (Rocba: 197/2186
       populated). Treat as untrusted strings; they reflect attacker-
       controlled command-line arguments when populated.
    3. children — recursive list of ProcessTreeRecord, parent-anchored
       by Volatility from each EPROCESS's
       ``InheritedFromUniqueProcessId``. Top-level (depth-0) records
       are processes whose PPID is no longer in the active list, plus
       the genuine root (PID 4 / System, PPID 0). On Rocba: 58 top-
       level entries, max depth 8.

    Cmd / path / audit are not wrapped in ``UntrustedString`` here —
    same convention as ProcessRecord.image_file_name. Wrapping is the
    tool-return-boundary's job; storing raw strings keeps the audit
    chain replayable across changes to the wrap function.
    """

    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    image_file_name: str
    offset_v: int = Field(ge=0)
    threads: int = Field(ge=0)
    handles: int | None = Field(default=None, ge=0)
    session_id: int | None = None
    wow64: bool
    create_time: datetime | None = None
    exit_time: datetime | None = None
    # Pstree-specific. ``audit`` is the kernel-side image name (e.g.
    # ``\Device\HarddiskVolume3\Windows\System32\smss.exe``); ``path``
    # is the user-space resolved path (e.g.
    # ``\SystemRoot\System32\smss.exe``); ``cmd`` is the full command
    # line. Any of the three may be null on Vol 3 2.27.0 even when
    # the others are populated.
    audit: str | None = None
    cmd: str | None = None
    path: str | None = None
    children: list["ProcessTreeRecord"] = Field(default_factory=list)

    @field_validator("create_time", "exit_time")
    @classmethod
    def _validate_optional_utc(cls, v: datetime | None, info) -> datetime | None:
        if v is None:
            return v
        return _enforce_utc(info.field_name, v)


# Pydantic v2 needs an explicit rebuild for self-referential forward
# references when used with `from __future__ import annotations`. The
# class body finishes evaluating to a string `"ProcessTreeRecord"` for
# `children`'s type; this resolves it.
ProcessTreeRecord.model_rebuild()


class PstreeResult(BaseModel):
    """Result envelope for the `windows.pstree.PsTree` Volatility plugin.

    Same provenance shape as PslistResult / PsscanResult — different
    `plugin_name` Literal, and `processes` carries top-level (depth-0)
    nodes with descendants nested via ``ProcessTreeRecord.children``.

    The week-6 validator uses this tree shape to detect masquerading
    (svchost.exe with a non-services.exe parent), unusual depth
    (powershell.exe spawned from explorer.exe at depth 4+), and
    orphaned subtrees whose PPID points outside the active list.
    """

    evidence_id: str
    plugin_name: Literal["windows.pstree.PsTree"]
    volatility_version: str = Field(min_length=1)
    processes: list[ProcessTreeRecord]
    command_executed: str = Field(min_length=1)
    runtime_seconds: float = Field(ge=0)
    invoked_at: datetime

    @field_validator("evidence_id")
    @classmethod
    def _validate_evidence_id(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"evidence_id must be a UUID string, got {v!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"evidence_id must be UUID version 4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("invoked_at")
    @classmethod
    def _validate_invoked_at(cls, v: datetime) -> datetime:
        return _enforce_utc("invoked_at", v)


class NetworkRecord(BaseModel):
    """One network endpoint or connection from `windows.netscan.NetScan`.

    Pool-tag scans the network object table and recovers TCP / UDP
    endpoint structures plus connection state. The same field set
    applies across all four protocol families — UDP records use
    ``state == ""`` (UDP is connectionless) and ``foreign_addr == "*"``
    when the endpoint is unbound, rather than null. This is the
    netstat convention; the validator should treat `state == ""` as
    "no TCP-style state, this is a UDP endpoint".

    `pid` and `owner` may both be null for kernel-only endpoints or
    sockets whose owning process exited but whose pool entry survives
    — same recovery semantic as psscan's exited rows. On Rocba 7 of
    430 records had null PID + null owner.

    Strings (`local_addr`, `foreign_addr`, `owner`) are stored raw
    from the evidence; the tool's return boundary wraps them in
    ``UntrustedString`` for analyst consumption. Same convention as
    ProcessRecord.image_file_name. IP-address strings are not length-
    capped — IPv6 zone-id'd link-local forms can be long.
    """

    proto: Literal["TCPv4", "TCPv6", "UDPv4", "UDPv6"]
    local_addr: str
    local_port: int = Field(ge=0, le=65535)
    foreign_addr: str
    foreign_port: int = Field(ge=0, le=65535)
    # TCP states observed on Rocba: LISTENING, ESTABLISHED, CLOSED,
    # CLOSE_WAIT, SYN_RCVD. The full Windows TCP state set is larger
    # (TIME_WAIT, FIN_WAIT_*, LAST_ACK, ...). Using `str` rather than
    # an enum keeps schema construction tolerant of any state Vol
    # surfaces; the validator can pattern-match on values it cares
    # about. Empty string for UDP records — see class docstring.
    state: str = ""
    pid: int | None = Field(default=None, ge=0)
    owner: str | None = None
    offset: int = Field(ge=0)
    created: datetime | None = None

    @field_validator("created")
    @classmethod
    def _validate_optional_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return v
        return _enforce_utc("created", v)


class NetscanResult(BaseModel):
    """Result envelope for the `windows.netscan.PsScan` Volatility plugin.

    Same provenance shape as the other memory-tool results — different
    `plugin_name` Literal and `connections: list[NetworkRecord]`.

    Cross-source within memory: combined with vol_psscan/vol_pstree's
    process artifacts, the week-6 validator can flag "PID is bound to
    a port in netscan but absent from pslist's active-list walk" —
    a classic DKOM-hidden process signal.
    """

    evidence_id: str
    plugin_name: Literal["windows.netscan.NetScan"]
    volatility_version: str = Field(min_length=1)
    connections: list[NetworkRecord]
    command_executed: str = Field(min_length=1)
    runtime_seconds: float = Field(ge=0)
    invoked_at: datetime

    @field_validator("evidence_id")
    @classmethod
    def _validate_evidence_id(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(f"evidence_id must be a UUID string, got {v!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"evidence_id must be UUID version 4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("invoked_at")
    @classmethod
    def _validate_invoked_at(cls, v: datetime) -> datetime:
        return _enforce_utc("invoked_at", v)


# ---------------------------------------------------------------------------
# Findings substrate
#
# `record_finding` is the MCP tool analyst subagents call to commit a
# finding to the case. The agent cannot drift away from the contract:
# either it called the tool (in which case the audit chain records
# what was claimed and a new line lands in `findings.jsonl`) or it
# didn't (in which case there is no finding). A required-final-JSON
# convention would be a prompt commitment; this is architectural.
#
# The schemas below split into three:
#   - `EvidenceRef`: one back-pointer from a finding into the audit
#     chain. Every finding must carry ≥1.
#   - `DraftFinding`: the finding payload. Server-controlled fields
#     (`finding_id`, `created_at`, `state`, `tool_invocations`) are
#     enforced at the tool layer, not here — the schema accepts what
#     the server constructs.
#   - `FindingChainEntry`: the wrapper line written into
#     `findings.jsonl`. Mirrors `AuditLogEntry`'s shape (line_number
#     + timestamp + payload + prev/this-hash) so the on-disk log is
#     hash-chain-replayable the same way.
# ---------------------------------------------------------------------------


# Allow-listed sources for an EvidenceRef. Mirrors the live MCP tool
# surface as of week 5 — extending the surface (e.g. registry parsers
# in week 6) requires extending this Literal *and* the surface-lock
# test, by design. The `:rejected_*` and `:record_validation_warning`
# variants are not listed here because findings only point at
# successful tool invocations.
EvidenceRefSourceTool = Literal[
    "register_evidence",
    "vol_pslist",
    "vol_psscan",
    "vol_pstree",
    "vol_netscan",
]


class EvidenceRef(BaseModel):
    """One back-pointer from a finding into the audit chain.

    `audit_line` is the line number in `case-data/audit/sift-guard-mcp.jsonl`
    where the source tool's success entry was logged.
    `record_finding` validates at write time that the line exists AND that
    the audit entry's `tool_name` matches `source_tool`, so the finding
    cannot point at a tool call that didn't actually run. `detail`
    captures the specific row, PID, port, etc. the finding is about
    — kept short (≤500 chars) so a top-k retrieval result remains
    LLM-context-friendly.
    """

    source_tool: EvidenceRefSourceTool
    audit_line: int = Field(ge=1)
    detail: str = Field(min_length=1, max_length=500)


FindingCategory = Literal[
    "process_anomaly",
    "process_hidden",
    "process_masquerade",
    "process_injection",
    "network_anomaly",
    "network_beacon",
    "network_lateral_movement",
    "persistence",
    "credential_access",
    "other",
]
FindingSeverity = Literal["info", "low", "medium", "high", "critical"]
FindingConfidence = Literal["LOW", "MEDIUM", "HIGH", "DISPUTED"]
FindingState = Literal["DRAFT", "CONFIRMED", "DISPUTED"]
# Allow-listed analyst names. Today: the three subagents that actually
# write findings against the active memory roster. Adding an analyst
# requires an explicit edit — silent extension would erode the
# audit-chain authorship signal.
AnalystName = Literal["process_analyst", "network_analyst", "validator"]


class DraftFinding(BaseModel):
    """A single analyst finding, in DRAFT state at write time.

    Lifecycle:
      - DRAFT — written by analysts; the only state `record_finding`
        will accept. Self-marked DISPUTED is rejected architecturally.
      - CONFIRMED / DISPUTED — set by the week-6 validator after
        cross-source / cross-plugin correlation.

    Server-controlled fields:
      - `finding_id` is generated by the server (UUIDv4); never
        agent-supplied. The schema accepts whatever the server
        constructs but the tool layer overrides any agent input.
      - `created_at` is set to the tool-call timestamp.
      - `state` is fixed at "DRAFT" by the tool; promotion happens
        elsewhere.
      - `tool_invocations` is derived from `evidence_refs` — sorted,
        deduplicated `<source_tool>:<audit_line>` strings — so it
        cannot disagree with the back-pointers.

    Length constraints on `title` (10-200) and `description`
    (50-2000) push analysts toward the right granularity: short
    enough to be one finding, long enough to be substantiated.
    """

    finding_id: str
    evidence_id: str
    analyst: AnalystName
    state: FindingState
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str = Field(min_length=10, max_length=200)
    description: str = Field(min_length=50, max_length=2000)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)
    hypothesis: str | None = Field(default=None, max_length=1000)
    created_at: datetime
    tool_invocations: list[str] = Field(default_factory=list)

    @field_validator("finding_id", "evidence_id")
    @classmethod
    def _validate_uuid4(cls, v: str, info) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"{info.field_name} must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"{info.field_name} must be UUID version 4, got version "
                f"{parsed.version}"
            )
        return str(parsed)

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, v: datetime) -> datetime:
        return _enforce_utc("created_at", v)


class FindingChainEntry(BaseModel):
    """One JSONL line of the hash-chained findings log.

    Mirrors `AuditLogEntry` exactly in chain semantics —
    `prev_finding_hash` is the previous record's `this_finding_hash`,
    or 64 zeros for genesis; `this_finding_hash` is sha256 over a
    canonical JSON serialization of every other field. Tampering with
    any field of any line breaks every subsequent line's chain.

    Distinct field names (`prev_finding_hash` / `this_finding_hash`)
    rather than reusing `prev_line_hash` / `this_line_hash` from the
    audit chain so a line read from one file cannot be silently
    misread as the other.
    """

    line_number: int = Field(ge=1)
    timestamp: datetime
    finding: DraftFinding
    prev_finding_hash: str = Field(pattern=_HEX64_PATTERN)
    this_finding_hash: str = Field(pattern=_HEX64_PATTERN)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        return _enforce_utc("timestamp", v)

    @classmethod
    def compute_this_finding_hash(cls, **fields: Any) -> str:
        """Deterministic sha256 over all fields except `this_finding_hash`.

        Same canonical-form rule as `AuditLogEntry.compute_this_line_hash`:
        sorted JSON keys, ISO timestamps, enum values rendered as strings.
        Passing `this_finding_hash` is a no-op; the helper accepts a full
        `model_dump()` without filtering.
        """
        payload = {k: v for k, v in fields.items() if k != "this_finding_hash"}
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Tier-1 / tier-2 architecture (week 5 refactor)
#
# Tier-1 memory tools (vol_pslist/psscan/pstree/netscan) persist their full
# Volatility output to `case-data/extractions/<evidence_id>/<plugin_name>.json`
# and return a small (≤10 KB) Summary object pointing at the stored
# extraction. Tier-2 analytical tools (query_records, group_by,
# set_difference, subtree) read stored extractions and compose narrowed
# answers. Architecture rationale: the tool-result token budget collapses
# the "tool returns full data" pattern on realistic Windows memory images
# (process_analyst v1 experiment, 2026-05-05 — see
# docs/process-analyst-v1-results.md).
#
# The schemas below split into:
#   - PluginName: shared Literal across tier-1 and tier-2 schemas.
#   - ExtractionRef: agent-visible handle for a stored extraction. Carries
#     the fields the agent needs to know the extraction is real (sha256,
#     chain-line, record_count) without containing the records themselves.
#   - ExtractionChainEntry: one JSONL line of `extractions.jsonl`. Mirrors
#     `AuditLogEntry`'s and `FindingChainEntry`'s chain shape with distinct
#     hash field names so a line read out of context cannot be misread.
#   - Tier-1 *Summary types (Pslist/Psscan/Pstree/Netscan): the thing the
#     LLM actually sees — distribution / shape signal, not records.
#   - Tier-2 result types (QueryRecords/GroupBy/SetDifference/Subtree):
#     bounded composed answers, all under the 10 KB ceiling.
#   - FieldFilter: shared filter primitive for tier-2 tools.
# ---------------------------------------------------------------------------


# All four supported Volatility memory plugins. Tier-1 tools each pin one
# of these as their plugin_name; tier-2 tools accept it as an argument.
# Adding a plugin requires extending this Literal AND extending the
# matching test in tests/test_mcp_protocol.py — by design.
PluginName = Literal[
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.pstree.PsTree",
    "windows.netscan.NetScan",
]


class ExtractionRef(BaseModel):
    """Agent-visible handle for a stored extraction.

    Returned inside every tier-1 Summary and every tier-2 result. Carries
    enough provenance for the agent to reason about freshness and
    reproducibility (the chain line, the hash, the record count) without
    embedding records that would blow the token budget. The matching
    extraction file lives at
    `<case_dir>/extractions/<evidence_id>/<plugin_name>.json`; the agent
    cannot construct that path (no file-tools surface), so the reference
    is informational, not addressable.

    `cached` distinguishes a fresh Volatility run (`False`,
    `runtime_seconds` populated) from a re-read of a stored extraction
    (`True`, `runtime_seconds` null per the cache contract). The
    `extraction_id` is server-generated at first creation and stable
    across re-reads — re-invoking a cached pair returns the same id.
    """

    evidence_id: str
    plugin_name: PluginName
    extraction_id: str
    record_count: int = Field(ge=0)
    extraction_sha256: str = Field(pattern=_HEX64_PATTERN)
    extractions_chain_line: int = Field(ge=1)
    runtime_seconds: float | None = Field(default=None, ge=0)
    cached: bool

    @field_validator("evidence_id", "extraction_id")
    @classmethod
    def _validate_uuid4(cls, v: str, info) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"{info.field_name} must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"{info.field_name} must be UUID version 4, got version "
                f"{parsed.version}"
            )
        return str(parsed)


class ExtractionChainEntry(BaseModel):
    """One JSONL line of the hash-chained extractions log.

    Distinct field names (`prev_extraction_hash` / `this_extraction_hash`)
    rather than reusing the audit chain's hash field names so a line read
    from one file cannot be silently misread as the other. Same canonical
    hash semantics as AuditLogEntry / FindingChainEntry (sorted JSON
    keys, ISO timestamps, enum values rendered as strings).
    """

    line_number: int = Field(ge=1)
    timestamp: datetime
    evidence_id: str
    plugin_name: str = Field(min_length=1)
    extraction_id: str
    extraction_sha256: str = Field(pattern=_HEX64_PATTERN)
    record_count: int = Field(ge=0)
    runtime_seconds: float = Field(ge=0)
    prev_extraction_hash: str = Field(pattern=_HEX64_PATTERN)
    this_extraction_hash: str = Field(pattern=_HEX64_PATTERN)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        return _enforce_utc("timestamp", v)

    @classmethod
    def compute_this_extraction_hash(cls, **fields: Any) -> str:
        """Deterministic sha256 over all fields except `this_extraction_hash`.

        Same canonical-form rule as `AuditLogEntry.compute_this_line_hash`
        and `FindingChainEntry.compute_this_finding_hash`. Passing
        `this_extraction_hash` is a no-op so the helper accepts a full
        `model_dump()` without filtering.
        """
        payload = {
            k: v for k, v in fields.items() if k != "this_extraction_hash"
        }
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PslistSummary(BaseModel):
    """Tier-1 return for `vol_pslist`.

    Carries shape and distribution signal — never specific records. The
    agent uses this to decide *where* to look (e.g., "psscan has 26 more
    records than pslist; query the diff"); it uses tier-2 tools to
    actually look.

    Field substitution note: the architecture spec listed
    `null_cmdline_count` here, but `ProcessRecord` has no `cmdline` field
    (only pstree carries `cmd`). `null_create_time_count` is the
    structurally-analogous nullable EPROCESS field on pslist's actual
    schema — equivalent shape signal (how many records have an unset
    metadata field), implementable from the data we have.

    `top_image_names` is bounded to 10 entries to keep the summary
    serialization under 10 KB even on images with thousands of distinct
    process names. Bounded count is verified in the tier-1 size budget
    test (10000-row synthetic fixture).
    """

    extraction: ExtractionRef
    unique_image_names: int = Field(ge=0)
    null_create_time_count: int = Field(ge=0)
    with_exit_time_count: int = Field(ge=0)
    distinct_ppids: int = Field(ge=0)
    top_image_names: list[tuple[str, int]] = Field(max_length=10)
    pid_range: tuple[int, int]


class PsscanSummary(PslistSummary):
    """Tier-1 return for `vol_psscan`.

    Identical shape to `PslistSummary` because the underlying record
    schema is the same (`ProcessScanRecord = ProcessRecord` alias). The
    differentiator surfaces via `extraction.plugin_name`; the
    cross-plugin diff is what `set_difference` does. Reserved as a
    distinct subclass so future psscan-specific fields (e.g., a
    pool-tag-derived offset signal) land cleanly without changing
    pslist's surface.
    """

    pass


class PstreeSummary(BaseModel):
    """Tier-1 return for `vol_pstree`.

    Captures tree shape: how many top-level roots, how deep, how the
    depth distribution looks, the largest single subtree, and how many
    roots are orphans (PPID not present anywhere in the tree, excluding
    PID 4 / System with PPID 0). The week-6 validator's masquerading
    detection runs against the stored extraction via `subtree`; this
    summary tells the validator where to start.

    `depth_distribution` keys are depth integers; pydantic v2 emits them
    as JSON object string keys per the spec. `largest_subtree` is
    `(root_pid, descendant_count)` — the count is total descendants,
    not just direct children.
    """

    extraction: ExtractionRef
    top_level_root_count: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    depth_distribution: dict[int, int]
    largest_subtree: tuple[int, int]
    orphan_count: int = Field(ge=0)


class NetscanSummary(BaseModel):
    """Tier-1 return for `vol_netscan`.

    Distribution-only: which protocols are present and how often, what
    TCP states show up, how many records have null owner (kernel-only or
    exited-process residual), how many endpoints are listening vs
    established, and how many distinct foreign addresses the host talked
    to. The agent uses these to decide whether a beacon hunt is worth
    `query_records` calls; specific endpoints come from query_records.
    """

    extraction: ExtractionRef
    protocol_distribution: dict[str, int]
    tcp_state_distribution: dict[str, int]
    null_owner_count: int = Field(ge=0)
    listening_port_count: int = Field(ge=0)
    established_count: int = Field(ge=0)
    distinct_foreign_addrs: int = Field(ge=0)


class FieldFilter(BaseModel):
    """One AND-combined filter clause for tier-2 query/group_by tools.

    `field` is validated against the plugin's known schema by the
    consuming tool (rejected with `:rejected_unknown_field` and
    audited if unknown). `value` is `None` only for the
    `is_null`/`is_not_null` ops; it is the raw comparison value
    otherwise. `Any` is intentional — filters operate on any field
    regardless of its declared type, and pydantic does not enforce a
    cross-field type match here. The tool layer does that.
    """

    field: str = Field(min_length=1)
    op: Literal[
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
        "contains",
        "starts_with",
        "is_null",
        "is_not_null",
    ]
    value: Any = None


class QueryRecordsResult(BaseModel):
    """Tier-2 return for `query_records`.

    `records` carries projected dicts (post-`fields` projection); the
    tool's `limit` cap holds the serialized size under 10 KB by the
    same property the tier-1 size-budget test pins. `matched_count` is
    the count *before* limit/offset, so the agent can decide whether
    to widen the limit or refine the filters.
    """

    extraction: ExtractionRef
    matched_count: int = Field(ge=0)
    returned_count: int = Field(ge=0)
    records: list[dict]
    truncated: bool


class GroupByResult(BaseModel):
    """Tier-2 return for `group_by`.

    `groups` is a list of `(value, count)` tuples sorted descending by
    count, capped at `top_n`. `distinct_values` is the full count of
    unique field values across the extraction (post-filter); a high
    `distinct_values` with a short `groups` list tells the agent the
    field is high-cardinality.
    """

    extraction: ExtractionRef
    field: str
    total_records: int = Field(ge=0)
    distinct_values: int = Field(ge=0)
    groups: list[tuple[Any, int]]


class SetDifferenceResult(BaseModel):
    """Tier-2 return for `set_difference`.

    The primary cross-plugin primitive. `set_difference(plugin_a=psscan,
    plugin_b=pslist, key="pid", direction="a_minus_b")` computes the
    DKOM-hidden-process candidate set (entries in psscan but not in
    pslist's active-list walk).

    Two count families surface together because they answer different
    questions (per `docs/decisions-log.md` 2026-05-06):

      - `a_only_count`, `b_only_count`, `intersection_count` are
        SET-semantic on the join key. `a_only_count` is the number of
        UNIQUE keys in plugin_a not present in plugin_b. The validator
        leans on this for "how many distinct entities are missing from
        plugin_b".
      - `a_record_count`, `b_record_count` are total record counts in
        each extraction. Useful for audit-style sanity checks ("the
        record-count delta is K"), distinct from the entity-set diff.
      - `a_duplicate_key_count`, `b_duplicate_key_count` are records
        in each extraction whose key value appears more than once in
        that same extraction (counted as "extras beyond first
        occurrence"). On Volatility psscan, pool-tag aliasing produces
        these — same EPROCESS structure discovered twice across pool
        boundaries. Useful for detecting whether a record-count delta
        is real anomaly or just pool-tag noise.

    `returned_records` is per-record (not deduped by key): if a key
    appears twice in plugin_a's a_only set, both records are returned
    (subject to `limit`). The agent typically wants every alias for
    forensic-grade evidence.
    """

    extraction_a: ExtractionRef
    extraction_b: ExtractionRef
    key: str
    direction: Literal["a_minus_b", "b_minus_a", "symmetric"]
    a_only_count: int = Field(ge=0)
    b_only_count: int = Field(ge=0)
    intersection_count: int = Field(ge=0)
    a_record_count: int = Field(ge=0)
    b_record_count: int = Field(ge=0)
    a_duplicate_key_count: int = Field(ge=0)
    b_duplicate_key_count: int = Field(ge=0)
    returned_records: list[dict]
    truncated: bool


class SubtreeResult(BaseModel):
    """Tier-2 return for `subtree`.

    Pstree-only because only pstree carries parent-child structure.
    `nodes` is a flat list with each node's `depth` field added so the
    agent can reconstruct hierarchy without the recursive shape
    blowing the token budget. `descendant_count` is total descendants
    (sum across all depths); `truncated` is True when the subtree
    contained more than 200 nodes.
    """

    extraction: ExtractionRef
    root_pid: int = Field(ge=0)
    root_found: bool
    depth_traversed: int = Field(ge=0)
    descendant_count: int = Field(ge=0)
    nodes: list[dict]
    truncated: bool


__all__ = [
    "AnalystName",
    "ArtifactClass",
    "AuditLogEntry",
    "DraftFinding",
    "EvidenceRecord",
    "EvidenceRef",
    "EvidenceRefSourceTool",
    "ExtractionChainEntry",
    "ExtractionRef",
    "FieldFilter",
    "FindingCategory",
    "FindingChainEntry",
    "FindingConfidence",
    "FindingSeverity",
    "FindingState",
    "GroupByResult",
    "NetscanResult",
    "NetscanSummary",
    "NetworkRecord",
    "PluginName",
    "ProcessRecord",
    "ProcessScanRecord",
    "ProcessTreeRecord",
    "PslistResult",
    "PslistSummary",
    "PsscanResult",
    "PsscanSummary",
    "PstreeResult",
    "PstreeSummary",
    "QueryRecordsResult",
    "SetDifferenceResult",
    "SubtreeResult",
    "UntrustedString",
]
