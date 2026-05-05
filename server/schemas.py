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


__all__ = [
    "AnalystName",
    "ArtifactClass",
    "AuditLogEntry",
    "DraftFinding",
    "EvidenceRecord",
    "EvidenceRef",
    "EvidenceRefSourceTool",
    "FindingCategory",
    "FindingChainEntry",
    "FindingConfidence",
    "FindingSeverity",
    "FindingState",
    "NetscanResult",
    "NetworkRecord",
    "ProcessRecord",
    "ProcessScanRecord",
    "ProcessTreeRecord",
    "PslistResult",
    "PsscanResult",
    "PstreeResult",
    "UntrustedString",
]
