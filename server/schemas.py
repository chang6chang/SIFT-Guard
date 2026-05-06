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
from typing import Annotated, Any, Literal, Union
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


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
# test, by design. The `:rejected_*`, `:cached`, `:hash_mismatch`, and
# `:record_validation_warning` variants are not listed here because
# findings only point at successful tool invocations whose audit
# entries carry the bare tool_name (or `:cached` if the agent wants
# to cite the cache hit explicitly — but the analyst typically cites
# the original ExtractionRef.audit_line, which is the bare tool_name's
# line, not the cache-hit's).
#
# Tier-2 names added 2026-05-06: a tier-2 result's `audit_line` field
# is the agent-visible primitive for citing a derived analysis as
# evidence (e.g., a finding "PID 7900 is in psscan but not pslist"
# is supported by the underlying tier-1 evidence and the
# set_difference call that surfaced the relationship).
EvidenceRefSourceTool = Literal[
    "register_evidence",
    "vol_pslist",
    "vol_psscan",
    "vol_pstree",
    "vol_netscan",
    "query_records",
    "group_by",
    "set_difference",
    "subtree",
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


class FindingRecordKind(StrEnum):
    """Discriminator on `findings.jsonl` line payloads.

    Three writers, three roles:
      - Analysts call `record_finding` and produce `DraftFinding`
        entries (`record_kind = "draft"`). DRAFT only at write time;
        analysts never write CONFIRMED.
      - The orchestrator calls `update_finding` and produces
        `FindingUpdate` entries (`record_kind = "update"`) — promotion
        events that change a prior finding's `state` and / or
        `confidence`. Carries a back-pointer to the original
        `finding_id` and to the correlations that drove the
        promotion.

    Both kinds land in the SAME `findings.jsonl` chain, distinguished
    by this discriminator. The chain remains append-only: an UPDATE
    entry never modifies the original DRAFT line; readers replay the
    chain and apply UPDATE entries last-write-wins to derive the
    current state of any given finding.

    Migration semantic: legacy lines (written before this
    discriminator existed) lack `record_kind`; the chain reader
    injects `"draft"` so they parse as `DraftFinding` under the
    discriminated union. New writes always populate the field.
    """

    DRAFT = "draft"
    UPDATE = "update"


# Promotion-rule names recognized by `update_finding`. The orchestrator
# (Prompt B's deliverable, week 6) decides which rule to call by name;
# the substrate's job is to record the name in the chain so a future
# audit-replay can reconstruct which rule fired and why. The validator
# never calls `update_finding`; the orchestrator never calls
# `record_correlation`. Adding a rule requires extending this Literal
# AND the matching test in `tests/test_update_finding.py`.
PromotionRule = Literal["R1", "R2", "R3", "R4", "R5", "R6"]


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

    # Discriminator under FindingChainPayload. Default = "draft" so
    # that loading a legacy DraftFinding row (written before the
    # discriminator existed) succeeds via field default. The chain-
    # entry-level model_validator(mode="before") additionally injects
    # `record_kind="draft"` into the inner finding dict for the
    # discriminated-union dispatch (defaults aren't seen by the
    # discriminator extractor, which reads the raw input dict).
    record_kind: Literal[FindingRecordKind.DRAFT] = FindingRecordKind.DRAFT
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


class FindingUpdate(BaseModel):
    """A promotion event from the orchestrator.

    Lands in `findings.jsonl` as a sibling of `DraftFinding` entries,
    distinguished by `record_kind = "update"`. Carries a back-pointer
    to the original `finding_id` and to the correlations that drove
    the promotion, plus the state/confidence transition. The
    orchestrator computes `previous_state` and `previous_confidence`
    by scanning the chain for the most recent record of the same
    `finding_id` (last-write-wins across DRAFT and prior UPDATEs);
    the substrate validates the transition is allowed (DRAFT can go
    to DRAFT or CONFIRMED; CONFIRMED stays CONFIRMED) and rejects
    backward moves.

    `promotion_rule` is the named rule the orchestrator chose. The
    rule decision logic (which rule fires when) is the orchestrator's
    job; the substrate only records the name. `driving_correlation_ids`
    points at the validator's correlation entries that the rule
    consumed; the substrate validates each id resolves to a real
    correlation in `correlations.jsonl`.

    `audit_line` is the audit-chain line where this `update_finding`
    call's success entry was logged — same provenance pattern as
    tier-2 results.

    `orchestrator_version` is a free-form version string the
    orchestrator stamps on each promotion so a future audit-replay
    can resolve "which version of the rule code produced this
    promotion".
    """

    record_kind: Literal[FindingRecordKind.UPDATE] = FindingRecordKind.UPDATE
    update_id: str
    finding_id: str
    iteration_number: int = Field(ge=0)
    previous_state: Literal["DRAFT", "CONFIRMED"]
    new_state: Literal["DRAFT", "CONFIRMED"]
    previous_confidence: FindingConfidence
    new_confidence: FindingConfidence
    promotion_rule: PromotionRule
    # Field-level minimum is 0 so R5 ("quiet stabilization") can write
    # an UPDATE entry. R5's defining precondition is "no correlations
    # on F across two iterations of silence", which is incompatible
    # with the original min_length=1 invariant. The model_validator
    # below restores the min_length=1 contract for every other rule —
    # R1-R4 / R6 still cannot write empty lists, only R5 can.
    driving_correlation_ids: list[str]
    created_at: datetime
    audit_line: int = Field(ge=1)
    orchestrator_version: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def _r5_only_may_be_empty(self) -> "FindingUpdate":
        """Empty `driving_correlation_ids` is permitted iff
        `promotion_rule == "R5"`. R5's quiet-stabilization semantics
        explicitly carry no driving correlations (the rule fires when
        no correlations exist on the finding for two iterations); for
        every other rule, an empty list would break the audit-trail
        invariant that promotions cite the correlations that drove
        them. See `docs/decisions-log.md` 2026-05-07 R5 persistence
        entry.
        """
        if not self.driving_correlation_ids and self.promotion_rule != "R5":
            raise ValueError(
                "driving_correlation_ids must be non-empty for "
                f"promotion_rule={self.promotion_rule!r}; only R5 "
                "(quiet stabilization) may write an empty list"
            )
        return self

    @field_validator("update_id", "finding_id")
    @classmethod
    def _validate_uuid4_update(cls, v: str, info) -> str:
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

    @field_validator("driving_correlation_ids")
    @classmethod
    def _validate_correlation_uuids(cls, v: list[str]) -> list[str]:
        for cid in v:
            try:
                parsed = UUID(cid)
            except (ValueError, AttributeError, TypeError) as exc:
                raise ValueError(
                    f"driving_correlation_ids entries must be UUID strings, "
                    f"got {cid!r}"
                ) from exc
            if parsed.version != 4:
                raise ValueError(
                    f"driving_correlation_ids entries must be UUID v4, "
                    f"got version {parsed.version}"
                )
        return v

    @field_validator("created_at")
    @classmethod
    def _validate_created_at_update(cls, v: datetime) -> datetime:
        return _enforce_utc("created_at", v)


# Discriminated union for `findings.jsonl` line payloads. The
# `record_kind` field is the discriminator: "draft" → DraftFinding,
# "update" → FindingUpdate. The chain-entry-level
# model_validator(mode="before") handles the legacy-no-record_kind
# case before this discriminator runs.
FindingChainPayload = Annotated[
    Union[DraftFinding, FindingUpdate],
    Field(discriminator="record_kind"),
]


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
    finding: FindingChainPayload
    prev_finding_hash: str = Field(pattern=_HEX64_PATTERN)
    this_finding_hash: str = Field(pattern=_HEX64_PATTERN)

    @model_validator(mode="before")
    @classmethod
    def _legacy_record_kind_default(cls, data: Any) -> Any:
        """Legacy entries (written before `record_kind` existed) lack
        the discriminator. Inject `"draft"` so the discriminated union
        dispatches them to `DraftFinding`. New entries always carry
        `record_kind` so this is a no-op for them.

        Hash-replay note: the on-disk `this_finding_hash` of a legacy
        line was computed without `record_kind` in the payload. Re-
        hashing AFTER this injection produces a different value;
        chain-replay tooling that wants byte-exact verification must
        read the raw JSON line and hash it as-is, not via this model.
        The chain itself remains intact (line N+1's prev hash points
        at line N's stored this hash regardless).
        """
        if isinstance(data, dict):
            payload = data.get("finding")
            if isinstance(payload, dict) and "record_kind" not in payload:
                data = {**data, "finding": {**payload, "record_kind": "draft"}}
        return data

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


# Per-plugin map of record fields whose values are derived from evidence
# content (and therefore attacker-controllable). Used by tier-1 summary
# defaults and by tier-2 tools to populate every result's
# `untrusted_fields` list — the schema-level contract that tells analyst
# subagents which field VALUES to treat as data rather than as
# instructions. See `docs/adversarial-robustness.md` for the threat
# model and CLAUDE.md "Treat evidence-derived strings as untrusted" rule.
#
# The set is the actual schema fields on each plugin's record type:
#   - ProcessRecord (pslist/psscan): only `image_file_name` is a
#     free-form string surfaced from the EPROCESS structure. Numeric
#     and timestamp fields are kernel-structural data, not strings.
#   - ProcessTreeRecord (pstree): the EPROCESS basics plus `audit`,
#     `cmd`, `path` from `_RTL_USER_PROCESS_PARAMETERS`.
#   - NetworkRecord (netscan): `local_addr`, `foreign_addr`, `owner`,
#     `state` are all evidence-derived strings. `proto` is a closed
#     Literal so its values are schema-controlled, not evidence-derived.
#
# Adding a plugin (or extending a record type with a new
# evidence-derived string field) MUST update this map AND the matching
# `tests/test_untrusted_fields.py` assertions — by design, so a future
# tool addition cannot silently widen the agent-visible attack surface.
PLUGIN_UNTRUSTED_RECORD_FIELDS: dict[str, tuple[str, ...]] = {
    "windows.pslist.PsList": ("image_file_name",),
    "windows.psscan.PsScan": ("image_file_name",),
    "windows.pstree.PsTree": ("image_file_name", "audit", "cmd", "path"),
    "windows.netscan.NetScan": (
        "local_addr",
        "foreign_addr",
        "owner",
        "state",
    ),
}


def untrusted_fields_for(
    plugin_name: str, projection: list[str] | None = None
) -> list[str]:
    """Compute the `untrusted_fields` list for a tier-2 result.

    `plugin_name` is the source plugin whose records back the result
    (e.g. ``windows.pslist.PsList`` for a query_records call against
    pslist's stored extraction; the chosen side for set_difference).
    `projection` is the list of fields actually projected into the
    returned records — when None or empty, the records contain every
    field of the plugin's record type and all plugin-untrusted fields
    apply. When non-empty, only the intersection (a projection that
    drops every untrusted field yields an empty list).

    Order is preserved: the result's list reflects the canonical
    PLUGIN_UNTRUSTED_RECORD_FIELDS order, not the projection's order.
    Stable order keeps the schema property reproducible across calls
    with different projection orderings, per the test
    `test_untrusted_fields_is_stable_across_projection_order`.
    """
    base = PLUGIN_UNTRUSTED_RECORD_FIELDS.get(plugin_name, ())
    if not projection:
        return list(base)
    projection_set = set(projection)
    return [f for f in base if f in projection_set]


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

    `audit_line` is the audit-chain line number where the Volatility
    plugin invocation that *originally* produced this extraction was
    logged. For cached returns, this is the original (pre-cache)
    invocation's line number, NOT the cache-hit's `<plugin>:cached`
    log entry. The cache-hit is logged separately but is not the
    provenance reference for findings. May be `None` for legacy
    extractions written before the `audit_line` field was added to
    `extractions.jsonl` (migration semantic — see
    `docs/decisions-log.md` 2026-05-06 audit_line plumbing entry).
    """

    evidence_id: str
    plugin_name: PluginName
    extraction_id: str
    record_count: int = Field(ge=0)
    extraction_sha256: str = Field(pattern=_HEX64_PATTERN)
    extractions_chain_line: int = Field(ge=1)
    audit_line: int | None = Field(default=None, ge=1)
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
    # Added 2026-05-06 (audit_line plumbing). Optional / nullable for
    # backward compatibility with the 3 extractions.jsonl lines written
    # before this field existed. New writes always populate it; legacy
    # reads default to None. Migration approach: nullable, no
    # retroactive backfill — see docs/decisions-log.md.
    audit_line: int | None = Field(default=None, ge=1)
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
    # The keys of `top_image_names` are running-process image names,
    # i.e. evidence-derived strings the agent must treat as data.
    # Counts and the rest of the summary are aggregates, not raw
    # evidence. Synthetic name `top_image_names_keys` because the
    # untrusted axis is the tuples' first element, not the field as a
    # whole. See `untrusted_fields_for` and PLUGIN_UNTRUSTED_RECORD_FIELDS.
    untrusted_fields: list[str] = Field(
        default_factory=lambda: ["top_image_names_keys"]
    )


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
    # PstreeSummary surfaces only counts, depth integers, and
    # (root_pid, descendant_count) — no evidence-derived strings.
    # Default empty per the schema-level contract; actual pstree
    # process names / paths are reached via the `subtree` tier-2 tool,
    # which carries its own non-empty list.
    untrusted_fields: list[str] = Field(default_factory=list)


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
    # NetscanSummary's keys are protocol literals (TCPv4/TCPv6/UDPv4/
    # UDPv6 — schema-bounded enum) and TCP state strings derived from
    # kernel state-machine values, not free-form attacker-controllable
    # strings. The evidence-derived address / owner content surfaces
    # only via tier-2 `query_records` against the netscan extraction;
    # that tool's `untrusted_fields` is non-empty.
    untrusted_fields: list[str] = Field(default_factory=list)


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

    `audit_line` is the audit-chain line number for THIS query_records
    invocation. The analyst uses it directly when constructing an
    `EvidenceRef` for `record_finding` — eliminates the probe-finding
    pattern observed in process_analyst v2 (failure mode #1 in
    `docs/accuracy-report.md`).
    """

    extraction: ExtractionRef
    audit_line: int = Field(ge=1)
    matched_count: int = Field(ge=0)
    returned_count: int = Field(ge=0)
    records: list[dict]
    truncated: bool
    # Names of fields within `records` that contain evidence-derived
    # strings. Computed by the tool from the source plugin's
    # PLUGIN_UNTRUSTED_RECORD_FIELDS entry, intersected with the
    # `fields` projection actually applied — when the agent projects
    # away every untrusted field, this list is empty. Default empty
    # at the schema level; the tool always populates explicitly.
    untrusted_fields: list[str] = Field(default_factory=list)


class GroupByResult(BaseModel):
    """Tier-2 return for `group_by`.

    `groups` is a list of `(value, count)` tuples sorted descending by
    count, capped at `top_n`. `distinct_values` is the full count of
    unique field values across the extraction (post-filter); a high
    `distinct_values` with a short `groups` list tells the agent the
    field is high-cardinality.

    `audit_line` carries the audit-chain line for THIS call (same
    contract as `QueryRecordsResult.audit_line`).
    """

    extraction: ExtractionRef
    audit_line: int = Field(ge=1)
    field: str
    total_records: int = Field(ge=0)
    distinct_values: int = Field(ge=0)
    groups: list[tuple[Any, int]]
    # Synthetic name `groups_keys`: the untrusted axis is the first
    # element of each tuple in `groups` (the grouped value). Set when
    # `field` is in the source plugin's untrusted-record-field set
    # (e.g. group_by image_file_name on pslist), empty otherwise
    # (e.g. group_by pid). Counts are integer aggregates, not raw
    # evidence.
    untrusted_fields: list[str] = Field(default_factory=list)


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
    audit_line: int = Field(ge=1)
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
    # Inherits from the source plugin's untrusted-record-field set,
    # restricted to fields actually present in `returned_records`. The
    # source plugin is plugin_a for `a_minus_b` / `symmetric` and
    # plugin_b for `b_minus_a` (whichever side the records are pulled
    # from). When `fields` projects everything away, this list is empty.
    untrusted_fields: list[str] = Field(default_factory=list)


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
    audit_line: int = Field(ge=1)
    root_pid: int = Field(ge=0)
    root_found: bool
    depth_traversed: int = Field(ge=0)
    descendant_count: int = Field(ge=0)
    nodes: list[dict]
    truncated: bool
    # Pstree-only by construction; the per-plugin set is the
    # ProcessTreeRecord untrusted fields (image_file_name, audit, cmd,
    # path), restricted to fields actually present in `nodes` after
    # the call's `fields` projection.
    untrusted_fields: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Validator substrate (week 6) — correlations
#
# `record_correlation` is the MCP tool the validator subagent (Prompt B's
# deliverable) calls to commit a cross-source / cross-plugin observation
# about one or more findings. Five correlation types, each a separate
# pydantic model, joined under a discriminated union on `correlation_type`.
# The substrate validates per-type required fields, the audit-line
# provenance of `evidence_refs`, and the existence of every referenced
# `finding_id` in `findings.jsonl` — same architectural principle as
# `record_finding` (the agent cannot drift away from the contract).
#
# Three writers, three roles, three chains:
#   - Analysts → record_finding → findings.jsonl (DRAFT only)
#   - Validator → record_correlation → correlations.jsonl (NEW)
#   - Orchestrator → update_finding → findings.jsonl (UPDATE entries,
#     same chain as DRAFT, distinguished by `record_kind`)
#
# correlations.jsonl is its own hash chain. Distinct field names
# (`prev_correlation_hash` / `this_correlation_hash`) so a line read out
# of context cannot be silently misinterpreted as an audit / findings /
# extractions line.
# ---------------------------------------------------------------------------


class CorrelationType(StrEnum):
    """Discriminator on `correlations.jsonl` line payloads.

    Five validator outputs:
      - `corroborates` — N findings agree on the same target (e.g.,
        process_analyst's hidden-PID claim is corroborated by the
        psscan/pslist set-diff and the pool-tag aliasing observation).
        Carries `target_finding_ids` (≥1) and a `strength`.
      - `contradicts` — two findings make incompatible claims about
        the same artifact (e.g., one says PID X is hidden, another
        says PID X is canonical). Carries `finding_a_id` /
        `finding_b_id` plus a `severity` and a `resolvable_by_followup`
        hint.
      - `strengthens` — one new piece of evidence strengthens an
        existing finding without rising to the structural bar of
        `corroborates`.
      - `weakens` — one new piece of evidence weakens an existing
        finding without rising to `contradicts`.
      - `request_followup` — the validator requests that a named
        analyst re-run with a focus context (e.g., "process_analyst
        re-examine PID 7900 with handles + cmdline"). Carries the
        `target_analyst`, the related `finding_ids`, a structured
        `focus_context`, and a free-form `rationale`. The orchestrator
        consumes these to dispatch the next iteration.
    """

    CORROBORATES = "corroborates"
    CONTRADICTS = "contradicts"
    STRENGTHENS = "strengthens"
    WEAKENS = "weakens"
    REQUEST_FOLLOWUP = "request_followup"


CorrelationStrength = Literal["weak", "moderate", "strong"]
ContradictionSeverity = Literal["minor", "material", "fundamental"]
FollowupTargetAnalyst = Literal["process_analyst", "network_analyst"]


class _BaseCorrelation(BaseModel):
    """Common fields for every correlation. Not directly written —
    every correlation lands in `correlations.jsonl` as one of the five
    concrete subtypes below.

    Server-controlled fields:
      - `correlation_id` is generated by the server (UUIDv4); the agent
        does not supply it.
      - `created_at` is set to the tool-call timestamp.
      - `audit_line` is the audit-chain line for this
        `record_correlation` call's success entry — same provenance
        pattern as tier-2 results.
    """

    correlation_id: str
    case_id: str = Field(min_length=1, max_length=200)
    iteration_number: int = Field(ge=0)
    created_at: datetime
    audit_line: int = Field(ge=1)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)
    hypothesis: str = Field(min_length=50, max_length=1000)

    @field_validator("correlation_id")
    @classmethod
    def _validate_correlation_uuid(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"correlation_id must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"correlation_id must be UUID version 4, got version "
                f"{parsed.version}"
            )
        return str(parsed)

    @field_validator("created_at")
    @classmethod
    def _validate_correlation_created_at(cls, v: datetime) -> datetime:
        return _enforce_utc("created_at", v)


def _validate_uuid4_list(v: list[str], field_name: str) -> list[str]:
    for item in v:
        try:
            parsed = UUID(item)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"{field_name} entries must be UUID strings, got {item!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"{field_name} entries must be UUID v4, got version "
                f"{parsed.version}"
            )
    return v


class CorroboratesCorrelation(_BaseCorrelation):
    """N findings agree on the same target. `target_finding_ids` lists
    every finding the correlation supports. `strength` is the
    validator's qualitative read of how strong the agreement is —
    cross-source HIGH and cross-plugin HIGH are both "strong" reads
    earned via different evidence patterns.
    """

    correlation_type: Literal[CorrelationType.CORROBORATES] = (
        CorrelationType.CORROBORATES
    )
    target_finding_ids: list[str] = Field(min_length=1)
    strength: CorrelationStrength

    @field_validator("target_finding_ids")
    @classmethod
    def _validate_target_uuids(cls, v: list[str]) -> list[str]:
        return _validate_uuid4_list(v, "target_finding_ids")


class ContradictsCorrelation(_BaseCorrelation):
    """Two findings make incompatible claims about the same artifact.
    `severity` distinguishes "minor" disagreement (one finding's
    confidence should drop) from "fundamental" disagreement (the two
    findings cannot both be true; the orchestrator must pick one).
    `resolvable_by_followup` flags whether a re-run with a different
    tool surface could resolve the contradiction without human
    intervention.
    """

    correlation_type: Literal[CorrelationType.CONTRADICTS] = (
        CorrelationType.CONTRADICTS
    )
    finding_a_id: str
    finding_b_id: str
    severity: ContradictionSeverity
    resolvable_by_followup: bool

    @field_validator("finding_a_id", "finding_b_id")
    @classmethod
    def _validate_finding_uuid(cls, v: str, info) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"{info.field_name} must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"{info.field_name} must be UUID v4, got version "
                f"{parsed.version}"
            )
        return str(parsed)


class StrengthensCorrelation(_BaseCorrelation):
    """One new piece of evidence strengthens an existing finding
    without rising to the structural bar of `corroborates` (which
    requires multiple agreeing findings)."""

    correlation_type: Literal[CorrelationType.STRENGTHENS] = (
        CorrelationType.STRENGTHENS
    )
    target_finding_id: str

    @field_validator("target_finding_id")
    @classmethod
    def _validate_target_uuid(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"target_finding_id must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"target_finding_id must be UUID v4, got version "
                f"{parsed.version}"
            )
        return str(parsed)


class WeakensCorrelation(_BaseCorrelation):
    """One new piece of evidence weakens an existing finding without
    rising to the structural bar of `contradicts` (which requires a
    second finding making an incompatible claim)."""

    correlation_type: Literal[CorrelationType.WEAKENS] = (
        CorrelationType.WEAKENS
    )
    target_finding_id: str

    @field_validator("target_finding_id")
    @classmethod
    def _validate_target_uuid_w(cls, v: str) -> str:
        try:
            parsed = UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"target_finding_id must be a UUID string, got {v!r}"
            ) from exc
        if parsed.version != 4:
            raise ValueError(
                f"target_finding_id must be UUID v4, got version "
                f"{parsed.version}"
            )
        return str(parsed)


class RequestFollowupCorrelation(_BaseCorrelation):
    """The validator requests that a named analyst re-run with a
    focus context. The orchestrator consumes these to dispatch the
    next iteration of the self-correction loop. `focus_context` is
    a structured dict (e.g., `{"pids": [7900], "image_names": [...]}`)
    rather than free-form text so the orchestrator can pass it to
    the analyst as typed input rather than having to parse a
    paragraph."""

    correlation_type: Literal[CorrelationType.REQUEST_FOLLOWUP] = (
        CorrelationType.REQUEST_FOLLOWUP
    )
    target_analyst: FollowupTargetAnalyst
    related_finding_ids: list[str] = Field(min_length=1)
    focus_context: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=20, max_length=1000)

    @field_validator("related_finding_ids")
    @classmethod
    def _validate_related_uuids(cls, v: list[str]) -> list[str]:
        return _validate_uuid4_list(v, "related_finding_ids")


# Discriminated union for `correlations.jsonl` line payloads. The
# `correlation_type` field is the discriminator; pydantic dispatches
# to the matching variant by the literal value.
CorrelationPayload = Annotated[
    Union[
        CorroboratesCorrelation,
        ContradictsCorrelation,
        StrengthensCorrelation,
        WeakensCorrelation,
        RequestFollowupCorrelation,
    ],
    Field(discriminator="correlation_type"),
]


class CorrelationChainEntry(BaseModel):
    """One JSONL line of the hash-chained correlations log.

    Mirrors `AuditLogEntry` and `FindingChainEntry` chain semantics:
    `prev_correlation_hash` is the previous record's
    `this_correlation_hash`, or 64 zeros for genesis;
    `this_correlation_hash` is sha256 over a canonical JSON
    serialization of every other field.

    Distinct hash field names (not `prev_line_hash` / `this_line_hash`)
    so a line read out of context cannot be silently misinterpreted as
    an audit chain line. Same convention as the findings and
    extractions chains.
    """

    line_number: int = Field(ge=1)
    timestamp: datetime
    correlation: CorrelationPayload
    prev_correlation_hash: str = Field(pattern=_HEX64_PATTERN)
    this_correlation_hash: str = Field(pattern=_HEX64_PATTERN)

    @field_validator("timestamp")
    @classmethod
    def _validate_correlation_chain_timestamp(cls, v: datetime) -> datetime:
        return _enforce_utc("timestamp", v)

    @classmethod
    def compute_this_correlation_hash(cls, **fields: Any) -> str:
        """Deterministic sha256 over all fields except
        `this_correlation_hash`. Same canonical-form rule as
        `AuditLogEntry.compute_this_line_hash`: sorted JSON keys, ISO
        timestamps, enum values rendered as strings.
        """
        payload = {
            k: v for k, v in fields.items() if k != "this_correlation_hash"
        }
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "AnalystName",
    "ArtifactClass",
    "AuditLogEntry",
    "ContradictionSeverity",
    "ContradictsCorrelation",
    "CorroboratesCorrelation",
    "CorrelationChainEntry",
    "CorrelationPayload",
    "CorrelationStrength",
    "CorrelationType",
    "DraftFinding",
    "EvidenceRecord",
    "EvidenceRef",
    "EvidenceRefSourceTool",
    "ExtractionChainEntry",
    "ExtractionRef",
    "FieldFilter",
    "FindingCategory",
    "FindingChainEntry",
    "FindingChainPayload",
    "FindingConfidence",
    "FindingRecordKind",
    "FindingSeverity",
    "FindingState",
    "FindingUpdate",
    "FollowupTargetAnalyst",
    "GroupByResult",
    "NetscanResult",
    "NetscanSummary",
    "NetworkRecord",
    "PLUGIN_UNTRUSTED_RECORD_FIELDS",
    "PluginName",
    "ProcessRecord",
    "ProcessScanRecord",
    "ProcessTreeRecord",
    "PromotionRule",
    "PslistResult",
    "PslistSummary",
    "PsscanResult",
    "PsscanSummary",
    "PstreeResult",
    "PstreeSummary",
    "QueryRecordsResult",
    "RequestFollowupCorrelation",
    "SetDifferenceResult",
    "StrengthensCorrelation",
    "SubtreeResult",
    "UntrustedString",
    "WeakensCorrelation",
    "untrusted_fields_for",
]
