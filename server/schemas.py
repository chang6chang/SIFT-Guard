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


__all__ = [
    "ArtifactClass",
    "AuditLogEntry",
    "EvidenceRecord",
    "ProcessRecord",
    "ProcessScanRecord",
    "PslistResult",
    "PsscanResult",
    "UntrustedString",
]
