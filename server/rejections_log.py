"""Side-channel debug log for rejected MCP tool calls.

The hash-chained audit log at ``audit/sift-guard-mcp.jsonl`` stores
only the ``input_hash`` of each tool call — the raw ``input_args``
are deliberately discarded so the chain stays compact and so the
"MCP error messages must not echo agent-supplied input" rule (see
CLAUDE.md, Hard Rules) is enforced by construction.

For the operator console that's the wrong trade-off: when an analyst's
``query_records`` is rejected as ``unknown_field``, the operator needs
to see *what field* was named in order to fix it (either correct the
schema allow-list or correct the analyst's prompt). With only the
hash, the console renders ``input=None`` and the operator is flying
blind.

This module writes a parallel, non-chained JSONL file at
``audit/rejections.jsonl`` containing a sanitized redaction of
``input_args`` for every rejection. Each line carries the
corresponding audit-chain ``line_number`` so the display can join the
two streams on a stable key. The file is non-chained — operators may
truncate or rotate it without breaking audit integrity — and stays
local to the case (no analyst tool ever reads it; the agent's
adversarial surface area is unchanged).

Sanitization rules (see ``_redact_input_args``):

* ``<evidence>...</evidence>`` substrings are replaced with
  ``<evidence redacted>`` — evidence-derived strings can carry
  attacker-controlled content per the prompt-injection model and we
  do not want any of it round-tripping through the console.
* Any string field longer than ``_MAX_STRING_LEN`` is truncated with
  a ``…`` suffix. Operators looking at this log want the shape of the
  offending input, not the full payload.
* Field name allow-list is intentionally absent: this is a debug
  channel for the operator, not a tool result returned to the agent.

The writer never raises — a write failure logs a warning and returns.
A missing rejections.jsonl on the display side is treated as "no
sanitized input available" and the line renders the same way it did
before this module existed.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.schemas import AuditLogEntry

logger = logging.getLogger(__name__)

_REJECTIONS_SUBDIR = "audit"
_REJECTIONS_FILENAME = "rejections.jsonl"
_MAX_STRING_LEN = 200
_EVIDENCE_BLOCK_RE = re.compile(
    r"<evidence\b[^>]*>.*?</evidence>", re.DOTALL | re.IGNORECASE
)
_EVIDENCE_REDACTION = "<evidence redacted>"


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        sanitized = _EVIDENCE_BLOCK_RE.sub(_EVIDENCE_REDACTION, value)
        if len(sanitized) > _MAX_STRING_LEN:
            return sanitized[: _MAX_STRING_LEN - 1] + "…"
        return sanitized
    if isinstance(value, dict):
        return {str(k): _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, tuple):
        return [_redact_value(v) for v in value]
    return value


def _redact_input_args(input_args: dict[str, Any] | None) -> dict[str, Any]:
    """Return a redacted shallow-or-nested copy of input_args.

    See module-level docstring for the rules. Always returns a dict
    even when the input is None or non-dict-typed — keeps the
    on-disk shape consistent for the consumer (display tail).
    """
    if not isinstance(input_args, dict):
        return {}
    return {str(k): _redact_value(v) for k, v in input_args.items()}


def append_rejection_record(
    case_dir: Path | str,
    audit_entry: AuditLogEntry,
    input_args: dict[str, Any] | None,
) -> None:
    """Append one redacted-input record to ``audit/rejections.jsonl``.

    ``audit_entry`` is the freshly-written audit-chain entry (its
    ``line_number`` and ``tool_name`` are mirrored here so the display
    can join on either). ``input_args`` is the raw args dict the
    rejecting tool received — passed through ``_redact_input_args``
    before being persisted.

    Best-effort: failures log a warning and return. We refuse to crash
    a tool's rejection path over a debug-log failure.
    """
    case_dir_path = Path(case_dir).resolve()
    target_dir = case_dir_path / _REJECTIONS_SUBDIR
    target_path = target_dir / _REJECTIONS_FILENAME
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("could not create %s: %s", target_dir, exc)
        return

    record = {
        "line_number": audit_entry.line_number,
        "timestamp": audit_entry.timestamp.astimezone(timezone.utc).isoformat(),
        "tool_name": audit_entry.tool_name,
        "evidence_id": audit_entry.evidence_id,
        "redacted_input": _redact_input_args(input_args),
    }
    try:
        with target_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        logger.warning("could not append rejection record to %s: %s", target_path, exc)


def iter_rejection_records(case_dir: Path | str) -> list[dict[str, Any]]:
    """Return all rejection records in append order (display helper).

    Bounded by the size of the on-disk file — the display tail uses
    this for one-shot reads when rendering an audit-chain rejection
    line, so a full scan is acceptable. If the file is missing or
    unreadable, returns an empty list.
    """
    target_path = Path(case_dir).resolve() / _REJECTIONS_SUBDIR / _REJECTIONS_FILENAME
    if not target_path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        with target_path.open("r", encoding="utf-8") as f:
            for raw in f:
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    out.append(json.loads(stripped))
                except ValueError:
                    continue
    except OSError as exc:
        logger.warning("could not read %s: %s", target_path, exc)
        return []
    return out


def _now_utc() -> datetime:
    """Module-level UTC clock — exposed so tests can monkey-patch it."""
    return datetime.now(tz=timezone.utc)


__all__ = [
    "append_rejection_record",
    "iter_rejection_records",
]
