"""Hash-chained JSONL writer for SIFT-Guard correlations.

Correlations written by `record_correlation` land in
`<case_dir>/correlations.jsonl` as one wrapper line per correlation.
Each line carries the sha256 of the previous line's
`this_correlation_hash` in `prev_correlation_hash`, and its own
`this_correlation_hash` is sha256 over a canonical serialization of
the rest of the record. Same tamper-evident-chain property as
`server/audit.py` and `server/findings_log.py`.

Why a separate file (and a separate writer) from the audit and
findings chains:

  - The audit chain records *what the server's parent process did*:
    every MCP tool invocation, including rejections.
  - The findings chain records *what analysts (and the orchestrator)
    claim about the case*: DRAFT findings + UPDATE promotions, both
    distinguished by `record_kind`.
  - The correlations chain records *what the validator observes about
    those findings*: corroborations, contradictions,
    strengthens/weakens, follow-up requests.
  - Distinct on-disk files mean a downstream consumer can stream one
    without parsing the others.
  - Distinct hash field names (`prev_correlation_hash` /
    `this_correlation_hash`) mean a line accidentally read from one
    file cannot be silently misinterpreted as the other.

Three writers, three roles, three chains — the substrate the week-6
validator + orchestrator consume. No shared `HashChainedJsonl` base
class yet: per the standing convention (CLAUDE.md "three similar
lines is better than premature abstraction"), three consumers
triggers extraction; that lands as a separate commit AFTER this
substrate ships and tests pass.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from server.schemas import (
    CorrelationChainEntry,
    CorroboratesCorrelation,
    ContradictsCorrelation,
    RequestFollowupCorrelation,
    StrengthensCorrelation,
    WeakensCorrelation,
)

_CORRELATIONS_FILENAME = "correlations.jsonl"
_GENESIS_PREV_HASH = "0" * 64

# The five concrete correlation types. Type-narrowing helper for the
# `correlation` argument to `append_correlation_entry` so the writer
# accepts any concrete subtype without needing the discriminated-union
# wrapper at the call site.
_AnyCorrelation = (
    CorroboratesCorrelation
    | ContradictsCorrelation
    | StrengthensCorrelation
    | WeakensCorrelation
    | RequestFollowupCorrelation
)


def _read_chain_state(correlations_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_correlation_hash) for the next
    append. Mirrors `findings_log._read_chain_state` exactly.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the next
    line number is one greater than the count of non-blank lines, and
    the previous-hash comes from the last non-blank line's
    `this_correlation_hash`.
    """
    if not correlations_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with correlations_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_correlation_hash"]


def append_correlation_entry(
    case_dir: Path | str, correlation: _AnyCorrelation
) -> CorrelationChainEntry:
    """Append one hash-chained record to
    `<case_dir>/correlations.jsonl`.

    Returns the constructed `CorrelationChainEntry` so the caller can
    digest it for the audit-chain `output_hash` without re-reading the
    on-disk line — same convention as `findings_log.append_finding_entry`.

    Single-process server: no file lock. If a future multi-process
    design is needed, wrap this call in a writer-process queue rather
    than layering fcntl into the public path — keeping the writer
    trivial is what makes the chain easy to audit by hand.
    """
    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)
    correlations_path = case_dir_path / _CORRELATIONS_FILENAME

    line_number, prev_correlation_hash = _read_chain_state(correlations_path)
    timestamp = datetime.now(tz=timezone.utc)

    chained_fields = dict(
        line_number=line_number,
        timestamp=timestamp,
        correlation=correlation.model_dump(mode="json"),
        prev_correlation_hash=prev_correlation_hash,
    )
    this_correlation_hash = CorrelationChainEntry.compute_this_correlation_hash(**chained_fields)

    entry = CorrelationChainEntry(
        line_number=line_number,
        timestamp=timestamp,
        correlation=correlation,
        prev_correlation_hash=prev_correlation_hash,
        this_correlation_hash=this_correlation_hash,
    )

    serialized = entry.model_dump_json()
    with correlations_path.open("a", encoding="utf-8") as f:
        f.write(serialized + "\n")
        f.flush()
        os.fsync(f.fileno())

    return entry


def read_correlation_ids(case_dir: Path | str) -> set[str]:
    """Return the set of every `correlation_id` ever written to
    `<case_dir>/correlations.jsonl`.

    Used by `update_finding` to validate `driving_correlation_ids`
    against the live correlations chain. Streamed line-by-line to keep
    memory bounded; malformed lines are skipped silently — id lookup
    is a provenance check, not a chain integrity verification.
    """
    case_dir_path = Path(case_dir).resolve()
    correlations_path = case_dir_path / _CORRELATIONS_FILENAME
    if not correlations_path.exists():
        return set()

    ids: set[str] = set()
    with correlations_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            corr = row.get("correlation")
            if isinstance(corr, dict):
                cid = corr.get("correlation_id")
                if isinstance(cid, str):
                    ids.add(cid)
    return ids


__all__ = ["append_correlation_entry", "read_correlation_ids"]
