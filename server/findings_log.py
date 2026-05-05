"""Hash-chained JSONL writer for SIFT-Guard findings.

Findings written by `record_finding` land in
`<case_dir>/findings.jsonl` as one wrapper line per finding. Each
line carries the sha256 of the previous line's `this_finding_hash`
in `prev_finding_hash`, and its own `this_finding_hash` is sha256
over a canonical serialization of the rest of the record. Same
tamper-evident-chain property as `server/audit.py`'s log.

Why a separate file (and a separate writer) from the audit chain:

  - The audit chain records *what the server's parent process did*:
    every MCP tool invocation, including rejections and warnings.
    Findings are *what analysts claim*, structurally distinct from
    "I observed a tool call".
  - Distinct on-disk files mean a downstream consumer can stream
    one without parsing the other.
  - Distinct hash field names (`prev_finding_hash` /
    `this_finding_hash` vs `prev_line_hash` / `this_line_hash`)
    mean a line accidentally read from one file cannot be silently
    misinterpreted as the other.

Why not extracted into a shared `HashChainedJsonl` base: the shared
core is ~30 lines and reshaping `audit.py` to expose a generic base
class would be heavier than the duplication. Per CLAUDE.md
"three similar lines is better than premature abstraction" — two
consumers do not yet justify the abstraction. If a third hash-chained
log lands later, revisit.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from server.schemas import DraftFinding, FindingChainEntry

_FINDINGS_FILENAME = "findings.jsonl"
_GENESIS_PREV_HASH = "0" * 64


def _read_chain_state(findings_path: Path) -> tuple[int, str]:
    """Return (next_line_number, prev_finding_hash) for the next append.

    For a missing or empty file the chain starts at line 1 with the
    genesis previous-hash (64 zeros). For a non-empty file the next
    line number is one greater than the count of non-blank lines, and
    the previous-hash comes from the last non-blank line's
    `this_finding_hash`.
    """
    if not findings_path.exists():
        return 1, _GENESIS_PREV_HASH

    last_line = ""
    line_count = 0
    with findings_path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if stripped:
                last_line = stripped
                line_count += 1

    if line_count == 0:
        return 1, _GENESIS_PREV_HASH

    prev_record = json.loads(last_line)
    return line_count + 1, prev_record["this_finding_hash"]


def append_finding_entry(
    case_dir: Path | str, finding: DraftFinding
) -> FindingChainEntry:
    """Append one hash-chained record to `<case_dir>/findings.jsonl`.

    Returns the constructed FindingChainEntry so the caller can
    digest it for the audit-chain `output_hash` without re-reading
    the on-disk line.

    Single-process server: no file lock. If a future multi-process
    design is needed, wrap this call in a writer-process queue rather
    than layering fcntl into the public path — keeping the writer
    trivial is what makes the chain easy to audit by hand.
    """
    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)
    findings_path = case_dir_path / _FINDINGS_FILENAME

    line_number, prev_finding_hash = _read_chain_state(findings_path)
    timestamp = datetime.now(tz=timezone.utc)

    chained_fields = dict(
        line_number=line_number,
        timestamp=timestamp,
        finding=finding.model_dump(mode="json"),
        prev_finding_hash=prev_finding_hash,
    )
    this_finding_hash = FindingChainEntry.compute_this_finding_hash(
        **chained_fields
    )

    entry = FindingChainEntry(
        line_number=line_number,
        timestamp=timestamp,
        finding=finding,
        prev_finding_hash=prev_finding_hash,
        this_finding_hash=this_finding_hash,
    )

    serialized = entry.model_dump_json()
    with findings_path.open("a", encoding="utf-8") as f:
        f.write(serialized + "\n")
        f.flush()
        os.fsync(f.fileno())

    return entry


__all__ = ["append_finding_entry"]
