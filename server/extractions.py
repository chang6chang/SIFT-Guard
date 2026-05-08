"""Storage layer for tier-1 Volatility extractions.

Tier-1 tools (`vol_pslist`, `vol_psscan`, `vol_pstree`, `vol_netscan`)
persist their full Volatility output here once per (evidence_id,
plugin_name) pair. Cache contract: re-invoking a tier-1 tool against an
already-extracted pair returns the stored summary without re-running
Volatility, audited as `<tool>:cached`. Tampering with a stored
extraction (.json bytes don't match the chain's recorded sha256 or the
.sha256 sidecar) is detected at cache-read time and bubbles as
`HashMismatchError`, which the tier-1 wrapper translates into a
`<tool>:hash_mismatch` audit line and a sanitized `ValueError`.

Layout:

  <case_dir>/
    extractions/
      <evidence_id>/
        windows.pslist.PsList.json     # full PslistResult (model_dump_json)
        windows.pslist.PsList.sha256   # hex64 of the .json bytes
        windows.psscan.PsScan.json
        windows.psscan.PsScan.sha256
        ...
    extractions.jsonl                  # hash-chained provenance log

Every successful tier-1 invocation produces exactly one new
`extractions.jsonl` line. Cache hits do not extend the chain (only the
audit chain records cache hits, with `tool_name=<tool>:cached`).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from server.extractions_log import append_extraction_entry, find_extraction_entry
from server.schemas import ExtractionChainEntry, ExtractionRef, PluginName

_EXTRACTIONS_SUBDIR = "extractions"


class ExtractionNotFoundError(LookupError):
    """No stored extraction exists for the given (evidence_id, plugin_name)."""


class HashMismatchError(RuntimeError):
    """Tampering detected — stored extraction does not hash to its sidecar
    or chain-recorded hash.

    Raised by `load_extraction` when any of:
      - the .json bytes do not match the .sha256 sidecar
      - the .json bytes do not match the extractions chain entry's
        `extraction_sha256`
      - the .sha256 sidecar does not match the chain entry's
        `extraction_sha256`

    All three are forms of tampering; we audit them under the same
    rejection reason at the tier-1 boundary so the agent sees one
    sanitized error regardless of which file diverged.
    """


def _extraction_dir(case_dir: Path, evidence_id: str) -> Path:
    return case_dir / _EXTRACTIONS_SUBDIR / evidence_id


def _json_path(case_dir: Path, evidence_id: str, plugin_name: str) -> Path:
    return _extraction_dir(case_dir, evidence_id) / f"{plugin_name}.json"


def _sha256_sidecar_path(
    case_dir: Path, evidence_id: str, plugin_name: str
) -> Path:
    return _extraction_dir(case_dir, evidence_id) / f"{plugin_name}.sha256"


def extraction_exists(
    case_dir: Path | str,
    evidence_id: str,
    plugin_name: str,
) -> bool:
    """True iff all three artifacts exist: .json, .sha256, and a chain line.

    A partial state (e.g., .json present but no chain line) is treated as
    "does not exist" so the caller falls back to the fresh-run path.
    Repairing a partial write is operator-tooling territory, not a
    runtime concern.
    """
    case_dir_path = Path(case_dir).resolve()
    json_path = _json_path(case_dir_path, evidence_id, plugin_name)
    sidecar_path = _sha256_sidecar_path(case_dir_path, evidence_id, plugin_name)
    if not (json_path.exists() and sidecar_path.exists()):
        return False
    return find_extraction_entry(case_dir_path, evidence_id, plugin_name) is not None


def _read_sidecar(sidecar_path: Path) -> str:
    """Read a .sha256 sidecar. Format: `<hex64>\n`. Strips whitespace."""
    return sidecar_path.read_text(encoding="utf-8").strip()


def write_extraction(
    case_dir: Path | str,
    evidence_id: str,
    plugin_name: PluginName,
    result: BaseModel,
    runtime_seconds: float,
    audit_line: int | None = None,
) -> ExtractionRef:
    """Persist a tier-1 Volatility result.

    Writes the .json (`result.model_dump_json()` bytes) and the .sha256
    sidecar, then appends one line to `extractions.jsonl`. Returns an
    `ExtractionRef` carrying `cached=False`, `runtime_seconds`
    populated, and `extraction_id` server-generated. The `record_count`
    is read from `result.processes` or `result.connections` — whichever
    list field the model carries.

    Idempotency: refuses to overwrite an existing extraction. Callers
    must check `extraction_exists` first; the tier-1 wrappers do this
    in their cache-hit branch.

    Atomicity caveat: the three writes (.json → .sha256 → chain line)
    are not atomic across a process crash. On crash recovery,
    `extraction_exists` returns False if any artifact is missing, so a
    partial state degrades to "no extraction" and the next call
    re-runs Volatility cleanly.
    """
    case_dir_path = Path(case_dir).resolve()
    extraction_dir = _extraction_dir(case_dir_path, evidence_id)
    json_path = _json_path(case_dir_path, evidence_id, plugin_name)
    sidecar_path = _sha256_sidecar_path(case_dir_path, evidence_id, plugin_name)

    if json_path.exists() or sidecar_path.exists():
        raise FileExistsError(
            f"extraction already exists for ({evidence_id}, {plugin_name})"
        )

    extraction_dir.mkdir(parents=True, exist_ok=True)

    payload = result.model_dump_json().encode("utf-8")
    sha256 = hashlib.sha256(payload).hexdigest()

    record_list = _record_list_from_result(result)
    record_count = len(record_list)
    extraction_id = str(uuid4())

    with json_path.open("wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    with sidecar_path.open("w", encoding="utf-8") as f:
        f.write(sha256 + "\n")
        f.flush()
        os.fsync(f.fileno())

    chain_entry: ExtractionChainEntry = append_extraction_entry(
        case_dir=case_dir_path,
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        extraction_id=extraction_id,
        extraction_sha256=sha256,
        record_count=record_count,
        runtime_seconds=runtime_seconds,
        audit_line=audit_line,
    )

    return ExtractionRef(
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        extraction_id=extraction_id,
        record_count=record_count,
        extraction_sha256=sha256,
        extractions_chain_line=chain_entry.line_number,
        audit_line=audit_line,
        runtime_seconds=runtime_seconds,
        cached=False,
    )


def load_extraction(
    case_dir: Path | str,
    evidence_id: str,
    plugin_name: PluginName,
) -> tuple[ExtractionRef, dict]:
    """Read a stored extraction; verify it has not been tampered with.

    Returns `(ExtractionRef, parsed_json_dict)`:
      - `ExtractionRef.cached=True`
      - `ExtractionRef.runtime_seconds=None` per the cache contract
      - `extraction_id` and `extractions_chain_line` come from the chain

    Raises:
      - `ExtractionNotFoundError` when no chain entry exists.
      - `HashMismatchError` when any pair of (.json bytes / .sha256
        sidecar / chain.extraction_sha256) disagrees.

    The .json is parsed into a plain dict (not a pydantic model) — the
    analytical tools introspect the records list directly, and
    re-validating thousands of rows on every cache read is wasted work
    when the sha256 already proves the bytes are intact.
    """
    case_dir_path = Path(case_dir).resolve()
    chain_entry = find_extraction_entry(
        case_dir_path, evidence_id, plugin_name
    )
    if chain_entry is None:
        raise ExtractionNotFoundError(
            f"no chain entry for ({evidence_id}, {plugin_name})"
        )

    json_path = _json_path(case_dir_path, evidence_id, plugin_name)
    sidecar_path = _sha256_sidecar_path(case_dir_path, evidence_id, plugin_name)
    if not json_path.exists() or not sidecar_path.exists():
        raise ExtractionNotFoundError(
            f"chain entry present but artifacts missing for "
            f"({evidence_id}, {plugin_name})"
        )

    payload = json_path.read_bytes()
    computed_sha256 = hashlib.sha256(payload).hexdigest()
    sidecar_sha256 = _read_sidecar(sidecar_path)

    if (
        computed_sha256 != chain_entry.extraction_sha256
        or sidecar_sha256 != chain_entry.extraction_sha256
    ):
        raise HashMismatchError(
            f"extraction hash mismatch for ({evidence_id}, {plugin_name})"
        )

    parsed = json.loads(payload.decode("utf-8"))

    ref = ExtractionRef(
        evidence_id=evidence_id,
        plugin_name=plugin_name,
        extraction_id=chain_entry.extraction_id,
        record_count=chain_entry.record_count,
        extraction_sha256=chain_entry.extraction_sha256,
        extractions_chain_line=chain_entry.line_number,
        audit_line=chain_entry.audit_line,
        runtime_seconds=None,
        cached=True,
    )
    return ref, parsed


def _record_list_from_result(result: BaseModel) -> list:
    """Pull the records list from a tier-1 result model.

    Tier-1 result models name their records list differently across
    plugin families:

      - ``processes``  — pslist, psscan, pstree, cmdline
      - ``connections`` — netscan
      - ``detections`` — malfind
      - ``entries``    — disk MFT timeline, disk prefetch
      - ``events``     — disk evtx
      - ``keys``       — disk registry

    Centralizing the lookup here keeps ``write_extraction``
    model-agnostic so a future tier-1 plugin can plug in by reusing
    one of the conventions (or by adding a new branch here) without
    touching the storage layer.
    """
    for field_name in ("processes", "connections", "detections",
                       "entries", "events", "keys"):
        if hasattr(result, field_name):
            return list(getattr(result, field_name))
    raise TypeError(
        f"tier-1 result {type(result).__name__} carries no recognized "
        "record list (processes / connections / detections / entries / "
        "events / keys)"
    )


__all__ = [
    "ExtractionNotFoundError",
    "HashMismatchError",
    "extraction_exists",
    "load_extraction",
    "write_extraction",
]
