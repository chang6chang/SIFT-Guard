"""CaseManifest pydantic models + JSON persistence.

The manifest is an orchestrator-side per-case organization layer
that sits ON TOP of `CASE.yaml` (which is the registration ledger).
Each `EvidenceFile` references an `evidence_id` that has been
registered into `CASE.yaml` via `register_evidence`; the manifest
groups those evidence_ids into `HostEvidence` blocks so
multi-evidence (`run-case`) orchestration can dispatch the right
analysts per evidence_type and group findings by host_id for
cross-host correlation.

Scope: this module is data-model + persistence only. The grouping
heuristic + magic-byte detection live in `orchestrator.inventory`.

Two-file relationship:

  CASE.yaml          (registration ledger; canonical evidence records)
    case_id, evidence: [EvidenceRecord, ...]

  case-data/manifest.json  (orchestrator-side host grouping)
    case_id, hosts: [HostEvidence, ...], created_at

Both files coexist; the manifest references the ledger by
evidence_id. The manifest is rewritten by every `run-case`
invocation (it reflects the operator's current scan), while
CASE.yaml is append-only across the case lifecycle (registrations
never disappear).
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# Closed Literal of evidence-type tags. Mirrors (but is narrower
# than) `server.schemas.ArtifactClass` because the manifest's job is
# to drive analyst dispatch, not to track every artifact family. A
# disk_image / triage_zip / registry_hive all surface here as
# "disk" (the disk_analyst's stack handles them); a memory_image
# surfaces as "memory"; anything else surfaces as "unknown" and is
# skipped at dispatch time with a warning.
EvidenceType = Literal["memory", "disk", "unknown"]


_HOST_ID_PATTERN = r"^[A-Za-z0-9._-]+$"


class EvidenceFile(BaseModel):
    """One registered evidence file under a host.

    `evidence_id` resolves to `CASE.yaml`; `file_path` is the
    absolute path the operator pointed `register_evidence` at.
    `evidence_type` is the orchestrator's narrower bucket
    (memory / disk / unknown) — see module docstring.
    """

    evidence_id: str = Field(min_length=1, max_length=128)
    file_path: str = Field(min_length=1)
    evidence_type: EvidenceType
    os_guess: str | None = Field(default=None, max_length=128)
    file_size_bytes: int = Field(ge=0)


class HostEvidence(BaseModel):
    """All evidence files attributed to one host.

    `host_id` is the stable identifier the orchestrator injects into
    analyst prompts and that the analyst passes to record_finding's
    host_id parameter. It must round-trip through filename text and
    process command lines, so it is restricted to alphanumerics, dot,
    underscore, hyphen.

    `host_label` is the human-readable name the operator might use
    in a report. It is free-form — no character restriction beyond
    a length cap.
    """

    host_id: str = Field(min_length=1, max_length=128, pattern=_HOST_ID_PATTERN)
    host_label: str = Field(min_length=1, max_length=256)
    evidence_files: list[EvidenceFile] = Field(min_length=1)

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_files)


class CaseManifest(BaseModel):
    """The full per-case manifest produced by `run-case`'s scan +
    register pass. Persisted to `case-data/manifest.json`.

    `case_id` matches `CASE.yaml`'s `case_id` (the case directory
    name). `hosts` is the per-host grouping; `created_at` is when
    the manifest was assembled.
    """

    case_id: str = Field(min_length=1, max_length=200)
    hosts: list[HostEvidence] = Field(default_factory=list)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (UTC)")
        return v

    @property
    def evidence_count(self) -> int:
        return sum(len(h.evidence_files) for h in self.hosts)


_MANIFEST_FILENAME = "manifest.json"


def manifest_path(case_dir: Path | str) -> Path:
    """Return the canonical path of the manifest file under
    `<case_dir>/manifest.json`."""
    return Path(case_dir) / _MANIFEST_FILENAME


def write_manifest(manifest: CaseManifest, case_dir: Path | str) -> Path:
    """Persist the manifest as pretty-printed JSON, fsync'd.

    Overwrites any existing manifest — the file is per-`run-case`
    invocation, not append-only. The on-disk JSON is loadable via
    `read_manifest` for the loop's per-iteration reads.
    """
    out = manifest_path(case_dir)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.model_dump_json(indent=2)
    with out.open("w", encoding="utf-8") as f:
        f.write(payload)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    return out


def read_manifest(case_dir: Path | str) -> CaseManifest:
    """Load + validate the manifest. Raises FileNotFoundError if no
    manifest exists for the case (single-evidence runs do not produce
    one)."""
    src = manifest_path(case_dir)
    if not src.exists():
        raise FileNotFoundError(f"no manifest at {src} — run-case mode produces this file")
    return CaseManifest.model_validate_json(src.read_text(encoding="utf-8"))


def manifest_exists(case_dir: Path | str) -> bool:
    """Cheap pre-check for the loop's mode-detection fork."""
    return manifest_path(case_dir).exists()


__all__ = [
    "CaseManifest",
    "EvidenceFile",
    "EvidenceType",
    "HostEvidence",
    "manifest_exists",
    "manifest_path",
    "read_manifest",
    "write_manifest",
]
