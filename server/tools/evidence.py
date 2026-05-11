"""`register_evidence` — the only on-ramp for case data.

Per CLAUDE.md "Architectural enforcement of evidence integrity":

- compute SHA-256
- chmod the file to 0o444
- record the registration in CASE.yaml and the hash-chained audit log

This is the single point where arbitrary filesystem paths become
`evidence_id` handles. Every other MCP tool takes only `evidence_id` and
resolves through CASE.yaml — see CLAUDE.md "Ground truth isolation"
rule 3.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from server.audit import append_audit_entry
from server.schemas import ArtifactClass, EvidenceRecord


_DISK_EXTENSIONS = {".e01", ".aff4", ".vhdx", ".dd"}
_MEMORY_SIZE_THRESHOLD = 100 * 1024 * 1024  # 100 MB

_REGF_MAGIC = b"regf"
_EVTX_MAGIC = b"ElfFile\x00"
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_ZIP_MAGIC = b"PK\x03\x04"

_CHUNK_SIZE = 64 * 1024
_CASE_FILENAME = "CASE.yaml"
_FILE_MODE = 0o444


def _stream_sha256_and_magic(path: Path) -> tuple[str, bytes]:
    """Return (sha256_hex, first_16_bytes) in a single pass over the file.

    Streaming matters: Rocba-Memory.raw is 19 GB. Loading whole files into
    memory would OOM on any reasonable host. The first chunk size (64 KiB)
    is comfortably larger than every magic-byte signature we recognize, so
    one read suffices for both classification and hashing.
    """
    hasher = hashlib.sha256()
    magic_bytes = b""
    with path.open("rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            if not magic_bytes:
                magic_bytes = chunk[:16]
            hasher.update(chunk)
    return hasher.hexdigest(), magic_bytes


def _detect_artifact_class(path: Path, size_bytes: int, magic: bytes) -> ArtifactClass:
    extension = path.suffix.lower()

    # Magic-byte signatures take precedence over extension.
    if magic.startswith(_REGF_MAGIC):
        return ArtifactClass.REGISTRY_HIVE
    if magic.startswith(_EVTX_MAGIC) and extension == ".evtx":
        return ArtifactClass.EVENT_LOG
    if magic.startswith(_PCAP_MAGIC_BE) or magic.startswith(_PCAP_MAGIC_LE):
        return ArtifactClass.PCAP
    if extension == ".zip" and magic.startswith(_ZIP_MAGIC):
        return ArtifactClass.TRIAGE_ZIP

    # Extension-only classification (no reliable magic for these on disk).
    if extension in _DISK_EXTENSIONS:
        return ArtifactClass.DISK_IMAGE
    if extension == ".raw" and size_bytes > _MEMORY_SIZE_THRESHOLD:
        return ArtifactClass.MEMORY_IMAGE
    # FTK Imager split-image first segment (`.001`) — raw memory dumps
    # have no distinguishing magic so the classification leans on the
    # SRL-2015 / SANS Standard Forensic Case naming convention:
    # memory split images carry "memory" in the filename, disk split
    # images do not. Mirrors the heuristic in
    # `orchestrator.inventory._detect_evidence_type_by_extension`.
    if (
        extension == ".001"
        and "memory" in path.name.lower()
        and size_bytes > _MEMORY_SIZE_THRESHOLD
    ):
        return ArtifactClass.MEMORY_IMAGE

    return ArtifactClass.UNKNOWN


def _load_case_yaml(case_yaml_path: Path) -> dict:
    if not case_yaml_path.exists():
        return {}
    with case_yaml_path.open("r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f)
    return loaded or {}


def _write_case_yaml(case_yaml_path: Path, doc: dict) -> None:
    with case_yaml_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, default_flow_style=False, sort_keys=False)


def _find_existing_evidence_entry(
    doc: dict, absolute_path: str
) -> EvidenceRecord | None:
    """Return the CASE.yaml entry whose ``absolute_path`` matches, or None.

    Used by the idempotency skip path so a re-run of
    ``register_evidence`` against the same file doesn't re-hash
    50 GB of evidence. The match is exact-string on the resolved
    absolute path — same comparator the caller uses when writing
    the entry, so the round-trip is stable.
    """
    for entry in doc.get("evidence", []) or []:
        if entry.get("absolute_path") == absolute_path:
            try:
                return EvidenceRecord.model_validate(entry)
            except Exception:
                return None
    return None


def register_evidence(
    filepath: str,
    case_dir: str = "case-data",
    *,
    confine_to_evidence_dir: bool = True,
) -> EvidenceRecord:
    """Register one piece of evidence into the case directory.

    Sequence:
      0. (optional, default on) confine ``filepath`` to
         ``<case_dir>/evidence/`` (sanitized rejection)
      1. resolve and validate the path
      2. idempotency skip — if CASE.yaml already has an entry whose
         ``absolute_path`` matches and the file is mode 0o444 on disk,
         return the recorded EvidenceRecord without recomputing the
         SHA-256. Saves ~30 s per 16 GB image on a re-run.
      3. stream-hash sha256 and capture magic bytes in one pass
      4. detect artifact class
      5. mint UUID4 evidence_id
      6. chmod the file to 0o444
      7. append to (or create) CASE.yaml
      8. append a hash-chained line to the audit log
      9. return the EvidenceRecord

    ``confine_to_evidence_dir`` defaults to True — what the MCP-exposed
    tool enforces. Path confinement is a defense-in-depth check
    against prompt-injection-driven registration of arbitrary host
    files (CLAUDE.md "Ground truth isolation" rule 3). The orchestrator's
    own ``--no-copy`` flow sets it to False so the original evidence
    path (under ``/mnt/rocba/...`` or similar) is registered directly
    instead of forcing a 50 GB copy into ``<case_dir>/evidence/``.
    """
    # Step 0 — path confinement (defense-in-depth).
    # Sanitized message: never echo the offending path back to the agent
    # (decisions-log 2026-05-05, MCP error-message sanitization rule).
    case_dir_path = Path(case_dir).resolve(strict=False)
    path = Path(filepath).resolve(strict=False)
    if confine_to_evidence_dir:
        evidence_root = (case_dir_path / "evidence").resolve(strict=False)
        try:
            path.relative_to(evidence_root)
        except ValueError:
            raise PermissionError("Path outside evidence directory rejected")

    if not path.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Evidence path is not a regular file: {path}")

    # Step 2 — idempotency skip. Re-running `sift-guard analyze`
    # against an already-registered case (same case_dir, same
    # evidence files) should not pay the SHA-256 cost again. We
    # gate on TWO conditions so a stray chmod 444 on a foreign file
    # can't trick us into trusting an arbitrary CASE.yaml hit:
    #   (a) CASE.yaml already has an entry with this absolute_path.
    #   (b) The file is currently mode 0o444 — the post-registration
    #       state this function itself leaves files in.
    # Either one alone is insufficient; both together mean the file
    # was registered through this code path previously and remains
    # untouched on disk.
    case_yaml_path = case_dir_path / _CASE_FILENAME
    existing_doc = _load_case_yaml(case_yaml_path) if case_yaml_path.exists() else {}
    existing_record = _find_existing_evidence_entry(existing_doc, str(path))
    current_mode = path.stat().st_mode & 0o777
    if existing_record is not None and current_mode == _FILE_MODE:
        # Audit the skip so the chain still records every call.
        append_audit_entry(
            case_dir=case_dir_path,
            tool_name="register_evidence:idempotent_skip",
            evidence_id=existing_record.evidence_id,
            input_args={"filepath": str(path), "case_dir": str(case_dir_path)},
            output=existing_record,
        )
        return existing_record

    size_bytes = path.stat().st_size
    sha256, magic = _stream_sha256_and_magic(path)
    artifact_class = _detect_artifact_class(path, size_bytes, magic)
    evidence_id = str(uuid.uuid4())
    registered_at = datetime.now(tz=timezone.utc)

    os.chmod(path, _FILE_MODE)

    record = EvidenceRecord(
        evidence_id=evidence_id,
        original_filename=path.name,
        absolute_path=str(path),
        sha256=sha256,
        size_bytes=size_bytes,
        artifact_class=artifact_class,
        registered_at=registered_at,
        file_mode_after_registration=oct(_FILE_MODE),
    )

    case_dir_path.mkdir(parents=True, exist_ok=True)

    doc = existing_doc
    if not doc:
        doc = {
            "case_id": case_dir_path.name,
            "registered_at": registered_at.isoformat(),
            "evidence": [],
        }
    doc.setdefault("evidence", [])
    doc["evidence"].append(record.model_dump(mode="json"))
    _write_case_yaml(case_yaml_path, doc)

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name="register_evidence",
        evidence_id=evidence_id,
        input_args={"filepath": str(path), "case_dir": str(case_dir_path)},
        output=record,
    )

    return record


__all__ = ["register_evidence"]
