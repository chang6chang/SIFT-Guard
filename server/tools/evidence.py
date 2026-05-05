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


def _detect_artifact_class(
    path: Path, size_bytes: int, magic: bytes
) -> ArtifactClass:
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


def register_evidence(
    filepath: str, case_dir: str = "case-data"
) -> EvidenceRecord:
    """Register one piece of evidence into the case directory.

    Sequence:
      1. resolve and validate the path
      2. stream-hash sha256 and capture magic bytes in one pass
      3. detect artifact class
      4. mint UUID4 evidence_id
      5. chmod the file to 0o444
      6. append to (or create) CASE.yaml
      7. append a hash-chained line to the audit log
      8. return the EvidenceRecord
    """
    path = Path(filepath).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Evidence path is not a regular file: {path}")

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

    case_dir_path = Path(case_dir).resolve()
    case_dir_path.mkdir(parents=True, exist_ok=True)

    case_yaml_path = case_dir_path / _CASE_FILENAME
    doc = _load_case_yaml(case_yaml_path)
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
