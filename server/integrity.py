"""End-of-run evidence re-hash.

CLAUDE.md 'Architectural enforcement of evidence integrity' promises:
"Audit log re-hashes evidence at the end of every run; mismatch is a
fatal error". This module is that closure step. The orchestrator calls
`assert_evidence_integrity` at loop termination; every re-hash lands
on the audit chain (`verify_evidence_integrity` /
`verify_evidence_integrity:mismatch`) so the tamper check is itself
tamper-evident.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import BaseModel

from server.audit import append_audit_entry

_CASE_FILENAME = "CASE.yaml"
_CHUNK_SIZE = 64 * 1024
_TOOL_NAME = "verify_evidence_integrity"


class EvidenceIntegrityCheck(BaseModel):
    """One re-hash outcome. Pydantic (not dataclass) so it can be the
    `output=` payload of `append_audit_entry` directly."""

    evidence_id: str
    original_filename: str
    sha256_expected: str
    sha256_actual: str | None
    ok: bool
    error: str | None = None


class EvidenceIntegrityError(RuntimeError):
    """At least one registered evidence file failed the end-of-run
    re-hash. Message is sanitized (ids only, no paths); the audit
    chain carries the full context."""

    def __init__(self, failures: list[EvidenceIntegrityCheck]) -> None:
        self.failures = failures
        ids = ", ".join(f.evidence_id for f in failures)
        super().__init__(
            f"evidence integrity check failed for {len(failures)} "
            f"file(s): {ids}"
        )


def _stream_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_evidence_integrity(
    case_dir: Path | str, *, audit: bool = True
) -> list[EvidenceIntegrityCheck]:
    """Re-hash every evidence file registered in CASE.yaml.

    Returns one check per entry; never raises on mismatch (that is
    `assert_evidence_integrity`'s job). Unreadable/missing files
    count as failures with `error` set to the exception class name —
    a vanished evidence file is an integrity failure, not a skip.
    Missing CASE.yaml returns [] (nothing registered, nothing to
    verify).
    """
    case_dir_path = Path(case_dir).resolve()
    case_yaml = case_dir_path / _CASE_FILENAME
    if not case_yaml.exists():
        return []
    with case_yaml.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    results: list[EvidenceIntegrityCheck] = []
    for entry in doc.get("evidence", []) or []:
        evidence_id = str(entry.get("evidence_id", ""))
        expected = str(entry.get("sha256", ""))
        path = Path(str(entry.get("absolute_path", "")))
        actual: str | None
        error: str | None
        try:
            actual = _stream_sha256(path)
            error = None
        except OSError as exc:
            actual = None
            error = exc.__class__.__name__
        check = EvidenceIntegrityCheck(
            evidence_id=evidence_id,
            original_filename=str(entry.get("original_filename", "")),
            sha256_expected=expected,
            sha256_actual=actual,
            ok=actual == expected,
            error=error,
        )
        if audit:
            append_audit_entry(
                case_dir=case_dir_path,
                tool_name=_TOOL_NAME if check.ok else f"{_TOOL_NAME}:mismatch",
                evidence_id=evidence_id,
                input_args={"sha256_expected": expected},
                output=check,
            )
        results.append(check)
    return results


def assert_evidence_integrity(
    case_dir: Path | str,
) -> list[EvidenceIntegrityCheck]:
    """`verify_evidence_integrity`, but fatal on any failure."""
    results = verify_evidence_integrity(case_dir)
    failures = [r for r in results if not r.ok]
    if failures:
        raise EvidenceIntegrityError(failures)
    return results


__all__ = [
    "EvidenceIntegrityCheck",
    "EvidenceIntegrityError",
    "assert_evidence_integrity",
    "verify_evidence_integrity",
]
