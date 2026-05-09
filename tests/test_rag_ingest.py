"""Unit tests for `rag.ingest_attack`.

Covers:
  - STIX → RagRecord projection: filter rules (revoked, deprecated,
    non-attack-pattern types), required-field extraction, sort order
  - end-to-end index build on the fixture: writes the three expected
    files, meta is correct, FAISS index has the right size

No network: tests load the checked-in fixture rather than calling
`fetch_attack_bundle()`. The function exists for the CLI path and is
exercised manually via `python -m rag.ingest_attack`.

The first test that loads the embedding model pays a one-time cost
(~80 MB download on a fresh machine, ~3 s on CPU). Subsequent tests
in the same process reuse the cached model.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rag.ingest_attack import (
    ATTACK_LICENSE,
    ATTACK_SOURCE,
    ATTACK_TAG,
    attack_url,
    build_index_files,
    build_records,
)
from rag.retriever import (
    DEFAULT_EMBEDDING_MODEL,
    _INDEX_FILENAME,
    _META_FILENAME,
    _RECORDS_FILENAME,
)
from rag.schemas import RagRecord


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "rag_attack_sample.json"


def _load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# build_records — STIX projection / filter rules
# ---------------------------------------------------------------------------


class TestBuildRecords:
    def test_keeps_only_active_attack_patterns(self):
        bundle = _load_fixture()
        records = build_records(bundle)
        # Fixture has 5 active + 1 revoked + 1 deprecated +
        # 1 course-of-action + 1 malware. Keep only the 5 active.
        assert {r.technique_id for r in records} == {"T1003", "T1014", "T1027", "T1036", "T1055"}

    def test_records_sorted_by_technique_id(self):
        records = build_records(_load_fixture())
        ids = [r.technique_id for r in records]
        assert ids == sorted(ids), (
            "records must be sorted by technique_id so re-runs produce "
            "byte-identical index files (idempotency)"
        )

    def test_t1055_record_carries_full_metadata(self):
        records = build_records(_load_fixture())
        t1055 = next(r for r in records if r.technique_id == "T1055")

        assert t1055.name == "Process Injection"
        assert "inject code into processes" in t1055.description
        # ATT&CK technique pages are at https://attack.mitre.org/techniques/<TID>/
        assert t1055.citation_url == "https://attack.mitre.org/techniques/T1055/"
        assert t1055.source == ATTACK_SOURCE
        assert t1055.license == ATTACK_LICENSE
        assert t1055.embedding_model_version == DEFAULT_EMBEDDING_MODEL
        # T1055 is in two phases per the fixture; both must survive.
        assert "defense-evasion" in t1055.kill_chain_phases
        assert "privilege-escalation" in t1055.kill_chain_phases
        assert set(t1055.platforms) == {"Windows", "Linux", "macOS"}

    def test_runs_are_byte_stable(self):
        # Idempotency at the projection layer. The index-file step has
        # its own determinism story (sentence-transformers on CPU); this
        # test only locks the deterministic-by-construction half.
        bundle = _load_fixture()
        a = [r.model_dump(mode="json") for r in build_records(bundle)]
        b = [r.model_dump(mode="json") for r in build_records(bundle)]
        assert a == b


# ---------------------------------------------------------------------------
# attack_url — pinned-tag URL construction
# ---------------------------------------------------------------------------


class TestAttackUrl:
    def test_url_encodes_ampersand_in_tag(self):
        # The literal `&` would be a separator in a URL; raw.githubusercontent
        # serves the file only at the percent-encoded form.
        url = attack_url()
        assert "%26" in url, f"& must be %26-encoded in {url}"
        assert "&" not in url.split("//", 1)[1], "no raw & should survive the encoding step"
        assert ATTACK_TAG.replace("&", "%26") in url


# ---------------------------------------------------------------------------
# build_index_files — end-to-end on the fixture
# ---------------------------------------------------------------------------


class TestBuildIndexFiles:
    """Builds a real index in tmp_path. This pulls the embedding model
    weights (~80 MB) on first invocation per test session.

    Loads the model exactly once — the SentenceTransformer cache is
    process-global, and we want any fixture-level performance pain to
    be obvious rather than amortized across many tests."""

    @pytest.fixture(scope="class")
    def built_index(self, tmp_path_factory):
        records = build_records(_load_fixture())
        out = tmp_path_factory.mktemp("rag_index")
        meta = build_index_files(records, out)
        return records, out, meta

    def test_writes_all_three_files(self, built_index):
        _, out, _ = built_index
        assert (out / _INDEX_FILENAME).exists()
        assert (out / _RECORDS_FILENAME).exists()
        assert (out / _META_FILENAME).exists()

    def test_meta_carries_load_bearing_fields(self, built_index):
        _, out, meta = built_index
        # Re-read from disk to catch any serialization mismatch.
        on_disk = json.loads((out / _META_FILENAME).read_text())
        assert on_disk == meta

        assert meta["embedding_model_version"] == DEFAULT_EMBEDDING_MODEL
        assert meta["embedding_dim"] == 384  # all-MiniLM-L6-v2 dimensionality
        assert meta["record_count"] == 5
        assert meta["source"] == ATTACK_SOURCE
        assert meta["license"] == ATTACK_LICENSE
        assert meta["attack_tag"] == ATTACK_TAG
        # built_at is an ISO string with a UTC offset.
        assert "T" in meta["built_at"]
        assert meta["built_at"].endswith("+00:00") or meta["built_at"].endswith("Z")

    def test_records_json_round_trips_through_RagRecord(self, built_index):
        records, out, _ = built_index
        on_disk = json.loads((out / _RECORDS_FILENAME).read_text())
        # Same length, same order — record_id is implicit row position
        # so retrieval can index records[i] by FAISS rowid i.
        assert len(on_disk) == len(records)
        for d, r in zip(on_disk, records):
            assert d["technique_id"] == r.technique_id
            # The on-disk record validates back into the schema cleanly,
            # which is the contract the retriever depends on.
            RagRecord.model_validate(d)

    def test_faiss_index_has_one_vector_per_record(self, built_index):
        import faiss

        records, out, _ = built_index
        index = faiss.read_index(str(out / _INDEX_FILENAME))
        assert index.ntotal == len(records)
        assert index.d == 384

    def test_empty_corpus_refused(self, tmp_path):
        # Refusing an empty index avoids a silent failure mode where
        # every retrieval call returns nothing without complaint.
        with pytest.raises(ValueError, match="no records"):
            build_index_files([], tmp_path)
