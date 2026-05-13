"""Tests for the pre-extract phase.

The 2026-05-13 SRL-v2 run motivated this module: three of four
``disk_analyst`` dispatches hit the 1800s wall while plaso was still
mid-MFT, leaving the audit chain with ``disk_*:runner_failed`` lines
and zero useful tier-1 extractions. The pre-extract phase moves the
plaso/regripper wall time OUT of the analyst session — the analyst
dispatch then only does fast tier-2 queries against a pre-populated
cache.

The tests stub the four tier-1 disk functions so the orchestration
logic can be validated without standing up plaso/regripper. The
real tier-1 wrappers have their own coverage in
``tests/test_disk_*.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from orchestrator import pre_extract as pre_extract_mod
from orchestrator.manifest import CaseManifest, EvidenceFile, HostEvidence
from orchestrator.pre_extract import (
    has_disk_evidence,
    pre_extract_disk_tier1,
)


NOW_UTC = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)


def _ef(evidence_id: str, evidence_type: str = "disk") -> EvidenceFile:
    return EvidenceFile(
        evidence_id=evidence_id,
        file_path=f"/tmp/{evidence_id}",
        evidence_type=evidence_type,  # type: ignore[arg-type]
        os_guess=None,
        file_size_bytes=1024,
    )


def _host(host_id: str, files: list[EvidenceFile]) -> HostEvidence:
    return HostEvidence(
        host_id=host_id,
        host_label=host_id,
        evidence_files=files,
    )


def _manifest(hosts: list[HostEvidence]) -> CaseManifest:
    return CaseManifest(
        case_id="case-x",
        hosts=hosts,
        created_at=NOW_UTC,
    )


class TestHasDiskEvidence:
    def test_returns_true_when_at_least_one_disk_evidence(self):
        m = _manifest(
            [
                _host("a", [_ef("e1", "memory")]),
                _host("b", [_ef("e2", "disk")]),
            ]
        )
        assert has_disk_evidence(m) is True

    def test_returns_false_for_memory_only_case(self):
        m = _manifest(
            [
                _host("a", [_ef("e1", "memory")]),
                _host("b", [_ef("e2", "memory")]),
            ]
        )
        assert has_disk_evidence(m) is False

    def test_returns_false_for_empty_manifest(self):
        m = CaseManifest(case_id="c", hosts=[], created_at=NOW_UTC)
        assert has_disk_evidence(m) is False


class TestPreExtractOrchestration:
    def test_runs_four_tier1_plugins_per_disk_evidence(self, tmp_path: Path):
        # 2 hosts × 1 disk evidence × 4 plugins = 8 tasks
        m = _manifest(
            [
                _host("nfury", [_ef("e1", "disk"), _ef("e1mem", "memory")]),
                _host("nromanoff", [_ef("e2", "disk")]),
            ]
        )

        calls: list[tuple[str, str]] = []  # (tool_name, evidence_id)

        def _fake(name: str):
            def f(eid: str, case_dir: str) -> dict:
                calls.append((name, eid))
                return {}

            return f

        with (
            patch.object(pre_extract_mod, "disk_mft_timeline", _fake("disk_mft_timeline")),
            patch.object(pre_extract_mod, "disk_prefetch", _fake("disk_prefetch")),
            patch.object(pre_extract_mod, "disk_evtx", _fake("disk_evtx")),
            patch.object(pre_extract_mod, "disk_registry", _fake("disk_registry")),
            # Replace the _DISK_TIER1_FUNCTIONS tuple too — the orchestration
            # captured function references at module-load time.
            patch.object(
                pre_extract_mod,
                "_DISK_TIER1_FUNCTIONS",
                (
                    ("disk_mft_timeline", _fake("disk_mft_timeline")),
                    ("disk_prefetch", _fake("disk_prefetch")),
                    ("disk_evtx", _fake("disk_evtx")),
                    ("disk_registry", _fake("disk_registry")),
                ),
            ),
        ):
            result = pre_extract_disk_tier1(
                case_dir=tmp_path,
                manifest=m,
                max_workers=2,
            )

        # 8 successful tasks, no failures.
        assert len(result.tasks) == 8
        assert result.succeeded_count == 8
        assert result.failed_count == 0

        # Each of the four plugins ran twice (once per disk evidence).
        seen = {(t.evidence_id, t.plugin_tool_name) for t in result.tasks}
        expected = {
            (eid, plugin)
            for eid in ("e1", "e2")
            for plugin in (
                "disk_mft_timeline",
                "disk_prefetch",
                "disk_evtx",
                "disk_registry",
            )
        }
        assert seen == expected

        # Memory evidence was skipped — no calls referenced "e1mem".
        assert all(eid in ("e1", "e2") for _, eid in calls)

    def test_failures_are_recorded_not_raised(self, tmp_path: Path):
        m = _manifest([_host("nfury", [_ef("e1", "disk")])])

        def _failing(eid: str, case_dir: str) -> dict:
            raise RuntimeError("plaso runner_failed")

        def _ok(eid: str, case_dir: str) -> dict:
            return {}

        with patch.object(
            pre_extract_mod,
            "_DISK_TIER1_FUNCTIONS",
            (
                ("disk_mft_timeline", _failing),
                ("disk_prefetch", _ok),
                ("disk_evtx", _ok),
                ("disk_registry", _ok),
            ),
        ):
            result = pre_extract_disk_tier1(
                case_dir=tmp_path,
                manifest=m,
                max_workers=2,
            )

        # One task failed; phase still completed.
        assert result.succeeded_count == 3
        assert result.failed_count == 1
        failed = [t for t in result.tasks if not t.succeeded][0]
        assert failed.plugin_tool_name == "disk_mft_timeline"
        assert failed.error_class == "RuntimeError"
        assert "plaso runner_failed" in (failed.error_message or "")

    def test_empty_manifest_is_a_noop(self, tmp_path: Path):
        m = CaseManifest(case_id="c", hosts=[], created_at=NOW_UTC)
        result = pre_extract_disk_tier1(
            case_dir=tmp_path,
            manifest=m,
            max_workers=2,
        )
        assert result.tasks == []
        assert result.succeeded_count == 0

    def test_memory_only_manifest_is_a_noop(self, tmp_path: Path):
        m = _manifest(
            [
                _host("a", [_ef("e1", "memory")]),
                _host("b", [_ef("e2", "memory")]),
            ]
        )
        call_count = 0

        def _counter(eid: str, case_dir: str) -> dict:
            nonlocal call_count
            call_count += 1
            return {}

        with patch.object(
            pre_extract_mod,
            "_DISK_TIER1_FUNCTIONS",
            (("disk_mft_timeline", _counter),),
        ):
            result = pre_extract_disk_tier1(
                case_dir=tmp_path,
                manifest=m,
                max_workers=2,
            )

        assert result.tasks == []
        assert call_count == 0

    def test_on_progress_events_fire(self, tmp_path: Path):
        m = _manifest([_host("nfury", [_ef("e1", "disk")])])
        events: list[tuple[str, dict]] = []

        def _record(event: str, payload: dict) -> None:
            events.append((event, payload))

        with patch.object(
            pre_extract_mod,
            "_DISK_TIER1_FUNCTIONS",
            (("disk_mft_timeline", lambda e, c: {}),),
        ):
            pre_extract_disk_tier1(
                case_dir=tmp_path,
                manifest=m,
                max_workers=1,
                on_progress=_record,
            )

        event_names = [e for e, _ in events]
        assert event_names[0] == "pre_extract_phase_start"
        assert "pre_extract_start" in event_names
        assert "pre_extract_done" in event_names
        assert event_names[-1] == "pre_extract_phase_done"

        # Phase-done event carries succeeded/failed counts.
        last_payload = events[-1][1]
        assert last_payload["succeeded"] == 1
        assert last_payload["failed"] == 0

    def test_on_progress_exception_does_not_crash_phase(self, tmp_path: Path):
        # A misbehaving observer should not bring down pre-extract.
        m = _manifest([_host("nfury", [_ef("e1", "disk")])])

        def _bad(event: str, payload: dict) -> None:
            raise ValueError("observer crashed")

        with patch.object(
            pre_extract_mod,
            "_DISK_TIER1_FUNCTIONS",
            (("disk_mft_timeline", lambda e, c: {}),),
        ):
            result = pre_extract_disk_tier1(
                case_dir=tmp_path,
                manifest=m,
                max_workers=1,
                on_progress=_bad,
            )

        # Task still ran and succeeded.
        assert result.succeeded_count == 1
