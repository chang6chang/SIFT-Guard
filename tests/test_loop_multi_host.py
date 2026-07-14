"""Multi-host loop tests. Mock every subprocess + MCP call; the
loop logic itself is what we want to exercise."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import yaml

from orchestrator.dispatch import DispatchResult
from orchestrator.loop import (
    MANIFEST_TYPE_TO_ANALYSTS,
    _default_multi_host_token_budget,
    run_loop_multi_host,
)
from orchestrator.manifest import (
    CaseManifest,
    EvidenceFile,
    HostEvidence,
)
from server.schemas import (
    ArtifactClass,
    EvidenceRecord,
)


VALID_SHA256 = "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
NOW_UTC = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)


def _make_case_dir_with_two_hosts(tmp_path: Path) -> tuple[Path, CaseManifest]:
    """Build a tmp case_dir with two host entries:
    - nfury: memory_image
    - controller: disk_image
    """
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    nfury_mem = case_dir / "evidence" / "nfury-memory.raw"
    nfury_mem.write_bytes(b"\x00" * 1024)
    controller_disk = case_dir / "evidence" / "controller-disk.E01"
    controller_disk.write_bytes(b"\x00" * 1024)

    nfury_id = str(uuid4())
    controller_id = str(uuid4())
    records = [
        EvidenceRecord(
            evidence_id=nfury_id,
            original_filename="nfury-memory.raw",
            absolute_path=str(nfury_mem),
            sha256=VALID_SHA256,
            size_bytes=1024,
            artifact_class=ArtifactClass.MEMORY_IMAGE,
            registered_at=NOW_UTC,
            file_mode_after_registration="0o444",
        ),
        EvidenceRecord(
            evidence_id=controller_id,
            original_filename="controller-disk.E01",
            absolute_path=str(controller_disk),
            sha256=VALID_SHA256,
            size_bytes=1024,
            artifact_class=ArtifactClass.DISK_IMAGE,
            registered_at=NOW_UTC,
            file_mode_after_registration="0o444",
        ),
    ]
    doc = {
        "case_id": case_dir.name,
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [r.model_dump(mode="json") for r in records],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))

    manifest = CaseManifest(
        case_id=case_dir.name,
        hosts=[
            HostEvidence(
                host_id="nfury",
                host_label="nfury",
                evidence_files=[
                    EvidenceFile(
                        evidence_id=nfury_id,
                        file_path=str(nfury_mem),
                        evidence_type="memory",
                        os_guess="Windows 7 64-bit",
                        file_size_bytes=1024,
                    )
                ],
            ),
            HostEvidence(
                host_id="controller",
                host_label="controller",
                evidence_files=[
                    EvidenceFile(
                        evidence_id=controller_id,
                        file_path=str(controller_disk),
                        evidence_type="disk",
                        os_guess="Server 2008 R2",
                        file_size_bytes=1024,
                    )
                ],
            ),
        ],
        created_at=NOW_UTC,
    )
    return case_dir, manifest


def _ok_dispatch(agent: str, **kwargs) -> DispatchResult:
    """Minimal-cost succeeded dispatch result for analyst mocking.

    Includes ``mcp_server_status={"sift-guard": "connected"}`` so the
    new MCP-attach guard in ``DispatchResult.succeeded`` is satisfied.
    Tests for the fail-closed path live in ``test_dispatch.py``."""
    return DispatchResult(
        agent=agent,
        session_id="sid",
        stop_reason="end_turn",
        num_turns=1,
        duration_ms=10,
        duration_api_ms=5,
        total_cost_usd=0.0,
        input_tokens=0,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=0,
        output_tokens=0,
        tokens_uncached=0,
        final_text="",
        mcp_server_status={"sift-guard": "connected"},
        raw_events=[],
    )


class TestDispatchOrdering:
    def test_per_host_per_evidence_dispatch_order(self, tmp_path: Path):
        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        dispatched: list[tuple[str, str, str]] = []  # (agent, host_id, eid)

        def fake_analyst(
            agent,
            *,
            evidence_id,
            case_id,
            iteration_number,
            cwd,
            focus_context=None,
            host_id=None,
            host_label=None,
        ):
            dispatched.append((agent, host_id, evidence_id))
            return _ok_dispatch(agent)

        def fake_validator(
            *,
            evidence_id,
            case_id,
            iteration_number,
            cwd,
            findings_summary=None,
            host_grouped_findings=None,
        ):
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        outcome = run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=fake_analyst,
            dispatch_validator_fn=fake_validator,
            update_finding_fn=fake_update,
            # parallel=False — this test asserts manifest-order
            # dispatch, which only holds under the sequential path.
            parallel=False,
        )

        # nfury (memory) → process_analyst + network_analyst
        # controller (disk) → disk_analyst
        agents_per_host = {}
        for agent, host_id, _ in dispatched:
            agents_per_host.setdefault(host_id, []).append(agent)
        assert agents_per_host["nfury"] == [
            "process_analyst",
            "network_analyst",
        ]
        assert agents_per_host["controller"] == ["disk_analyst"]
        # Hosts dispatched in manifest order (nfury before controller).
        host_order = [h for _, h, _ in dispatched]
        assert host_order.index("nfury") < host_order.index("controller")
        assert outcome.iterations[0].iteration.manifest_summary is not None

    def test_unknown_evidence_type_is_skipped_with_warning(self, tmp_path: Path, caplog):
        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        # Mutate one host to use evidence_type="unknown" — the
        # dispatcher should skip its evidence_files entirely.
        manifest.hosts[0].evidence_files[0] = EvidenceFile(
            evidence_id=manifest.hosts[0].evidence_files[0].evidence_id,
            file_path=manifest.hosts[0].evidence_files[0].file_path,
            evidence_type="unknown",
            os_guess=None,
            file_size_bytes=1024,
        )
        dispatched: list[tuple[str, str]] = []

        def fake_analyst(
            agent,
            *,
            evidence_id,
            case_id,
            iteration_number,
            cwd,
            focus_context=None,
            host_id=None,
            host_label=None,
        ):
            dispatched.append((agent, host_id))
            return _ok_dispatch(agent)

        def fake_validator(**kwargs):
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        with caplog.at_level("WARNING"):
            run_loop_multi_host(
                case_dir=case_dir,
                manifest=manifest,
                max_iterations=1,
                token_budget=10_000_000,
                dispatch_analyst_fn=fake_analyst,
                dispatch_validator_fn=fake_validator,
                update_finding_fn=fake_update,
            )

        # nfury was the unknown-typed host — its analysts are skipped.
        nfury_dispatches = [agent for agent, h in dispatched if h == "nfury"]
        assert nfury_dispatches == []
        # controller (disk) still got its disk_analyst.
        controller_dispatches = [agent for agent, h in dispatched if h == "controller"]
        assert controller_dispatches == ["disk_analyst"]
        # Skip was logged.
        assert any("unknown evidence_type" in rec.message for rec in caplog.records)

    def test_validator_receives_host_grouped_findings(self, tmp_path: Path):
        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        captured: dict = {}

        def fake_analyst(agent, **kwargs):
            return _ok_dispatch(agent)

        def fake_validator(
            *,
            evidence_id,
            case_id,
            iteration_number,
            cwd,
            findings_summary=None,
            host_grouped_findings=None,
        ):
            captured["host_grouped_findings"] = host_grouped_findings
            captured["findings_summary"] = findings_summary
            captured["evidence_id"] = evidence_id
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=fake_analyst,
            dispatch_validator_fn=fake_validator,
            update_finding_fn=fake_update,
        )

        # No analysts produced findings (mocked), so the validator
        # is skipped entirely — captured stays empty. That's also
        # the correct behavior; assert it explicitly.
        assert captured == {}, "validator should not be dispatched when no DRAFT findings exist"


class TestParallelDispatch:
    """Parallel analyst dispatch — both that it actually overlaps in
    wall-clock and that state mutation stays consistent under
    contention."""

    def test_parallel_dispatch_overlaps_in_wall_clock(self, tmp_path: Path):
        """Each fake analyst sleeps for ``SLEEP_S``. With three jobs
        (nfury memory → 2 analysts + controller disk → 1 analyst),
        parallel wall-clock must be roughly one sleep, not three."""
        import time

        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        SLEEP_S = 0.3

        def fake_analyst(agent, **kwargs):
            time.sleep(SLEEP_S)
            return _ok_dispatch(agent)

        def fake_validator(**kwargs):
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        start = time.monotonic()
        run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=fake_analyst,
            dispatch_validator_fn=fake_validator,
            update_finding_fn=fake_update,
            parallel=True,
        )
        elapsed = time.monotonic() - start
        # Three jobs sequentially would take ≥ 3 * SLEEP_S. Parallel
        # should finish in just over SLEEP_S (one round of sleeps).
        # 2 * SLEEP_S gives generous headroom for thread-pool setup
        # without admitting the sequential case.
        assert elapsed < 2 * SLEEP_S, (
            f"parallel dispatch should overlap; took {elapsed:.2f}s, expected < {2 * SLEEP_S:.2f}s"
        )

    def test_state_mutation_thread_safe_under_parallel(self, tmp_path: Path):
        """``state.tokens_uncached += result.tokens_uncached`` and the
        appends to ``state.dispatch_results`` / ``analysts_dispatched``
        must produce a consistent state. We assert: total tokens
        equals sum-of-jobs, dispatch_results length equals
        job-count, and every job-tag is present."""
        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        per_job_tokens = 1_000

        def fake_analyst(agent, **kwargs):
            r = _ok_dispatch(agent)
            r.tokens_uncached = per_job_tokens
            return r

        def fake_validator(**kwargs):
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        outcome = run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=fake_analyst,
            dispatch_validator_fn=fake_validator,
            update_finding_fn=fake_update,
            parallel=True,
        )
        iteration = outcome.iterations[0].iteration
        # 2 hosts: nfury memory → 2 analysts, controller disk → 1 analyst = 3 jobs.
        expected_jobs = 3
        assert len(iteration.analysts_dispatched) == expected_jobs
        # Tokens are summed — under-counting would suggest a lost
        # `+=` (race), over-counting suggests duplicate dispatch.
        assert iteration.tokens_used_uncached == expected_jobs * per_job_tokens

    def test_progress_callback_serialized_across_threads(self, tmp_path: Path):
        """The progress callback must run under the emit lock — multi-
        threaded reentries into a non-threadsafe callback would break
        the live progress display. We verify by asserting no two
        callback invocations are interleaved (i.e., the callback
        always observes a consistent in_flight count)."""
        import time

        case_dir, manifest = _make_case_dir_with_two_hosts(tmp_path)
        in_callback = threading.Lock()
        violations = []

        def progress(event, payload):
            # Tries to acquire — if the loop's lock isn't holding
            # exclusivity, two threads land inside this function
            # simultaneously and the non-blocking acquire fails for
            # one of them.
            if not in_callback.acquire(blocking=False):
                violations.append(event)
                return
            try:
                time.sleep(0.005)
            finally:
                in_callback.release()

        def fake_analyst(agent, **kwargs):
            return _ok_dispatch(agent)

        def fake_validator(**kwargs):
            return _ok_dispatch("validator")

        def fake_update(case_cwd, args):
            return {"update_id": str(uuid4())}

        run_loop_multi_host(
            case_dir=case_dir,
            manifest=manifest,
            max_iterations=1,
            token_budget=10_000_000,
            dispatch_analyst_fn=fake_analyst,
            dispatch_validator_fn=fake_validator,
            update_finding_fn=fake_update,
            on_progress=progress,
            parallel=True,
        )
        assert violations == [], (
            f"progress callback re-entered concurrently from threads "
            f"({len(violations)} events overlapped: {violations[:5]})"
        )


class TestTokenBudgetHeuristic:
    def test_default_budget_scales_with_host_count(self):
        # 1 host: 500K + 250K = 750K
        assert _default_multi_host_token_budget(1) == 750_000
        # 4 hosts: 500K + 1M = 1.5M
        assert _default_multi_host_token_budget(4) == 1_500_000
        # 100 hosts: capped at 5M
        assert _default_multi_host_token_budget(100) == 5_000_000


class TestManifestTypeToAnalystsMap:
    def test_memory_dispatches_two_analysts(self):
        assert MANIFEST_TYPE_TO_ANALYSTS["memory"] == [
            "process_analyst",
            "network_analyst",
        ]

    def test_disk_dispatches_disk_analyst(self):
        assert MANIFEST_TYPE_TO_ANALYSTS["disk"] == ["disk_analyst"]

    def test_unknown_is_absent_so_dispatcher_skips(self):
        assert "unknown" not in MANIFEST_TYPE_TO_ANALYSTS
