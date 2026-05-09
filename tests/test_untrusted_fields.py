"""Unit tests for the field-level evidence-delimiter discipline.

Each tier-1 summary type and each tier-2 result type carries an
`untrusted_fields: list[str]` schema field — the schema-level contract
that tells analyst subagents which field VALUES in the result are
attacker-controlled (evidence-derived) and must be treated as data,
never instructions.

Coverage targets:
  - per-plugin untrusted-record-field constants (the source of truth)
  - tier-1 summary defaults match the per-plugin map
  - tier-2 results populate the list correctly per source plugin
  - projection restriction: when an agent projects a field away, it
    must not appear in `untrusted_fields`
  - group_by uses the synthetic `groups_keys` axis
  - set_difference picks the source side based on `direction`
  - subtree is pstree-only and inherits pstree's set
  - schema-introspection guard: a future tool that adds a
    record-bearing return type without `untrusted_fields` must fail
    the build (see `test_every_record_bearing_result_type_declares_untrusted_fields`)

These are schema and tool-layer property tests; no SSH, no
Volatility. Each test seeds a tmp case_dir with a registered
evidence record and pre-written extraction, then asserts the
expected untrusted_fields on the returned tier-2 result. Tier-1
summary tests construct the model directly to verify the
default_factory.
"""

from __future__ import annotations

import typing
from datetime import datetime, timezone
from pathlib import Path

import yaml

from server.extractions import write_extraction
from server.schemas import (
    PLUGIN_UNTRUSTED_RECORD_FIELDS,
    ArtifactClass,
    EvidenceRecord,
    ExtractionRef,
    GroupByResult,
    NetscanResult,
    NetscanSummary,
    NetworkRecord,
    ProcessRecord,
    ProcessTreeRecord,
    PslistResult,
    PslistSummary,
    PsscanResult,
    PsscanSummary,
    PstreeResult,
    PstreeSummary,
    QueryRecordsResult,
    SetDifferenceResult,
    SubtreeResult,
    untrusted_fields_for,
)
from server.tools.analytical import (
    group_by,
    query_records,
    set_difference,
    subtree,
)


EVIDENCE_ID = "550e8400-e29b-41d4-a716-446655440000"
NOW_UTC = datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures — minimal case-dir seeding. Mirrors the pattern in
# tests/test_query_records.py / test_subtree.py / test_set_difference.py
# (deliberately not factored into conftest.py so each tier-2 test file
# stays self-contained and the failure mode of "fixture drift" is
# obvious at the call site).
# ---------------------------------------------------------------------------


def _seed_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case-data"
    case_dir.mkdir()
    (case_dir / "evidence").mkdir()
    record = EvidenceRecord(
        evidence_id=EVIDENCE_ID,
        original_filename="Rocba-Memory.raw",
        absolute_path=str(case_dir / "evidence" / "Rocba-Memory.raw"),
        sha256="e" * 64,
        size_bytes=1024,
        artifact_class=ArtifactClass.MEMORY_IMAGE,
        registered_at=NOW_UTC,
        file_mode_after_registration="0o444",
    )
    doc = {
        "case_id": "case-data",
        "registered_at": NOW_UTC.isoformat(),
        "evidence": [record.model_dump(mode="json")],
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    return case_dir


def _pr(pid: int, ppid: int = 4, name: str = "x.exe") -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        ppid=ppid,
        image_file_name=name,
        offset_v=0,
        threads=1,
        handles=None,
        session_id=None,
        wow64=False,
        create_time=NOW_UTC,
        exit_time=None,
    )


def _ptr(pid: int, ppid: int, name: str, children: list | None = None) -> ProcessTreeRecord:
    return ProcessTreeRecord(
        pid=pid,
        ppid=ppid,
        image_file_name=name,
        offset_v=0,
        threads=1,
        handles=None,
        session_id=None,
        wow64=False,
        create_time=NOW_UTC,
        exit_time=None,
        audit=None,
        cmd=None,
        path=None,
        children=children or [],
    )


def _nr(pid: int, foreign: str = "10.0.0.1", owner: str = "svc.exe") -> NetworkRecord:
    return NetworkRecord(
        proto="TCPv4",
        local_addr="127.0.0.1",
        local_port=1234,
        foreign_addr=foreign,
        foreign_port=443,
        state="ESTABLISHED",
        pid=pid,
        owner=owner,
        offset=0,
        created=NOW_UTC,
    )


def _seed_pslist(case_dir: Path, processes: list[ProcessRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pslist.PsList",
        PslistResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            volatility_version="2.27.0",
            processes=processes,
            command_executed="vol -f /tmp/x.raw -r json windows.pslist.PsList",
            runtime_seconds=14.7,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=14.7,
    )


def _seed_psscan(case_dir: Path, processes: list[ProcessRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.psscan.PsScan",
        PsscanResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.psscan.PsScan",
            volatility_version="2.27.0",
            processes=processes,
            command_executed="vol -f /tmp/x.raw -r json windows.psscan.PsScan",
            runtime_seconds=396.3,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=396.3,
    )


def _seed_pstree(case_dir: Path, processes: list[ProcessTreeRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.pstree.PsTree",
        PstreeResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            volatility_version="2.27.0",
            processes=processes,
            command_executed="vol -f /tmp/x.raw -r json windows.pstree.PsTree",
            runtime_seconds=29.5,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=29.5,
    )


def _seed_netscan(case_dir: Path, records: list[NetworkRecord]) -> None:
    write_extraction(
        case_dir,
        EVIDENCE_ID,
        "windows.netscan.NetScan",
        NetscanResult(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.netscan.NetScan",
            volatility_version="2.27.0",
            connections=records,
            command_executed="vol -f /tmp/x.raw -r json windows.netscan.NetScan",
            runtime_seconds=537.4,
            invoked_at=NOW_UTC,
        ),
        runtime_seconds=537.4,
    )


# ---------------------------------------------------------------------------
# (1) Per-plugin untrusted-record-field map — the source of truth
# ---------------------------------------------------------------------------


class TestPluginUntrustedRecordFieldsMap:
    def test_map_has_all_supported_plugins(self):
        # Every plugin in the PluginName Literal must appear in the map.
        # Adding a plugin without extending the map is the failure
        # mode this test catches.
        assert set(PLUGIN_UNTRUSTED_RECORD_FIELDS.keys()) == {
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.pstree.PsTree",
            "windows.netscan.NetScan",
            "windows.cmdline.CmdLine",
            "windows.malfind.Malfind",
            "disk.mft.MftTimeline",
            "disk.prefetch.Prefetch",
            "disk.evtx.EventLog",
            "disk.registry.Registry",
        }

    def test_pslist_psscan_match_processrecord_string_fields(self):
        # ProcessRecord (and its alias ProcessScanRecord) carries
        # exactly one evidence-derived string field: image_file_name.
        # Other fields are integer / bool / datetime — kernel-structural,
        # not free-form attacker-controllable strings.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.pslist.PsList"] == ("image_file_name",)
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.psscan.PsScan"] == ("image_file_name",)

    def test_pstree_carries_the_user_process_parameters_strings(self):
        # ProcessTreeRecord adds audit / cmd / path from
        # `_RTL_USER_PROCESS_PARAMETERS` on top of image_file_name.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.pstree.PsTree"] == (
            "image_file_name",
            "audit",
            "cmd",
            "path",
        )

    def test_netscan_carries_address_owner_state_strings(self):
        # NetworkRecord — local/foreign addresses, owner image name,
        # and TCP state are all evidence-derived. proto is a closed
        # Literal so its values are schema-controlled.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.netscan.NetScan"] == (
            "local_addr",
            "foreign_addr",
            "owner",
            "state",
        )

    def test_cmdline_carries_process_name_and_cmdline_strings(self):
        # ProcessCmdLineRecord — process_name (image name) plus the
        # user-space command line read out of
        # _RTL_USER_PROCESS_PARAMETERS. The cmdline value is the
        # half an attacker most directly controls.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.cmdline.CmdLine"] == (
            "process_name",
            "cmdline",
        )

    def test_malfind_carries_vad_and_memory_content_strings(self):
        # MalfindRecord — process_name plus the four fields whose
        # values come from suspect VAD memory: pool tag, page
        # protection string, hex dump bytes, and disassembly text.
        # Treating all four as data is what stops crafted shellcode
        # ASCII strings from steering the analyst.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["windows.malfind.Malfind"] == (
            "process_name",
            "vad_tag",
            "protection",
            "hex_dump",
            "disassembly",
        )

    def test_disk_mft_carries_full_path_string(self):
        # MftTimelineRecord — full_path is the on-disk filename
        # which an attacker who placed the binary controls.
        # entry_type is a closed Literal; timestamp / file_size are
        # kernel-structural.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["disk.mft.MftTimeline"] == ("full_path",)

    def test_disk_prefetch_carries_executable_and_path_strings(self):
        # PrefetchRecord — executable_name + volume_path +
        # referenced_files all reflect on-disk strings the attacker
        # influences. run_count and last_run_times are
        # OS-recorded.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["disk.prefetch.Prefetch"] == (
            "executable_name",
            "volume_path",
            "referenced_files",
        )

    def test_disk_evtx_carries_provider_channel_and_message_summary(self):
        # EvtxRecord — source/channel are typically schema-controlled
        # provider names but logged events can include attacker-
        # controlled strings; message_summary is the rendered
        # EventData and is the most directly attacker-controllable.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["disk.evtx.EventLog"] == (
            "source",
            "channel",
            "message_summary",
        )

    def test_disk_registry_carries_hive_key_path_and_value(self):
        # RegistryRecord — hive_name is one of a closed set but kept
        # as untrusted for forward-compat; key_path / value_name /
        # value_data are evidence-derived strings the attacker
        # populates when adding persistence keys.
        assert PLUGIN_UNTRUSTED_RECORD_FIELDS["disk.registry.Registry"] == (
            "hive_name",
            "key_path",
            "value_name",
            "value_data",
        )


# ---------------------------------------------------------------------------
# (2) Tier-1 summary defaults
# ---------------------------------------------------------------------------


class TestTier1SummaryDefaults:
    def _ref(self) -> ExtractionRef:
        return ExtractionRef(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            extraction_id="6770da81-f562-4643-b1d2-69d78104fb70",
            record_count=0,
            extraction_sha256="e" * 64,
            extractions_chain_line=1,
            audit_line=None,
            runtime_seconds=None,
            cached=False,
        )

    def test_pslist_summary_marks_top_image_names_keys(self):
        s = PslistSummary(
            extraction=self._ref(),
            unique_image_names=0,
            null_create_time_count=0,
            with_exit_time_count=0,
            distinct_ppids=0,
            top_image_names=[],
            pid_range=(0, 0),
        )
        # The top_image_names tuples carry image-name strings as the
        # untrusted axis. Counts (the second element) are aggregates.
        assert s.untrusted_fields == ["top_image_names_keys"]

    def test_psscan_summary_inherits_pslist_default(self):
        s = PsscanSummary(
            extraction=self._ref().model_copy(update={"plugin_name": "windows.psscan.PsScan"}),
            unique_image_names=0,
            null_create_time_count=0,
            with_exit_time_count=0,
            distinct_ppids=0,
            top_image_names=[],
            pid_range=(0, 0),
        )
        assert s.untrusted_fields == ["top_image_names_keys"]

    def test_pstree_summary_default_is_empty(self):
        # Only counts, depth integers, and (root_pid, descendant_count).
        # No evidence-derived strings surfaced at the summary level.
        s = PstreeSummary(
            extraction=self._ref().model_copy(update={"plugin_name": "windows.pstree.PsTree"}),
            top_level_root_count=0,
            max_depth=0,
            depth_distribution={},
            largest_subtree=(0, 0),
            orphan_count=0,
        )
        assert s.untrusted_fields == []

    def test_netscan_summary_default_is_empty(self):
        # protocol_distribution keys are closed Literal proto values.
        # tcp_state_distribution keys come from kernel state-machine
        # values, not free-form attacker-controllable strings. Address
        # / owner content is reached only via tier-2 query_records.
        s = NetscanSummary(
            extraction=self._ref().model_copy(update={"plugin_name": "windows.netscan.NetScan"}),
            protocol_distribution={},
            tcp_state_distribution={},
            null_owner_count=0,
            listening_port_count=0,
            established_count=0,
            distinct_foreign_addrs=0,
        )
        assert s.untrusted_fields == []


# ---------------------------------------------------------------------------
# (3) `untrusted_fields_for` helper — projection restriction & ordering
# ---------------------------------------------------------------------------


class TestUntrustedFieldsHelper:
    def test_no_projection_returns_full_plugin_set_in_canonical_order(self):
        assert untrusted_fields_for("windows.pstree.PsTree") == [
            "image_file_name",
            "audit",
            "cmd",
            "path",
        ]

    def test_empty_projection_treated_as_no_projection(self):
        # Empty list != "drop everything"; the tool layer's contract
        # is "fields=[] means no projection, every field present".
        assert untrusted_fields_for("windows.netscan.NetScan", []) == [
            "local_addr",
            "foreign_addr",
            "owner",
            "state",
        ]

    def test_projection_intersects_with_plugin_set(self):
        assert untrusted_fields_for(
            "windows.netscan.NetScan", ["pid", "foreign_addr", "state"]
        ) == ["foreign_addr", "state"]

    def test_projection_dropping_all_untrusted_yields_empty(self):
        assert untrusted_fields_for("windows.pslist.PsList", ["pid", "ppid", "threads"]) == []

    def test_unknown_plugin_returns_empty(self):
        # Defensive: if an unknown plugin name slips through (it
        # shouldn't, the Literal gates the surface), return empty
        # rather than KeyError. Fail-closed is the right default for
        # a security-relevant property.
        assert untrusted_fields_for("nonsense.plugin.Name") == []

    def test_stable_across_projection_order(self):
        # `untrusted_fields` reflects the canonical
        # PLUGIN_UNTRUSTED_RECORD_FIELDS order, not the projection's
        # input order — so a result's list is deterministic regardless
        # of how the agent listed its fields.
        a = untrusted_fields_for(
            "windows.pstree.PsTree", ["path", "image_file_name", "cmd", "audit"]
        )
        b = untrusted_fields_for(
            "windows.pstree.PsTree", ["audit", "cmd", "image_file_name", "path"]
        )
        assert a == b == ["image_file_name", "audit", "cmd", "path"]


# ---------------------------------------------------------------------------
# (4) Tier-2 results populate untrusted_fields
# ---------------------------------------------------------------------------


class TestQueryRecordsUntrustedFields:
    def test_pslist_no_projection_marks_image_file_name(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            case_dir=str(case_dir),
        )
        assert isinstance(result, QueryRecordsResult)
        assert result.untrusted_fields == ["image_file_name"]

    def test_pslist_projection_excluding_image_file_name_yields_empty(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            fields=["pid", "ppid"],
            case_dir=str(case_dir),
        )
        assert result.untrusted_fields == []

    def test_netscan_partial_projection_keeps_only_projected_untrusted(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_netscan(case_dir, [_nr(4)])
        result = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.netscan.NetScan",
            fields=["pid", "foreign_addr"],
            case_dir=str(case_dir),
        )
        # `foreign_addr` is in the per-plugin set; `pid` is integer.
        # Result must keep only the projected untrusted axis.
        assert result.untrusted_fields == ["foreign_addr"]


class TestGroupByUntrustedFields:
    def test_group_by_image_file_name_marks_groups_keys(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe")])
        result = group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="image_file_name",
            case_dir=str(case_dir),
        )
        assert isinstance(result, GroupByResult)
        # The values being aggregated are evidence-derived strings;
        # the `groups_keys` synthetic name flags the value-axis of the
        # (value, count) tuples.
        assert result.untrusted_fields == ["groups_keys"]

    def test_group_by_pid_yields_empty_untrusted_fields(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe")])
        result = group_by(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pslist.PsList",
            field="pid",
            case_dir=str(case_dir),
        )
        # PID is integer; not in the per-plugin untrusted set.
        assert result.untrusted_fields == []


class TestSetDifferenceUntrustedFields:
    def test_a_minus_b_uses_plugin_a_untrusted(self, tmp_path: Path):
        # psscan ∖ pslist on PID — DKOM-hidden candidate set.
        # Records returned come from psscan (plugin_a), so
        # untrusted_fields reflects psscan's set.
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe")])
        _seed_psscan(
            case_dir, [_pr(4, 0, "System"), _pr(100, 4, "smss.exe"), _pr(7900, 100, "evil.exe")]
        )
        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            case_dir=str(case_dir),
        )
        assert isinstance(result, SetDifferenceResult)
        assert result.untrusted_fields == ["image_file_name"]

    def test_set_difference_with_pid_only_projection_yields_empty(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pslist(case_dir, [_pr(4, 0, "System")])
        _seed_psscan(case_dir, [_pr(4, 0, "System"), _pr(7900, 100, "evil.exe")])
        result = set_difference(
            evidence_id=EVIDENCE_ID,
            plugin_a="windows.psscan.PsScan",
            plugin_b="windows.pslist.PsList",
            key="pid",
            direction="a_minus_b",
            fields=["pid", "ppid"],
            case_dir=str(case_dir),
        )
        # Projection drops every untrusted field → empty list.
        assert result.untrusted_fields == []


class TestSubtreeUntrustedFields:
    def test_subtree_no_projection_marks_all_pstree_untrusted(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_ptr(4, 0, "System", [_ptr(100, 4, "smss.exe")])])
        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=4,
            case_dir=str(case_dir),
        )
        assert isinstance(result, SubtreeResult)
        assert result.untrusted_fields == [
            "image_file_name",
            "audit",
            "cmd",
            "path",
        ]

    def test_subtree_pid_only_projection_yields_empty(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_pstree(case_dir, [_ptr(4, 0, "System")])
        result = subtree(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.pstree.PsTree",
            root_pid=4,
            fields=["pid"],
            case_dir=str(case_dir),
        )
        assert result.untrusted_fields == []


# ---------------------------------------------------------------------------
# (5) Stability across calls — schema property, not user-controlled
# ---------------------------------------------------------------------------


class TestUntrustedFieldsIsAStableSchemaProperty:
    def test_two_query_records_calls_with_same_args_yield_same_list(self, tmp_path: Path):
        case_dir = _seed_case_dir(tmp_path)
        _seed_netscan(case_dir, [_nr(4)])
        a = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.netscan.NetScan",
            case_dir=str(case_dir),
        )
        b = query_records(
            evidence_id=EVIDENCE_ID,
            plugin_name="windows.netscan.NetScan",
            case_dir=str(case_dir),
        )
        # The list is a function of (plugin, projection), not of the
        # data being queried — same call shape, same untrusted_fields.
        assert a.untrusted_fields == b.untrusted_fields
        assert a.untrusted_fields == [
            "local_addr",
            "foreign_addr",
            "owner",
            "state",
        ]


# ---------------------------------------------------------------------------
# (6) Schema-introspection guard: any future record-bearing return
# type that lacks `untrusted_fields` fails the build. This is the
# load-bearing test for the field-level evidence-delimiter discipline:
# a contributor adding a tier-2 tool that returns a new Result class
# (e.g. `JoinResult`) without declaring the contract is blocked at CI
# time. We discover return types by walking the public tool surface
# in `server.tools.{memory,analytical}` and asserting every annotated
# return type has the field.
# ---------------------------------------------------------------------------


class TestSchemaIntrospectionGuard:
    def _public_tool_return_types(self) -> set[type]:
        from server.tools import analytical as analytical_mod
        from server.tools import memory as memory_mod

        types: set[type] = set()
        for module in (memory_mod, analytical_mod):
            for name in module.__all__:
                fn = getattr(module, name)
                if not callable(fn):
                    continue
                # `from __future__ import annotations` is set in both
                # tool modules, so signature.return_annotation comes
                # back as a string; typing.get_type_hints resolves it
                # against the module's globals.
                try:
                    hints = typing.get_type_hints(fn)
                except Exception:
                    continue
                ret = hints.get("return")
                if ret is None:
                    continue
                # Only count BaseModel-derived returns; primitives and
                # helpers (translate_to_vm_path → str) are out of scope.
                if hasattr(ret, "model_fields"):
                    types.add(ret)
        return types

    def test_every_record_bearing_result_type_declares_untrusted_fields(self):
        return_types = self._public_tool_return_types()
        # Sanity: the introspection found something — otherwise the
        # test could vacuously pass after a refactor that broke
        # discovery.
        assert len(return_types) >= 8, (
            f"expected ≥8 tool return types from memory + analytical "
            f"modules, got {len(return_types)}: "
            f"{sorted(t.__name__ for t in return_types)}"
        )
        missing = [t.__name__ for t in return_types if "untrusted_fields" not in t.model_fields]
        assert not missing, (
            "every record-bearing tool return type must declare "
            f"`untrusted_fields: list[str]`; missing on: {missing}"
        )

    def test_eight_canonical_result_types_all_declare_the_field(self):
        # Belt-and-braces against introspection drift: pin the eight
        # types we know carry records today. If the `__all__` discovery
        # above silently misses one, this still catches.
        for cls in (
            PslistSummary,
            PsscanSummary,
            PstreeSummary,
            NetscanSummary,
            QueryRecordsResult,
            GroupByResult,
            SetDifferenceResult,
            SubtreeResult,
        ):
            assert "untrusted_fields" in cls.model_fields, (
                f"{cls.__name__} must declare `untrusted_fields`"
            )
            field = cls.model_fields["untrusted_fields"]
            assert field.annotation == list[str], (
                f"{cls.__name__}.untrusted_fields must be list[str], got {field.annotation}"
            )
