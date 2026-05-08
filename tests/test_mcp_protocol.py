"""Round-trip tests of the SIFT-Guard MCP server's tool surface.

Spawns `server/main.py` as a subprocess via stdio, exercises the real MCP
protocol the way Claude Code will, and verifies:

(1) the tool surface exposes exactly the registered tools — currently
    twelve: `register_evidence`, the four `vol_*` plugin wrappers, the
    four tier-2 analytical tools (`query_records`, `group_by`,
    `set_difference`, `subtree`), and the three writes
    (`record_finding`, `record_correlation`, `update_finding`). Each
    tool's input schema is locked to its declared parameters only (no
    `case_dir` leak); this is the architectural lock for CLAUDE.md
    rule 3.
(2) human-readable warnings reach the LLM over the wire (IRREVERSIBLE
    on register_evidence, latency cost on every vol_* tool).
(3) registration succeeds end-to-end and produces the expected on-disk
    side effects (chmod 444, CASE.yaml, audit JSONL).
(4) a bad input produces a protocol-level error response, not a crash;
    the server stays alive for further calls.

Tests are synchronous at the pytest level and drive the async MCP client
via `asyncio.run`, avoiding a pytest-asyncio dependency.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = str(PROJECT_ROOT / ".venv" / "bin" / "python")
SESSION_TIMEOUT_SECONDS = 20


def _server_params(cwd: Path) -> StdioServerParameters:
    """Spawn the SIFT-Guard server with cwd inside the test's tmp_path so
    the relative `case-data` path resolves there, not in the repo."""
    env = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    return StdioServerParameters(
        command=PYTHON_EXE,
        args=["-m", "server.main"],
        env=env,
        cwd=str(cwd),
    )


async def _list_tools_only(server_cwd: Path):
    async with stdio_client(_server_params(server_cwd)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.list_tools()


def _tool_by_name(listing, name: str):
    """Find a tool by name in a list_tools() result. With more than one
    tool exposed, ordering is not guaranteed by the protocol."""
    for t in listing.tools:
        if t.name == name:
            return t
    raise AssertionError(
        f"tool {name!r} not found in listing; got {[t.name for t in listing.tools]!r}"
    )


async def _full_round_trip(tmp_path: Path) -> dict:
    """Single MCP session: list → ok → not-found error → confinement
    rejection → list again.

    Bundled into one session so the 'server stays alive after error'
    assertion is meaningful — it would be trivial across new sessions.
    Fixture lives under <cwd>/case-data/evidence/ so the path-confinement
    check in `register_evidence` lets it through.
    """
    evidence_dir = tmp_path / "case-data" / "evidence"
    evidence_dir.mkdir(parents=True)
    fixture = evidence_dir / "fixture.dat"
    fixture.write_bytes(secrets.token_bytes(1024))

    results: dict = {}

    async with stdio_client(_server_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            results["ok"] = await session.call_tool(
                "register_evidence",
                arguments={"filepath": str(fixture)},
            )

            results["err"] = await session.call_tool(
                "register_evidence",
                arguments={"filepath": str(evidence_dir / "does-not-exist.dat")},
            )

            # Path-confinement rejection: an absolute path outside the
            # evidence root must be refused with the sanitized message
            # and must not extend the audit chain.
            results["denied"] = await session.call_tool(
                "register_evidence",
                arguments={"filepath": "/etc/passwd"},
            )

            # Verify the session is still healthy after both error kinds.
            results["tools_after"] = await session.list_tools()

    return results


def _run_async(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=SESSION_TIMEOUT_SECONDS))


def _extract_record(call_result) -> dict | None:
    """Pull a structured EvidenceRecord out of a CallToolResult.

    FastMCP attaches `structuredContent` as a dict when the tool returns
    a typed model; older paths put the JSON in a TextContent block.
    Try structured first, fall back to parsing the first text block.
    """
    structured = getattr(call_result, "structuredContent", None)
    if isinstance(structured, dict) and structured:
        # Some FastMCP versions wrap the model under a "result" key.
        if "result" in structured and isinstance(structured["result"], dict):
            return structured["result"]
        return structured
    if call_result.content:
        first = call_result.content[0]
        text = getattr(first, "text", None)
        if text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(parsed, dict) and "result" in parsed and isinstance(
                parsed["result"], dict
            ):
                return parsed["result"]
            return parsed if isinstance(parsed, dict) else None
    return None


# ---------------------------------------------------------------------------
# Architectural-lock tests (tools/list)
# ---------------------------------------------------------------------------


class TestToolSurface:
    def test_thirteen_tool_surface_is_locked(self, tmp_path: Path):
        # Surface lock: every new MCP tool added to server/main.py
        # forces an explicit update here. Adding a tool without
        # extending this set means the surface grew silently — which
        # is exactly the failure mode the test is here to prevent.
        #
        # Week-6 day-1 expansion: the validator/orchestrator substrate
        # adds two writes — record_correlation (validator) and
        # update_finding (orchestrator) — bringing the surface from
        # 10 to 12. record_finding remains the analyst's write.
        # Week-7 G-2 expansion: rag_query exposes the ATT&CK corpus
        # to the validator subagent for grounding correlation
        # hypotheses; 12 → 13. Week-8 cmdline+malfind expansion:
        # 13 → 15. Week-8 disk-side expansion: disk_mft_timeline,
        # disk_prefetch, disk_evtx, disk_registry add four
        # disk-image tier-1 wrappers; 15 → 19. The agent-layer
        # surface restriction (validator-only for rag_query;
        # process_analyst-only for cmdline/malfind; disk_analyst-
        # only for the four disk tools) lives in
        # `.claude/agents/<name>.md`, not at the MCP-server level
        # — every connected client sees all 19 tools listed.
        listing = _run_async(_list_tools_only(tmp_path))
        tool_names = {t.name for t in listing.tools}
        assert tool_names == {
            "register_evidence",
            "vol_pslist",
            "vol_psscan",
            "vol_pstree",
            "vol_netscan",
            "vol_cmdline",
            "vol_malfind",
            "disk_mft_timeline",
            "disk_prefetch",
            "disk_evtx",
            "disk_registry",
            "query_records",
            "group_by",
            "set_difference",
            "subtree",
            "record_finding",
            "record_correlation",
            "update_finding",
            "rag_query",
        }, (
            "expected exactly the 19-tool surface (tier-0/tier-1/tier-2 "
            "plus three writes plus rag_query); got "
            f"{sorted(tool_names)}"
        )

    def test_register_evidence_parameters_are_locked_to_filepath(
        self, tmp_path: Path
    ):
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "register_evidence")
        schema = tool.inputSchema

        assert schema.get("type") == "object"
        properties = schema.get("properties", {})
        assert set(properties.keys()) == {"filepath"}, (
            "register_evidence must accept only `filepath`; got "
            f"{sorted(properties.keys())}. If `case_dir` (or any other path) "
            "shows up here, CLAUDE.md rule 3 is broken."
        )
        assert properties["filepath"].get("type") == "string"
        assert "filepath" in schema.get("required", []), (
            "filepath must be required, not optional"
        )

    def test_vol_pslist_parameters_are_locked_to_evidence_id(
        self, tmp_path: Path
    ):
        # Symmetric to the register_evidence schema lock. CLAUDE.md
        # rule 3: the agent never names a path or a plugin — only an
        # evidence_id resolved through the registry. If `case_dir`,
        # `plugin_name`, or any free-form path leaks into this schema,
        # the architectural guarantee is broken.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_pslist")
        schema = tool.inputSchema

        assert schema.get("type") == "object"
        properties = schema.get("properties", {})
        assert set(properties.keys()) == {"evidence_id"}, (
            "vol_pslist must accept only `evidence_id`; got "
            f"{sorted(properties.keys())}. If `case_dir`, `plugin_name`, or "
            "any path field shows up here, CLAUDE.md rule 3 is broken."
        )
        assert properties["evidence_id"].get("type") == "string"
        assert "evidence_id" in schema.get("required", []), (
            "evidence_id must be required, not optional"
        )

    def test_tool_description_carries_irreversible_warning(self, tmp_path: Path):
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "register_evidence")
        assert tool.description, "register_evidence must carry a description"
        assert "IRREVERSIBLE" in tool.description, (
            "the IRREVERSIBLE warning must reach the LLM over the wire — "
            "this is the human-readable signal that calling this tool "
            "permanently chmods the source file"
        )

    def test_vol_pslist_description_carries_cost_warning(self, tmp_path: Path):
        # The LLM should see latency cost in the tool description so it
        # can decide whether the call is worth making. "5-15 seconds"
        # is the empirically-measured Rocba range from Phase B.4.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_pslist")
        assert tool.description, "vol_pslist must carry a description"
        assert "5-15 seconds" in tool.description, (
            "vol_pslist description must surface its latency cost — "
            "the LLM uses this to decide whether to invoke. Found: "
            f"{tool.description!r}"
        )

    def test_vol_psscan_parameters_are_locked_to_evidence_id(
        self, tmp_path: Path
    ):
        # Symmetric to vol_pslist's lock. Same architectural rule:
        # no `case_dir`, no `plugin_name`, no path leak — only
        # `evidence_id`. Schema-introspection test
        # `test_no_path_fields.py` is the systemic guard; this is
        # the per-tool tripwire that surfaces a failure with a
        # vol_psscan-specific message rather than a generic one.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_psscan")
        schema = tool.inputSchema

        assert schema.get("type") == "object"
        properties = schema.get("properties", {})
        assert set(properties.keys()) == {"evidence_id"}, (
            "vol_psscan must accept only `evidence_id`; got "
            f"{sorted(properties.keys())}. If `case_dir`, `plugin_name`, or "
            "any path field shows up here, CLAUDE.md rule 3 is broken."
        )
        assert properties["evidence_id"].get("type") == "string"
        assert "evidence_id" in schema.get("required", []), (
            "evidence_id must be required, not optional"
        )

    def test_vol_psscan_description_carries_cost_warning(self, tmp_path: Path):
        # psscan is materially more expensive than pslist (~6m on
        # Rocba vs ~5s for pslist). The LLM needs to see this so it
        # doesn't fire the tool reflexively after every pslist call.
        # "5-10 minutes" is the documented range; "Rocba: 6m36s" is
        # the empirical anchor.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_psscan")
        assert tool.description, "vol_psscan must carry a description"
        assert "5-10 minutes" in tool.description, (
            "vol_psscan description must surface its latency cost — "
            "the LLM uses this to decide whether to invoke. Found: "
            f"{tool.description!r}"
        )

    def test_vol_pstree_parameters_are_locked_to_evidence_id(
        self, tmp_path: Path
    ):
        # Symmetric to vol_pslist / vol_psscan locks. Same architectural
        # rule: no case_dir, no plugin_name, no path leak — only
        # evidence_id. Schema-introspection test test_no_path_fields.py
        # is the systemic guard; this is the per-tool tripwire that
        # surfaces a failure with a vol_pstree-specific message.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_pstree")
        schema = tool.inputSchema

        assert schema.get("type") == "object"
        properties = schema.get("properties", {})
        assert set(properties.keys()) == {"evidence_id"}, (
            "vol_pstree must accept only `evidence_id`; got "
            f"{sorted(properties.keys())}. If `case_dir`, `plugin_name`, or "
            "any path field shows up here, CLAUDE.md rule 3 is broken."
        )
        assert properties["evidence_id"].get("type") == "string"
        assert "evidence_id" in schema.get("required", []), (
            "evidence_id must be required, not optional"
        )

    def test_vol_pstree_description_carries_cost_warning(self, tmp_path: Path):
        # pstree's runtime sits between pslist (~5s) and psscan (~6m):
        # ~30s on Rocba. The LLM should see the range so it doesn't
        # treat pstree as free like pslist or expensive like psscan.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_pstree")
        assert tool.description, "vol_pstree must carry a description"
        assert "25-45 seconds" in tool.description, (
            "vol_pstree description must surface its latency cost — "
            "the LLM uses this to decide whether to invoke. Found: "
            f"{tool.description!r}"
        )

    def test_vol_netscan_parameters_are_locked_to_evidence_id(
        self, tmp_path: Path
    ):
        # Symmetric to the other vol_* locks. Same architectural rule:
        # no case_dir, no plugin_name, no path leak — only evidence_id.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_netscan")
        schema = tool.inputSchema

        assert schema.get("type") == "object"
        properties = schema.get("properties", {})
        assert set(properties.keys()) == {"evidence_id"}, (
            "vol_netscan must accept only `evidence_id`; got "
            f"{sorted(properties.keys())}. If `case_dir`, `plugin_name`, or "
            "any path field shows up here, CLAUDE.md rule 3 is broken."
        )
        assert properties["evidence_id"].get("type") == "string"
        assert "evidence_id" in schema.get("required", []), (
            "evidence_id must be required, not optional"
        )

    def test_vol_netscan_description_carries_cost_warning(
        self, tmp_path: Path
    ):
        # netscan is the slowest of the four vol_* tools (~9m on
        # Rocba). The LLM must see the cost so it doesn't queue it
        # reflexively after every other call.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "vol_netscan")
        assert tool.description, "vol_netscan must carry a description"
        assert "5-12 minutes" in tool.description, (
            "vol_netscan description must surface its latency cost — "
            "the LLM uses this to decide whether to invoke. Found: "
            f"{tool.description!r}"
        )

    # -----------------------------------------------------------------
    # Tier-2 analytical-tool surface locks (week 5)
    # -----------------------------------------------------------------

    def test_query_records_parameter_set(self, tmp_path: Path):
        # Tier-2 analytical tool. The agent supplies evidence_id +
        # plugin_name + filter / projection / paging — never a path,
        # never a file, never a case_dir.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "query_records")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "evidence_id",
            "plugin_name",
            "filters",
            "fields",
            "limit",
            "offset",
        }, (
            "query_records parameter set drifted; got "
            f"{sorted(properties.keys())}"
        )
        # plugin_name is a closed enum across the supported plugins.
        plugin_enum = properties["plugin_name"].get("enum", [])
        assert set(plugin_enum) == {
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
        }, f"plugin_name enum drifted: {plugin_enum}"
        assert "evidence_id" in tool.inputSchema.get("required", [])

    def test_group_by_parameter_set(self, tmp_path: Path):
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "group_by")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "evidence_id",
            "plugin_name",
            "field",
            "filters",
            "top_n",
        }, (
            "group_by parameter set drifted; got "
            f"{sorted(properties.keys())}"
        )
        for required in ("evidence_id", "plugin_name", "field"):
            assert required in tool.inputSchema.get("required", []), (
                f"{required} must be required"
            )

    def test_set_difference_parameter_set(self, tmp_path: Path):
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "set_difference")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "evidence_id",
            "plugin_a",
            "plugin_b",
            "key",
            "direction",
            "fields",
            "limit",
        }, (
            "set_difference parameter set drifted; got "
            f"{sorted(properties.keys())}"
        )
        # Both plugin sides are closed enums; same set as query_records.
        for side in ("plugin_a", "plugin_b"):
            plugin_enum = properties[side].get("enum", [])
            assert set(plugin_enum) == {
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
            }, f"{side} enum drifted: {plugin_enum}"

    def test_subtree_parameter_set(self, tmp_path: Path):
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "subtree")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "evidence_id",
            "plugin_name",
            "root_pid",
            "max_depth",
            "fields",
        }, (
            "subtree parameter set drifted; got "
            f"{sorted(properties.keys())}"
        )
        for required in ("evidence_id", "plugin_name", "root_pid"):
            assert required in tool.inputSchema.get("required", []), (
                f"{required} must be required"
            )

    # -----------------------------------------------------------------
    # Tier-1 summary-shape locks (week 5)
    #
    # vol_* tools now return Summary objects. The tools/list endpoint
    # publishes the full input schema; the output schema is implicit
    # in pydantic's return annotation but is not exposed by FastMCP
    # over the wire. We pin instead on the description (which the LLM
    # sees) carrying the word "Summary" so a regression that flips
    # the return type back to PslistResult shows up here.
    # -----------------------------------------------------------------

    def test_audit_line_in_extraction_ref_is_nullable(self, tmp_path: Path):
        """ExtractionRef.audit_line must be Optional[int] — `None` is
        the migration semantic for legacy chain entries written
        before the field existed. A future change that makes it
        required would re-break the migration approach.
        """
        from server.schemas import ExtractionRef
        schema = ExtractionRef.model_json_schema()
        prop = schema["properties"]["audit_line"]
        # pydantic v2 emits Optional[int] as anyOf[{type:integer}, {type:null}]
        any_of = prop.get("anyOf") or []
        types = {t.get("type") for t in any_of}
        assert "null" in types, (
            "ExtractionRef.audit_line must accept null per the "
            "no-retroactive-backfill migration approach"
        )
        assert "integer" in types, (
            "ExtractionRef.audit_line must also accept int — value type"
        )

    def test_audit_line_required_on_tier2_result_models(self, tmp_path: Path):
        """Tier-2 *Result.audit_line is REQUIRED (no `None`). Every
        tier-2 call happens under the new schema, so there's never a
        case where audit_line should be missing."""
        from server.schemas import (
            QueryRecordsResult,
            GroupByResult,
            SetDifferenceResult,
            SubtreeResult,
        )
        for cls in (
            QueryRecordsResult,
            GroupByResult,
            SetDifferenceResult,
            SubtreeResult,
        ):
            schema = cls.model_json_schema()
            assert "audit_line" in schema["required"], (
                f"{cls.__name__}.audit_line must be required, not optional"
            )
            prop = schema["properties"]["audit_line"]
            assert prop.get("type") == "integer", (
                f"{cls.__name__}.audit_line must be `int`, not nullable"
            )

    def test_tier1_descriptions_advertise_summary_return(self, tmp_path: Path):
        listing = _run_async(_list_tools_only(tmp_path))
        for name in ("vol_pslist", "vol_psscan", "vol_pstree", "vol_netscan"):
            tool = _tool_by_name(listing, name)
            assert "Summary" in tool.description, (
                f"{name} description must advertise its Summary return; "
                f"found: {tool.description!r}"
            )
            assert "extraction" in tool.description.lower(), (
                f"{name} description must mention the on-disk extraction "
                f"sink; found: {tool.description!r}"
            )

    def test_record_finding_parameter_set(self, tmp_path: Path):
        # record_finding is the analyst-write tool — different shape
        # from the read-only vol_* tools but the same evidence_id-only
        # boundary applies for the path-confinement question (no
        # free-form path field). The schema-introspection test in
        # test_no_path_fields.py is the systemic guard; here we check
        # the explicit parameter set so a regression that adds, say,
        # a `case_dir` parameter would surface immediately.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "record_finding")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "evidence_id",
            "analyst",
            "category",
            "severity",
            "confidence",
            "title",
            "description",
            "evidence_refs",
            "hypothesis",
        }, (
            "record_finding parameter set drifted; got "
            f"{sorted(properties.keys())}. If `case_dir`, `finding_id`, "
            "`created_at`, `state`, or `tool_invocations` shows up here, "
            "the server-controlled boundary is broken."
        )

    def test_record_finding_confidence_includes_disputed_for_validator(
        self, tmp_path: Path
    ):
        # The Literal must include DISPUTED — not because analysts can
        # set it (they can't; record_finding rejects + audits), but
        # because the same DraftFinding schema is the type the week-6
        # validator will use when it promotes a finding. If DISPUTED
        # were absent from the protocol-level enum the validator's
        # promotion call couldn't typecheck. This test pins the
        # surface so that architectural choice is visible.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "record_finding")
        properties = tool.inputSchema.get("properties", {})
        confidence = properties.get("confidence", {})
        # JSON Schema for a Literal[a,b,c,d] surfaces as `enum: [...]`.
        assert "DISPUTED" in confidence.get("enum", []), (
            "DISPUTED must be in the protocol-level confidence enum; "
            f"got {confidence!r}. The runtime check in record_finding "
            "audits + rejects analyst-supplied DISPUTED."
        )

    # -----------------------------------------------------------------
    # Validator/orchestrator-substrate surface locks (week 6 day 1)
    # -----------------------------------------------------------------

    def test_record_correlation_parameter_set(self, tmp_path: Path):
        # `record_correlation` is the validator-write tool. Same
        # evidence_id-only-no-path principle: no `case_dir`, no
        # `correlation_id` (server-set), no `created_at`, no
        # `audit_line`. The parameter list is wide because the
        # function dispatches on `correlation_type` and per-type
        # required fields are validated at construction time.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "record_correlation")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "case_id",
            "iteration_number",
            "correlation_type",
            "evidence_refs",
            "hypothesis",
            "target_finding_ids",
            "finding_a_id",
            "finding_b_id",
            "target_finding_id",
            "strength",
            "severity",
            "resolvable_by_followup",
            "target_analyst",
            "related_finding_ids",
            "focus_context",
            "rationale",
        }, (
            "record_correlation parameter set drifted; got "
            f"{sorted(properties.keys())}. If `correlation_id`, "
            "`created_at`, `audit_line`, or any path field shows up "
            "here, the server-controlled boundary is broken."
        )
        for required in (
            "case_id",
            "iteration_number",
            "correlation_type",
            "evidence_refs",
            "hypothesis",
        ):
            assert required in tool.inputSchema.get("required", []), (
                f"{required} must be required"
            )

    def test_update_finding_parameter_set(self, tmp_path: Path):
        # `update_finding` is the orchestrator's tool. The orchestrator
        # supplies finding_id + new_state + new_confidence +
        # promotion_rule + driving_correlation_ids; previous_state and
        # previous_confidence are SERVER-DERIVED (read from the chain),
        # never agent-supplied. Likewise update_id, created_at,
        # audit_line are server-set.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "update_finding")
        properties = tool.inputSchema.get("properties", {})
        assert set(properties.keys()) == {
            "finding_id",
            "iteration_number",
            "new_state",
            "new_confidence",
            "promotion_rule",
            "driving_correlation_ids",
            "orchestrator_version",
        }, (
            "update_finding parameter set drifted; got "
            f"{sorted(properties.keys())}. If `previous_state`, "
            "`previous_confidence`, `update_id`, `created_at`, or "
            "`audit_line` shows up here, the server-derived boundary "
            "is broken — the orchestrator could spoof the predecessor "
            "state by passing a chosen value."
        )
        for required in (
            "finding_id",
            "iteration_number",
            "new_state",
            "new_confidence",
            "promotion_rule",
            "driving_correlation_ids",
            "orchestrator_version",
        ):
            assert required in tool.inputSchema.get("required", []), (
                f"{required} must be required"
            )

    def test_record_correlation_correlation_type_enum(self, tmp_path: Path):
        # `correlation_type` is one of five Literal values; the JSON
        # schema must surface the closed enum so a client can autocomplete
        # / validate against it.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "record_correlation")
        # FastMCP may resolve Literal[Enum] either as `enum: [...]`
        # directly OR via `$ref` into a `$defs` table. Look in both.
        properties = tool.inputSchema.get("properties", {})
        ct = properties.get("correlation_type", {})
        defs = tool.inputSchema.get("$defs", {})
        observed_values: set[str] = set()
        if "enum" in ct:
            observed_values = set(ct["enum"])
        elif "$ref" in ct:
            ref_name = ct["$ref"].rsplit("/", 1)[-1]
            referenced = defs.get(ref_name, {})
            if "enum" in referenced:
                observed_values = set(referenced["enum"])
        assert observed_values == {
            "corroborates",
            "contradicts",
            "strengthens",
            "weakens",
            "request_followup",
        }, (
            "correlation_type enum drifted; got "
            f"{observed_values}. Adding a correlation type requires "
            "extending the CorrelationType enum AND this test."
        )

    def test_update_finding_promotion_rule_enum(self, tmp_path: Path):
        # `promotion_rule` is a Literal["R1"..."R6"]; the JSON schema
        # must surface the closed enum so the orchestrator's named
        # rules show up at the protocol boundary.
        listing = _run_async(_list_tools_only(tmp_path))
        tool = _tool_by_name(listing, "update_finding")
        properties = tool.inputSchema.get("properties", {})
        pr = properties.get("promotion_rule", {})
        defs = tool.inputSchema.get("$defs", {})
        observed_values: set[str] = set()
        if "enum" in pr:
            observed_values = set(pr["enum"])
        elif "$ref" in pr:
            ref_name = pr["$ref"].rsplit("/", 1)[-1]
            referenced = defs.get(ref_name, {})
            if "enum" in referenced:
                observed_values = set(referenced["enum"])
        assert observed_values == {"R1", "R2", "R3", "R4", "R5", "R6"}, (
            "promotion_rule enum drifted; got "
            f"{observed_values}. Adding a rule requires extending "
            "PromotionRule AND this test AND the matching update_finding "
            "test."
        )


# ---------------------------------------------------------------------------
# Full round-trip — call success, call error, recovery
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_full_session_call_then_error_then_recovery(self, tmp_path: Path):
        results = _run_async(_full_round_trip(tmp_path))
        ok = results["ok"]
        err = results["err"]
        tools_after = results["tools_after"]

        # (a) success call did not error.
        assert getattr(ok, "isError", False) is False, (
            f"register_evidence with a valid path returned an error: {ok!r}"
        )

        # (b) structured EvidenceRecord parsed from the response.
        record = _extract_record(ok)
        assert record is not None, (
            f"could not extract EvidenceRecord payload from {ok!r}"
        )
        for key in (
            "evidence_id",
            "original_filename",
            "absolute_path",
            "sha256",
            "size_bytes",
            "artifact_class",
            "registered_at",
            "file_mode_after_registration",
        ):
            assert key in record, f"EvidenceRecord missing field: {key}"
        assert record["original_filename"] == "fixture.dat"
        assert record["size_bytes"] == 1024
        assert len(record["sha256"]) == 64
        assert record["artifact_class"] == "unknown"
        assert record["file_mode_after_registration"] == "0o444"

        # (c) the actual file on disk is chmod 444. Fixture lives under
        # the evidence root so the path-confinement check let it through.
        fixture = tmp_path / "case-data" / "evidence" / "fixture.dat"
        mode = stat.S_IMODE(fixture.stat().st_mode)
        assert mode == 0o444, f"expected 0o444 after registration, got {oct(mode)}"

        # (d) audit log exists with exactly one line.
        audit = tmp_path / "case-data" / "audit" / "sift-guard-mcp.jsonl"
        assert audit.exists(), "audit log was not written"
        lines = audit.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1, f"expected one audit line, got {len(lines)}"
        entry = json.loads(lines[0])
        assert entry["tool_name"] == "register_evidence"
        assert entry["evidence_id"] == record["evidence_id"]
        assert entry["prev_line_hash"] == "0" * 64

        # (e) CASE.yaml exists.
        case_yaml = tmp_path / "case-data" / "CASE.yaml"
        assert case_yaml.exists(), "CASE.yaml was not written"

        # Error path: non-existent file becomes a protocol-level error
        # response, not a crash.
        assert getattr(err, "isError", False) is True, (
            f"non-existent path should yield isError=True; got {err!r}"
        )
        # Audit log must NOT have grown — the chain doesn't include the
        # failed registration.
        lines_after = audit.read_text(encoding="utf-8").splitlines()
        assert len(lines_after) == 1, (
            "failed registration must not append to the audit chain; "
            f"got {len(lines_after)} lines after error"
        )

        # Path-confinement: /etc/passwd is outside <case_dir>/evidence/.
        # The harness must surface isError=True with the sanitized
        # message ("Path outside evidence directory rejected"), the
        # offending path must not be echoed in the response, and the
        # audit chain must not grow. This is the over-the-wire proof
        # of CLAUDE.md Hard Rule #2 / Ground-truth-isolation rule 3 —
        # the agent cannot route itself out of the case sandbox even
        # by handing the server a fully-qualified absolute path.
        denied = results["denied"]
        assert getattr(denied, "isError", False) is True, (
            f"/etc/passwd should yield isError=True; got {denied!r}"
        )
        denied_text = "".join(
            getattr(c, "text", "") or "" for c in (denied.content or [])
        )
        assert "Path outside evidence directory rejected" in denied_text, (
            f"sanitized rejection message missing from response: {denied_text!r}"
        )
        # Sanitization: the offending path must not appear anywhere in
        # the LLM-visible response.
        assert "/etc/passwd" not in denied_text, (
            "rejection response must not echo the agent-supplied path "
            f"back; got: {denied_text!r}"
        )
        lines_after_denied = audit.read_text(encoding="utf-8").splitlines()
        assert len(lines_after_denied) == 1, (
            "path-confinement rejection must not append to the audit "
            f"chain; got {len(lines_after_denied)} lines after rejection"
        )

        # Server stays alive after both error kinds: list_tools succeeded.
        tool_names_after = {t.name for t in tools_after.tools}
        assert tool_names_after == {
            "register_evidence",
            "vol_pslist",
            "vol_psscan",
            "vol_pstree",
            "vol_netscan",
            "vol_cmdline",
            "vol_malfind",
            "disk_mft_timeline",
            "disk_prefetch",
            "disk_evtx",
            "disk_registry",
            "query_records",
            "group_by",
            "set_difference",
            "subtree",
            "record_finding",
            "record_correlation",
            "update_finding",
            "rag_query",
        }
