"""Tier-2 analytical MCP tools.

Tier-2 tools (`query_records`, `group_by`, `set_difference`, `subtree`)
read previously-stored tier-1 extractions from
`case-data/extractions/<evidence_id>/<plugin_name>.json` and compose
narrowed answers — bounded result sets, single field aggregations,
cross-plugin set differences, parent-child subtree extracts.

Architectural rules (week 5 tier-1/tier-2 split):

  - Tier-2 tools NEVER invoke Volatility. They read
    already-extracted JSON. Re-extracting requires invoking the
    matching tier-1 tool (which is idempotent on
    (evidence_id, plugin_name)).
  - Every tier-2 tool's return MUST stay under ~10 KB JSON. Limits
    are runtime-enforced and audited under
    `<tool>:rejected_limit_too_large`.
  - Field-name validation is strict. Unknown field references reject
    with `<tool>:rejected_unknown_field` so a malformed filter
    cannot become an unrecorded probe channel.
  - Hash-chain integrity of stored extractions is verified on every
    cache read (see `server.extractions.load_extraction`); a
    mismatch lands as `<tool>:hash_mismatch` and a sanitized
    `ValueError`.

The agent surface for these tools accepts `plugin_name` as a Literal
constrained to the four supported plugins. An unknown plugin name is
caught by pydantic at the MCP boundary before the tool body runs;
the rejection paths the body catches are (a) no extraction exists
for the requested pair, (b) the field references are unknown, (c)
limits are out of bounds, (d) cross-plugin keys disagree on
existence.
"""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from server.audit import append_audit_entry, peek_next_line_number
from server.extractions import (
    ExtractionNotFoundError,
    HashMismatchError,
    load_extraction,
)
from server.rejections_log import append_rejection_record
from server.schemas import (
    PLUGIN_UNTRUSTED_RECORD_FIELDS,
    ExtractionRef,
    FieldFilter,
    GroupByResult,
    PluginName,
    QueryRecordsResult,
    SetDifferenceResult,
    SubtreeResult,
    untrusted_fields_for,
)
from server.tools.memory import _resolve_evidence


_QUERY_RECORDS_TOOL = "query_records"
_GROUP_BY_TOOL = "group_by"
_SET_DIFFERENCE_TOOL = "set_difference"
_SUBTREE_TOOL = "subtree"

# Hard caps per the architecture spec. These are not the *defaults*
# (those live in the tool signatures); they are the maximum values
# the agent is allowed to request before the runtime gate audits and
# rejects. The 10 KB output ceiling is held by the smaller of the
# default and the cap on each tool — limit=200 records of ~50 byte
# projection fits comfortably under the ceiling; limit=500 (set_diff)
# fits because the diff records are the only content.
_QUERY_RECORDS_LIMIT_CAP = 200
_GROUP_BY_TOP_N_CAP = 200
_SET_DIFFERENCE_LIMIT_CAP = 500
_SUBTREE_MAX_DEPTH_CAP = 10
_SUBTREE_NODE_TRUNCATION = 200


# Field sets per plugin. Validated against filters, projection
# fields, and group_by keys. `children` is intentionally excluded
# from pstree's queryable surface — it's a recursive list, not a
# scalar; subtree composition is the `subtree` tool's job, not
# query_records'.
_PSLIST_FIELDS: frozenset[str] = frozenset(
    {
        "pid",
        "ppid",
        "image_file_name",
        "offset_v",
        "threads",
        "handles",
        "session_id",
        "wow64",
        "create_time",
        "exit_time",
    }
)
_PSTREE_FIELDS: frozenset[str] = _PSLIST_FIELDS | frozenset({"audit", "cmd", "path"})
_NETSCAN_FIELDS: frozenset[str] = frozenset(
    {
        "proto",
        "local_addr",
        "local_port",
        "foreign_addr",
        "foreign_port",
        "state",
        "pid",
        "owner",
        "offset",
        "created",
    }
)
_CMDLINE_FIELDS: frozenset[str] = frozenset({"pid", "process_name", "cmdline"})
_MALFIND_FIELDS: frozenset[str] = frozenset(
    {
        "pid",
        "process_name",
        "vad_start",
        "vad_tag",
        "protection",
        "hex_dump",
        "disassembly",
    }
)
_DISK_MFT_FIELDS: frozenset[str] = frozenset({"timestamp", "full_path", "entry_type", "file_size"})
_DISK_PREFETCH_FIELDS: frozenset[str] = frozenset(
    {
        "executable_name",
        "run_count",
        "last_run_times",
        "volume_path",
        "referenced_files",
    }
)
_DISK_EVTX_FIELDS: frozenset[str] = frozenset(
    {
        "event_id",
        "timestamp",
        "source",
        "channel",
        "message_summary",
        "logon_type",
    }
)
_DISK_REGISTRY_FIELDS: frozenset[str] = frozenset(
    {"hive_name", "key_path", "value_name", "value_data", "last_modified"}
)
_FIELDS_BY_PLUGIN: dict[str, frozenset[str]] = {
    "windows.pslist.PsList": _PSLIST_FIELDS,
    "windows.psscan.PsScan": _PSLIST_FIELDS,
    "windows.pstree.PsTree": _PSTREE_FIELDS,
    "windows.netscan.NetScan": _NETSCAN_FIELDS,
    "windows.cmdline.CmdLine": _CMDLINE_FIELDS,
    "windows.malfind.Malfind": _MALFIND_FIELDS,
    "disk.mft.MftTimeline": _DISK_MFT_FIELDS,
    "disk.prefetch.Prefetch": _DISK_PREFETCH_FIELDS,
    "disk.evtx.EventLog": _DISK_EVTX_FIELDS,
    "disk.registry.Registry": _DISK_REGISTRY_FIELDS,
}


# Field-name aliases per plugin.
#
# Analysts repeatedly request the malfind plugin's VAD region with
# the names the published Volatility 3 docs / blog posts use
# (``start``, ``end``, ``tag``, ``disasm``, ``hexdump``) — but the
# server's allow-list and the on-disk extraction use the names from
# the plugin's actual TreeGrid column headers (``vad_start``,
# ``vad_tag``, ``disassembly``, ``hex_dump``). Without aliasing,
# every malfind query was rejected and the analyst burned tokens in
# a retry loop guessing field names. See 2026-05-13 SRL-2015 run
# (commit 2272078 surfaced the rejection inputs via the side-channel
# log; this commit closes the loop).
#
# We map analyst-friendly synonyms to the canonical column name; the
# canonical name is what flows through validation, filtering, and
# projection. ``end`` / ``end_va`` / ``vad_end`` are intentionally
# absent: Volatility 3's windows.malfind.Malfind does not expose the
# VAD end address. Asking for it stays a hard rejection so the
# analyst learns to stop asking rather than getting a silent
# truncation.
_PLUGIN_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "windows.malfind.Malfind": {
        "start": "vad_start",
        "start_va": "vad_start",
        "tag": "vad_tag",
        "disasm": "disassembly",
        "hexdump": "hex_dump",
    },
    "windows.pslist.PsList": {
        # The analyst's natural name (matches malfind's actual field
        # name) maps to pslist's image_file_name column.
        "process_name": "image_file_name",
    },
    "windows.psscan.PsScan": {
        "process_name": "image_file_name",
    },
    "windows.pstree.PsTree": {
        "process_name": "image_file_name",
    },
    "windows.cmdline.CmdLine": {
        # The reverse: cmdline's canonical name is ``process_name`` but
        # the analyst frequently asks for ``image_file_name`` (carried
        # across from pslist habits). The 2026-05-13 SRL-v2 run had 6
        # rejections of identical shape
        # ``fields=[pid, ppid, image_file_name, cmdline]`` against
        # cmdline; ``image_file_name`` was the offender. ``ppid`` is
        # not aliasable — cmdline doesn't carry a parent-pid column,
        # the analyst needs to join against pslist for that — but
        # surfacing the alias removes the lower-stakes confusion.
        "image_file_name": "process_name",
        # ``args`` is sometimes asked alongside ``cmdline``: the
        # analyst conceptually wants "the arguments part of the
        # command line", but Vol 3's cmdline plugin only returns the
        # full string (which already includes the program and args).
        # Aliasing to ``cmdline`` so the analyst gets the whole string;
        # they can split client-side if they need to.
        "args": "cmdline",
    },
}


def _canonicalize_field(plugin_name: str, name: str) -> str:
    """Return the canonical field name for ``plugin_name`` if ``name``
    is a known alias; otherwise return ``name`` unchanged.

    Unknown names continue to flow through ``_validate_fields`` and
    get rejected — aliasing only resolves the *known* synonyms.
    """
    return _PLUGIN_FIELD_ALIASES.get(plugin_name, {}).get(name, name)


def _canonicalize_filters(
    plugin_name: str, filters: list[FieldFilter]
) -> list[FieldFilter]:
    """Build a parallel list of filters whose ``field`` is canonical.

    Filters are immutable from the caller's perspective; we
    return a new list so the audit-chain ``input_args`` can still
    reflect the original analyst-supplied field name while the
    execution path uses the canonical form against the actual
    extraction.
    """
    out: list[FieldFilter] = []
    for f in filters:
        canonical = _canonicalize_field(plugin_name, f.field)
        if canonical == f.field:
            out.append(f)
        else:
            out.append(FieldFilter(field=canonical, op=f.op, value=f.value))
    return out

# Where the records list lives in each plugin's stored JSON.
_RECORDS_KEY_BY_PLUGIN: dict[str, str] = {
    "windows.pslist.PsList": "processes",
    "windows.psscan.PsScan": "processes",
    "windows.pstree.PsTree": "processes",
    "windows.netscan.NetScan": "connections",
    "windows.cmdline.CmdLine": "processes",
    "windows.malfind.Malfind": "detections",
    "disk.mft.MftTimeline": "entries",
    "disk.prefetch.Prefetch": "entries",
    "disk.evtx.EventLog": "events",
    "disk.registry.Registry": "keys",
}


class _RejectionReason(StrEnum):
    """Rejection paths shared across tier-2 tools.

    Distinct from the memory module's `_RejectionReason` because the
    surface differs: tier-2 has no artifact-class check (the
    extraction's existence implies tier-1 already validated), and it
    adds extraction/field/limit/key/plugin-pair checks.
    """

    EVIDENCE_NOT_FOUND = "evidence_not_found"
    EXTRACTION_NOT_FOUND = "extraction_not_found"
    UNKNOWN_FIELD = "unknown_field"
    LIMIT_TOO_LARGE = "limit_too_large"
    INVALID_KEY = "invalid_key"
    SAME_PLUGIN = "same_plugin"
    ROOT_NOT_FOUND = "root_not_found"


class _RejectionRecord(BaseModel):
    """Audit payload for a tier-2 rejection.

    Same two-field shape as `server.tools.memory._RejectionRecord`
    (reason + evidence_id) so an operator paging through the audit
    log sees a consistent rejection-line structure across both tool
    families. The enum is tier-2's own; we keep the model
    self-contained rather than cross-import to avoid coupling tool
    modules through a shared rejection schema.
    """

    reason: _RejectionReason
    evidence_id: str


def _log_rejection(
    case_dir: Path,
    tool_name: str,
    reason: _RejectionReason,
    evidence_id: str,
    input_args: dict,
) -> None:
    """Append one rejection line to the audit chain, plus a sanitized
    copy of ``input_args`` to the side-channel rejections log.

    The audit chain still records only the input hash (no agent string
    is round-tripped through it). The side-channel log gives the
    operator console the *shape* of the rejected input —
    ``query_records:rejected_unknown_field`` is useless without
    knowing which field name tripped the validator. Sanitization
    (evidence-block stripping, length cap) lives in
    ``server.rejections_log``.
    """
    rejection = _RejectionRecord(reason=reason, evidence_id=evidence_id)
    entry = append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{tool_name}:rejected_{reason.value}",
        evidence_id=evidence_id,
        input_args=input_args,
        output=rejection,
    )
    append_rejection_record(case_dir, entry, input_args)


class _HashMismatchRecord(BaseModel):
    """Audit payload for a tier-2 cache-integrity failure.

    Carries a constant `reason` field — same JSON shape as
    `_RejectionRecord` (one string-typed `reason`, one
    `evidence_id`) so a consumer that processes both can use the
    same parser. Distinct class so accidentally writing this payload
    into a regular rejection slot would surface as a type error
    rather than as a misclassified rejection.
    """

    reason: str = "hash_mismatch"
    evidence_id: str


def _log_hash_mismatch(
    case_dir: Path,
    tool_name: str,
    evidence_id: str,
    input_args: dict,
) -> None:
    """Append a hash-mismatch line; same suffix convention as tier-1."""
    rejection = _HashMismatchRecord(evidence_id=evidence_id)
    append_audit_entry(
        case_dir=case_dir,
        tool_name=f"{tool_name}:hash_mismatch",
        evidence_id=evidence_id,
        input_args=input_args,
        output=rejection,
    )


def _validate_evidence_id(
    case_dir_path: Path,
    evidence_id: str,
    tool_name: str,
    input_args: dict,
) -> None:
    """Common gate: evidence must be registered in CASE.yaml.

    Tier-2 tools don't enforce artifact_class — the act of having a
    stored extraction for a plugin already implies tier-1 ran the
    plugin successfully (which means artifact_class was right at
    that point). Re-checking would be redundant.
    """
    if _resolve_evidence(evidence_id, case_dir_path) is None:
        _log_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.EVIDENCE_NOT_FOUND,
            evidence_id,
            input_args,
        )
        raise ValueError("evidence_id not found in CASE.yaml")


def _validate_fields(
    case_dir_path: Path,
    plugin_name: str,
    field_names: list[str],
    tool_name: str,
    evidence_id: str,
    input_args: dict,
) -> None:
    """Reject if any field name is unknown for the plugin's schema.

    All-or-nothing — first unknown field triggers rejection; we don't
    enumerate every bad name. Single audit line keeps the chain
    compact.
    """
    allowed = _FIELDS_BY_PLUGIN[plugin_name]
    for name in field_names:
        if name not in allowed:
            _log_rejection(
                case_dir_path,
                tool_name,
                _RejectionReason.UNKNOWN_FIELD,
                evidence_id,
                input_args,
            )
            raise ValueError("filter or projection references unknown field")


def _load_or_reject(
    case_dir_path: Path,
    evidence_id: str,
    plugin_name: PluginName,
    tool_name: str,
    input_args: dict,
) -> tuple[ExtractionRef, dict]:
    """Load a stored extraction; audit & raise on missing or tampered."""
    try:
        return load_extraction(case_dir_path, evidence_id, plugin_name)
    except ExtractionNotFoundError:
        _log_rejection(
            case_dir_path,
            tool_name,
            _RejectionReason.EXTRACTION_NOT_FOUND,
            evidence_id,
            input_args,
        )
        raise ValueError("no stored extraction for the requested plugin")
    except HashMismatchError:
        _log_hash_mismatch(case_dir_path, tool_name, evidence_id, input_args)
        raise ValueError("cached extraction failed integrity verification")


def _records_of(parsed: dict, plugin_name: str) -> list[dict]:
    """Return the records list from a loaded extraction.

    For pstree, flatten the recursive tree into a list of node dicts;
    each flattened node retains its original fields *minus* `children`
    (which would re-embed the recursive shape). The flattening is
    depth-first, parent-before-children, which keeps the output
    deterministic for downstream hashing.
    """
    if plugin_name == "windows.pstree.PsTree":
        return _flatten_pstree(parsed.get("processes", []))
    key = _RECORDS_KEY_BY_PLUGIN[plugin_name]
    return list(parsed.get(key, []))


def _flatten_pstree(roots: list[dict]) -> list[dict]:
    flat: list[dict] = []

    def visit(node: dict) -> None:
        without_children = {k: v for k, v in node.items() if k != "children"}
        flat.append(without_children)
        for child in node.get("children", []) or []:
            visit(child)

    for r in roots:
        visit(r)
    return flat


def _project(record: dict, fields: list[str]) -> dict:
    """Apply a projection. Empty `fields` returns all keys."""
    if not fields:
        return record
    return {f: record.get(f) for f in fields}


def _record_matches(record: dict, filters: list[FieldFilter]) -> bool:
    """AND-combined filter evaluation."""
    for f in filters:
        actual = record.get(f.field)
        op = f.op
        if op == "eq":
            if actual != f.value:
                return False
        elif op == "ne":
            if actual == f.value:
                return False
        elif op == "is_null":
            if actual is not None:
                return False
        elif op == "is_not_null":
            if actual is None:
                return False
        elif op in ("lt", "le", "gt", "ge"):
            if actual is None or f.value is None:
                return False
            if op == "lt" and not (actual < f.value):
                return False
            if op == "le" and not (actual <= f.value):
                return False
            if op == "gt" and not (actual > f.value):
                return False
            if op == "ge" and not (actual >= f.value):
                return False
        elif op == "contains":
            if actual is None or f.value not in str(actual):
                return False
        elif op == "starts_with":
            if actual is None or not str(actual).startswith(str(f.value)):
                return False
        else:
            # Pydantic Literal on FieldFilter.op should keep us out of
            # this branch; defensive fail-closed if an unknown op
            # somehow slipped through.
            return False
    return True


def _filter_args_for_audit(filters: list[FieldFilter]) -> list[dict]:
    """Render filters as plain dicts for audit input_args.

    `value` is passed through untouched — JSON-serialization of
    arbitrary types in audit's canonical form happens with
    `default=str`, so unrepresentable values become their `str()`
    form. Same property holds for the agent-input echoed into
    rejection lines.
    """
    return [{"field": f.field, "op": f.op, "value": f.value} for f in filters]


def query_records(
    *,
    evidence_id: str,
    plugin_name: PluginName,
    filters: list[FieldFilter] | None = None,
    fields: list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
    case_dir: str = "case-data",
) -> QueryRecordsResult:
    """Project + filter records from a stored extraction.

    Pre-filter `matched_count` reflects the AND of all filters before
    `limit` and `offset` apply. `truncated` is True iff
    `matched_count > limit + offset`.

    Hard limit cap: 200 records. Asking for more is rejected and
    audited; the cap holds the JSON return under the 10 KB ceiling
    even with relatively wide projections.
    """
    case_dir_path = Path(case_dir).resolve()
    filters = filters or []
    fields = fields or []
    input_args = {
        "evidence_id": evidence_id,
        "plugin_name": plugin_name,
        "filters": _filter_args_for_audit(filters),
        "fields": fields,
        "limit": limit,
        "offset": offset,
    }

    _validate_evidence_id(case_dir_path, evidence_id, _QUERY_RECORDS_TOOL, input_args)

    if limit > _QUERY_RECORDS_LIMIT_CAP or limit < 0 or offset < 0:
        _log_rejection(
            case_dir_path,
            _QUERY_RECORDS_TOOL,
            _RejectionReason.LIMIT_TOO_LARGE,
            evidence_id,
            input_args,
        )
        raise ValueError("limit/offset out of allowed range")

    # Resolve known field-name synonyms before validation so the
    # analyst's natural names (``start``, ``tag``, ``disasm``,
    # ``hexdump`` on malfind; ``process_name`` on pslist/psscan/
    # pstree) flow through cleanly. ``input_args`` keeps the original
    # form so the audit chain shows what the analyst actually
    # submitted; ``canonical_*`` carries what we run against the
    # extraction.
    canonical_filters = _canonicalize_filters(plugin_name, filters)
    canonical_fields = [_canonicalize_field(plugin_name, f) for f in fields]
    referenced_fields = [f.field for f in canonical_filters] + canonical_fields
    _validate_fields(
        case_dir_path,
        plugin_name,
        referenced_fields,
        _QUERY_RECORDS_TOOL,
        evidence_id,
        input_args,
    )

    ref, parsed = _load_or_reject(
        case_dir_path,
        evidence_id,
        plugin_name,
        _QUERY_RECORDS_TOOL,
        input_args,
    )

    records = _records_of(parsed, plugin_name)
    matched = [r for r in records if _record_matches(r, canonical_filters)]
    matched_count = len(matched)
    sliced = matched[offset : offset + limit]
    projected = [_project(r, canonical_fields) for r in sliced]
    truncated = matched_count > offset + limit

    # All rejection paths have cleared. The next audit line is THIS
    # call's success line; capture it so the analyst can reference it
    # directly in `record_finding`'s `EvidenceRef`.
    audit_line = peek_next_line_number(case_dir_path)

    result = QueryRecordsResult(
        extraction=ref,
        audit_line=audit_line,
        matched_count=matched_count,
        returned_count=len(projected),
        records=projected,
        truncated=truncated,
        # Projected records carry canonical field keys
        # (analyst-supplied aliases were resolved upstream), so the
        # untrusted-field marker set must reference those canonical
        # names too — otherwise the agent's untrusted-content scan
        # would miss e.g. ``disassembly`` because the analyst typed
        # ``disasm``.
        untrusted_fields=untrusted_fields_for(plugin_name, canonical_fields),
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_QUERY_RECORDS_TOOL,
        evidence_id=evidence_id,
        input_args=input_args,
        output=result,
    )
    return result


def group_by(
    *,
    evidence_id: str,
    plugin_name: PluginName,
    field: str,
    filters: list[FieldFilter] | None = None,
    top_n: int = 50,
    case_dir: str = "case-data",
) -> GroupByResult:
    """Aggregate records by a single field; return descending counts.

    `groups` is sorted by count descending, with ties broken by the
    natural ordering of the value (Python's tuple-tuple comparison
    handles mixed-type values via str fallback in
    `_filter_args_for_audit`). `distinct_values` is the post-filter
    cardinality of the field, useful when the agent wants to know
    whether truncation by `top_n` is hiding tail values.

    Hard cap: top_n ≤ 200.
    """
    case_dir_path = Path(case_dir).resolve()
    filters = filters or []
    input_args = {
        "evidence_id": evidence_id,
        "plugin_name": plugin_name,
        "field": field,
        "filters": _filter_args_for_audit(filters),
        "top_n": top_n,
    }

    _validate_evidence_id(case_dir_path, evidence_id, _GROUP_BY_TOOL, input_args)

    if top_n > _GROUP_BY_TOP_N_CAP or top_n < 0:
        _log_rejection(
            case_dir_path,
            _GROUP_BY_TOOL,
            _RejectionReason.LIMIT_TOO_LARGE,
            evidence_id,
            input_args,
        )
        raise ValueError("top_n out of allowed range")

    # Resolve aliases on the group axis and on each filter's field
    # so the analyst's natural names work without burning a rejection
    # retry. See ``_PLUGIN_FIELD_ALIASES``.
    canonical_field = _canonicalize_field(plugin_name, field)
    canonical_filters = _canonicalize_filters(plugin_name, filters)
    referenced_fields = [f.field for f in canonical_filters] + [canonical_field]
    _validate_fields(
        case_dir_path,
        plugin_name,
        referenced_fields,
        _GROUP_BY_TOOL,
        evidence_id,
        input_args,
    )

    ref, parsed = _load_or_reject(
        case_dir_path,
        evidence_id,
        plugin_name,
        _GROUP_BY_TOOL,
        input_args,
    )

    records = _records_of(parsed, plugin_name)
    filtered = [r for r in records if _record_matches(r, canonical_filters)]
    counter: Counter[Any] = Counter(r.get(canonical_field) for r in filtered)
    distinct_values = len(counter)
    groups = list(counter.most_common(top_n))

    audit_line = peek_next_line_number(case_dir_path)

    # `groups_keys` synthetic name: the untrusted axis is the value
    # side of every (value, count) tuple in `groups`. Marked when the
    # grouped field is itself in the plugin's untrusted record-field
    # set; group_by on `pid` (integer) yields an empty list. Use the
    # canonical name so the lookup matches the plugin's untrusted
    # set regardless of whether the analyst used an alias.
    if canonical_field in PLUGIN_UNTRUSTED_RECORD_FIELDS.get(plugin_name, ()):
        group_untrusted = ["groups_keys"]
    else:
        group_untrusted = []

    # ``field`` echoed in the result reflects the canonical column
    # the aggregation actually walked, not the alias the analyst may
    # have typed. Consistent with ``records`` shape: keys are
    # canonical post-projection.
    result = GroupByResult(
        extraction=ref,
        audit_line=audit_line,
        field=canonical_field,
        total_records=len(filtered),
        distinct_values=distinct_values,
        groups=groups,
        untrusted_fields=group_untrusted,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_GROUP_BY_TOOL,
        evidence_id=evidence_id,
        input_args=input_args,
        output=result,
    )
    return result


def set_difference(
    *,
    evidence_id: str,
    plugin_a: PluginName,
    plugin_b: PluginName,
    key: str,
    direction: str = "a_minus_b",
    fields: list[str] | None = None,
    limit: int = 200,
    case_dir: str = "case-data",
) -> SetDifferenceResult:
    """Compute the cross-plugin set difference on a join key.

    The primary cross-plugin primitive — the validator's "find PIDs
    in psscan that aren't in pslist" rule is one
    `set_difference(plugin_a="windows.psscan.PsScan",
    plugin_b="windows.pslist.PsList", key="pid",
    direction="a_minus_b")` call.

    `direction`:
      - `a_minus_b` — keys in a but not in b (DKOM-hidden candidates
        when a=psscan, b=pslist)
      - `b_minus_a` — keys in b but not in a
      - `symmetric` — keys in exactly one of a or b

    `key` must be a valid field on BOTH plugins. `returned_records`
    are pulled from `plugin_a` for `a_minus_b`/`symmetric`, and from
    `plugin_b` for `b_minus_a`. `fields` projects each returned row.
    Hard cap: limit ≤ 500.

    Same-plugin diff is rejected with
    `set_difference:rejected_same_plugin` — there is no useful diff
    of an extraction against itself, and the request is more likely
    a typo than an intentional probe.
    """
    case_dir_path = Path(case_dir).resolve()
    fields = fields or []
    input_args = {
        "evidence_id": evidence_id,
        "plugin_a": plugin_a,
        "plugin_b": plugin_b,
        "key": key,
        "direction": direction,
        "fields": fields,
        "limit": limit,
    }

    _validate_evidence_id(case_dir_path, evidence_id, _SET_DIFFERENCE_TOOL, input_args)

    if direction not in ("a_minus_b", "b_minus_a", "symmetric"):
        # Pydantic SetDifferenceResult.direction is a Literal but the
        # tool argument is a free string here for runtime audit.
        _log_rejection(
            case_dir_path,
            _SET_DIFFERENCE_TOOL,
            _RejectionReason.INVALID_KEY,
            evidence_id,
            input_args,
        )
        raise ValueError("direction must be a_minus_b/b_minus_a/symmetric")

    if plugin_a == plugin_b:
        _log_rejection(
            case_dir_path,
            _SET_DIFFERENCE_TOOL,
            _RejectionReason.SAME_PLUGIN,
            evidence_id,
            input_args,
        )
        raise ValueError("plugin_a and plugin_b must differ")

    if limit > _SET_DIFFERENCE_LIMIT_CAP or limit < 0:
        _log_rejection(
            case_dir_path,
            _SET_DIFFERENCE_TOOL,
            _RejectionReason.LIMIT_TOO_LARGE,
            evidence_id,
            input_args,
        )
        raise ValueError("limit out of allowed range")

    if key not in _FIELDS_BY_PLUGIN[plugin_a] or key not in _FIELDS_BY_PLUGIN[plugin_b]:
        _log_rejection(
            case_dir_path,
            _SET_DIFFERENCE_TOOL,
            _RejectionReason.INVALID_KEY,
            evidence_id,
            input_args,
        )
        raise ValueError("key is not a valid field on both plugins")

    if fields:
        # Projection is pulled from whichever plugin we return rows
        # from; both should know the field. For a_minus_b/symmetric
        # we pull from plugin_a; for b_minus_a from plugin_b.
        source_plugin = plugin_b if direction == "b_minus_a" else plugin_a
        _validate_fields(
            case_dir_path,
            source_plugin,
            fields,
            _SET_DIFFERENCE_TOOL,
            evidence_id,
            input_args,
        )

    ref_a, parsed_a = _load_or_reject(
        case_dir_path,
        evidence_id,
        plugin_a,
        _SET_DIFFERENCE_TOOL,
        input_args,
    )
    ref_b, parsed_b = _load_or_reject(
        case_dir_path,
        evidence_id,
        plugin_b,
        _SET_DIFFERENCE_TOOL,
        input_args,
    )

    records_a = _records_of(parsed_a, plugin_a)
    records_b = _records_of(parsed_b, plugin_b)
    keys_a = {r.get(key) for r in records_a if r.get(key) is not None}
    keys_b = {r.get(key) for r in records_b if r.get(key) is not None}

    a_only = keys_a - keys_b
    b_only = keys_b - keys_a
    intersection = keys_a & keys_b

    # Set-cardinality counts are agent-visible primary; record counts
    # and duplicate-key counts surface alongside so the agent can
    # tell pool-tag aliasing from real entity-count differences. See
    # SetDifferenceResult docstring.
    a_record_count = len(records_a)
    b_record_count = len(records_b)
    a_duplicate_key_count = _count_duplicate_keys(records_a, key)
    b_duplicate_key_count = _count_duplicate_keys(records_b, key)

    if direction == "a_minus_b":
        returned_keys = a_only
        source_records = records_a
        total_matching = sum(1 for r in records_a if r.get(key) in returned_keys)
    elif direction == "b_minus_a":
        returned_keys = b_only
        source_records = records_b
        total_matching = sum(1 for r in records_b if r.get(key) in returned_keys)
    else:  # symmetric
        returned_keys = a_only | b_only
        source_records = records_a + records_b
        total_matching = sum(1 for r in source_records if r.get(key) in returned_keys)

    # Per-record (NOT per-key) returned set: PID 7900's two
    # pool-aliased EPROCESS records both come back when querying
    # a_only. Subject to `limit`; truncated reflects whether any
    # matching record was dropped.
    diff_records: list[dict] = []
    for r in source_records:
        k = r.get(key)
        if k in returned_keys:
            diff_records.append(_project(r, fields))
            if len(diff_records) >= limit:
                break

    truncated = total_matching > len(diff_records)

    audit_line = peek_next_line_number(case_dir_path)

    # Source plugin: whichever side `returned_records` were pulled
    # from. For symmetric we returned a mix of both, but the source
    # plugin's untrusted-field set is identical between any two
    # plugins that share a record schema (pslist/psscan are aliased);
    # a true cross-schema symmetric (e.g., pslist↔netscan) cannot
    # happen because `key` must be valid on both, and only `pid`
    # qualifies — which is integer-typed in both schemas.
    source_plugin_for_untrusted = plugin_b if direction == "b_minus_a" else plugin_a
    diff_untrusted = untrusted_fields_for(source_plugin_for_untrusted, fields)

    result = SetDifferenceResult(
        extraction_a=ref_a,
        extraction_b=ref_b,
        audit_line=audit_line,
        key=key,
        direction=direction,  # type: ignore[arg-type]
        a_only_count=len(a_only),
        b_only_count=len(b_only),
        intersection_count=len(intersection),
        a_record_count=a_record_count,
        b_record_count=b_record_count,
        a_duplicate_key_count=a_duplicate_key_count,
        b_duplicate_key_count=b_duplicate_key_count,
        returned_records=diff_records,
        truncated=truncated,
        untrusted_fields=diff_untrusted,
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_SET_DIFFERENCE_TOOL,
        evidence_id=evidence_id,
        input_args=input_args,
        output=result,
    )
    return result


def subtree(
    *,
    evidence_id: str,
    plugin_name: PluginName,
    root_pid: int,
    max_depth: int = 3,
    fields: list[str] | None = None,
    case_dir: str = "case-data",
) -> SubtreeResult:
    """Extract a subtree of process descendants rooted at `root_pid`.

    Pstree-only — only pstree carries parent-child structure. Returns
    a flat node list with each node's `depth` field added; the agent
    can reconstruct hierarchy from `(pid, ppid, depth)` without the
    recursive shape blowing the budget.

    `max_depth` is bounded at 10. The 200-node truncation is the
    final size guard — a wide subtree (e.g., the Teams.exe
    1900-child fan-out the validator will eventually flag) drops
    descendants past the 200th and sets `truncated=True`.
    """
    case_dir_path = Path(case_dir).resolve()
    fields = fields or []
    input_args = {
        "evidence_id": evidence_id,
        "plugin_name": plugin_name,
        "root_pid": root_pid,
        "max_depth": max_depth,
        "fields": fields,
    }

    _validate_evidence_id(case_dir_path, evidence_id, _SUBTREE_TOOL, input_args)

    if plugin_name != "windows.pstree.PsTree":
        # Defense-in-depth: the Literal in the MCP signature should
        # keep us out of here, but if the tool is invoked
        # programmatically with a wider type, we audit and reject.
        _log_rejection(
            case_dir_path,
            _SUBTREE_TOOL,
            _RejectionReason.INVALID_KEY,
            evidence_id,
            input_args,
        )
        raise ValueError("subtree requires plugin_name=windows.pstree.PsTree")

    if max_depth > _SUBTREE_MAX_DEPTH_CAP or max_depth < 0:
        _log_rejection(
            case_dir_path,
            _SUBTREE_TOOL,
            _RejectionReason.LIMIT_TOO_LARGE,
            evidence_id,
            input_args,
        )
        raise ValueError("max_depth out of allowed range")

    # Resolve aliases so e.g. ``process_name`` on the pstree plugin
    # routes to ``image_file_name``. ``canonical_fields`` is the
    # form used for validation and (later) projection; ``input_args``
    # preserves the analyst-supplied form for the audit chain.
    canonical_fields = [_canonicalize_field(plugin_name, f) for f in fields]
    if canonical_fields:
        _validate_fields(
            case_dir_path,
            plugin_name,
            canonical_fields,
            _SUBTREE_TOOL,
            evidence_id,
            input_args,
        )

    ref, parsed = _load_or_reject(
        case_dir_path,
        evidence_id,
        plugin_name,
        _SUBTREE_TOOL,
        input_args,
    )

    root_node = _find_pstree_node(parsed.get("processes", []), root_pid)
    if root_node is None:
        _log_rejection(
            case_dir_path,
            _SUBTREE_TOOL,
            _RejectionReason.ROOT_NOT_FOUND,
            evidence_id,
            input_args,
        )
        raise ValueError("root_pid not found in extraction")

    nodes_visited: list[dict] = []
    deepest_seen = 0

    def visit(node: dict, depth: int) -> None:
        nonlocal deepest_seen
        if depth > deepest_seen:
            deepest_seen = depth
        if len(nodes_visited) < _SUBTREE_NODE_TRUNCATION:
            stripped = {k: v for k, v in node.items() if k != "children"}
            stripped["depth"] = depth
            nodes_visited.append(
                _project(stripped, canonical_fields + ["depth"])
                if canonical_fields
                else stripped
            )
        if depth >= max_depth:
            return
        for child in node.get("children", []) or []:
            if len(nodes_visited) >= _SUBTREE_NODE_TRUNCATION:
                break
            visit(child, depth + 1)

    visit(root_node, 0)
    descendant_count = len(nodes_visited) - 1  # exclude the root itself
    truncated_by_size = (
        len(nodes_visited) >= _SUBTREE_NODE_TRUNCATION
        and _count_descendants(root_node, max_depth) > descendant_count
    )

    audit_line = peek_next_line_number(case_dir_path)

    # Subtree is pstree-only by construction; nodes carry whichever
    # of pstree's untrusted record fields survived the projection
    # (image_file_name, audit, cmd, path). Empty `fields` means no
    # projection — every untrusted field is present in `nodes`.
    result = SubtreeResult(
        extraction=ref,
        audit_line=audit_line,
        root_pid=root_pid,
        root_found=True,
        depth_traversed=deepest_seen,
        descendant_count=descendant_count,
        nodes=nodes_visited,
        truncated=truncated_by_size,
        # Use the canonical field names for the untrusted-field
        # marker so it matches the keys present on the projected
        # ``nodes`` (which carry canonical names).
        untrusted_fields=untrusted_fields_for(plugin_name, canonical_fields),
    )

    append_audit_entry(
        case_dir=case_dir_path,
        tool_name=_SUBTREE_TOOL,
        evidence_id=evidence_id,
        input_args=input_args,
        output=result,
    )
    return result


def _count_duplicate_keys(records: list[dict], key: str) -> int:
    """Count records whose key value has been seen earlier in the
    extraction. Equivalent to "extras beyond first occurrence" —
    `len(records) - len(unique_keys_excluding_None)`.

    Used by `set_difference` to surface pool-tag aliasing in
    Volatility psscan: same EPROCESS structure can be discovered
    twice across pool boundaries, inflating record counts vs unique
    PIDs. The agent uses this to tell "real entity-count delta" from
    "pool noise".

    Records with `key is None` are excluded (kernel-only entries
    don't have a meaningful join key).
    """
    seen: set[Any] = set()
    duplicates = 0
    for r in records:
        k = r.get(key)
        if k is None:
            continue
        if k in seen:
            duplicates += 1
        else:
            seen.add(k)
    return duplicates


def _find_pstree_node(roots: list[dict], target_pid: int) -> dict | None:
    """Depth-first search for a node by PID. Returns the dict in place."""
    for r in roots:
        if r.get("pid") == target_pid:
            return r
        found = _find_pstree_node(r.get("children", []) or [], target_pid)
        if found is not None:
            return found
    return None


def _count_descendants(node: dict, max_depth: int) -> int:
    """Count nodes within max_depth of `node` (excluding the node itself)."""
    total = 0

    def walk(n: dict, depth: int) -> None:
        nonlocal total
        if depth >= max_depth:
            return
        for child in n.get("children", []) or []:
            total += 1
            walk(child, depth + 1)

    walk(node, 0)
    return total


__all__ = [
    "group_by",
    "query_records",
    "set_difference",
    "subtree",
]
