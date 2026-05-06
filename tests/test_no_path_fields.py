"""Architectural-lock test: every MCP tool except `register_evidence` must
take `evidence_id`, never a raw filesystem path.

This is the symbolic-introspection counterpart to the surface-lock tests in
`test_mcp_protocol.py`. The surface-lock tests assert the schema for the
two tools that exist today; this test asserts a property that must hold
for every tool we add tomorrow — without anyone having to remember to
update an allow-list.

Failure modes caught:

    @mcp.tool()
    def vol_foo(image_path: str): ...        # name matches /path|file|.../

    @mcp.tool()
    def vol_bar(mft_file: pathlib.Path): ... # type is pathlib.PurePath subclass

    @mcp.tool()
    def vol_baz(case_dir: str): ...          # name matches /dir/

CLAUDE.md "Ground truth isolation" rule 3 forbids any tool from accepting
arbitrary file paths from the agent: the agent can only name an
`evidence_id` registered through `register_evidence`, and the server
resolves that to a path inside its own sandbox. `register_evidence`
itself is the bootstrap exception — its `filepath` argument is the only
free-form path in the surface, and it has its own confinement defense
(`server/tools/evidence.py`, exercised over the wire by
`test_full_session_call_then_error_then_recovery` in test_mcp_protocol).

We use FastMCP's in-process tool registry (`mcp._tool_manager.list_tools()`)
rather than the wire protocol because we need access to the original
Python type annotations — the JSON-schema shadow alone (`format: "path"`)
would not catch a `case_dir: str` field, only a `case_dir: pathlib.Path`
one.
"""

from __future__ import annotations

import inspect
import re
import typing
from pathlib import PurePath

import pytest

from server.main import mcp


# Tokens that indicate a free-form filesystem path. Lowercased; the
# match is on the whole token (split on underscores, plus the bare
# field name as a fallback for one-word fields like `filepath`).
# Token-level matching avoids false positives where a path token
# would otherwise appear as a substring of an unrelated word — e.g.,
# `set_difference.direction` should not match because `direction`
# happens to contain `dir`.
#
# Catches the intended cases: `image_path` → ["image","path"],
# `mft_file`, `output_dir`, `target_directory`, `image_filename`,
# `case_filepath`, the bare `filepath`. False-positive guard against
# `direction`, `descriptor`, `pidfile_locking_strategy`, etc.
_PATH_TOKENS: frozenset[str] = frozenset(
    {"path", "file", "filename", "filepath", "dir", "directory"}
)


def _is_path_shaped_name(field_name: str) -> bool:
    """Tokenize on underscores; True if any token (or the bare name)
    is in the path-token set."""
    lowered = field_name.lower()
    if lowered in _PATH_TOKENS:
        return True
    tokens = lowered.split("_")
    return any(t in _PATH_TOKENS for t in tokens)


# Kept for the symmetric self-test below — `filepath` is the canonical
# allow-listed name and the test still pins the detector against it.
_PATH_NAME_PATTERN = re.compile(
    r"\b(path|file|filename|filepath|dir|directory)\b", re.IGNORECASE
)

# (tool_name, field_name) pairs that are allowed to look path-shaped.
# Keep this list minimal. Every entry is a load-bearing exception that
# needs its own argument for why the agent is permitted to name a path
# directly. Today: only the registration bootstrap.
ALLOWED_PATH_FIELDS: set[tuple[str, str]] = {
    ("register_evidence", "filepath"),
}


def _is_pathlib_subclass(annotation: object) -> bool:
    """True iff the annotation is a pathlib type (`Path`, `PurePath`,
    `PosixPath`, `WindowsPath`, etc.).

    Catches generic aliases (`list[Path]`, `Path | None`) as
    non-matches; we only flag direct path-typed fields. A future test
    can extend this if we ever start exposing collections of paths."""
    return inspect.isclass(annotation) and issubclass(annotation, PurePath)


def _walk_tool_for_violations(tool) -> list[str]:
    violations: list[str] = []

    # 1) Resolved Python type hints — the authoritative source of types.
    # Use typing.get_type_hints rather than reading param.annotation off
    # inspect.signature, because PEP-563 (`from __future__ import
    # annotations`) leaves raw string forms in the signature;
    # get_type_hints evaluates them in the function's own globals so we
    # see actual class objects (and recurse through `Annotated[...]`).
    try:
        hints = typing.get_type_hints(tool.fn)
    except Exception:  # pragma: no cover — should never fire on our own tools
        hints = {}
    sig = inspect.signature(tool.fn)
    for param_name in sig.parameters:
        if (tool.name, param_name) in ALLOWED_PATH_FIELDS:
            continue
        annotation = hints.get(param_name)
        if _is_pathlib_subclass(annotation):
            violations.append(
                f"{tool.name}.{param_name}: annotated as "
                f"{annotation.__name__} (pathlib type). Use evidence_id "
                "and resolve the path server-side."
            )

    # 2) Generated JSON schema — what the agent actually sees over the
    # wire. Catches name-only violations like `image_path: str` that
    # the type check above does not flag.
    properties = (tool.parameters or {}).get("properties", {}) or {}
    for prop_name, prop_schema in properties.items():
        if (tool.name, prop_name) in ALLOWED_PATH_FIELDS:
            continue
        name_hits = _is_path_shaped_name(prop_name)
        format_hits = (
            isinstance(prop_schema, dict) and prop_schema.get("format") == "path"
        )
        if name_hits or format_hits:
            why = []
            if name_hits:
                why.append("name token-matches a path-shaped name")
            if format_hits:
                why.append('JSON schema "format": "path"')
            violations.append(
                f"{tool.name}.{prop_name}: {' & '.join(why)}. "
                "Use evidence_id and resolve the path server-side. "
                "See CLAUDE.md Ground-truth-isolation rule 3."
            )

    return violations


def test_no_free_form_path_fields_in_mcp_tool_surface():
    """Walk every registered MCP tool and fail the build if any tool other
    than `register_evidence` exposes a free-form filesystem path — by
    field name, by JSON-schema `format`, or by Python type annotation."""
    tools = mcp._tool_manager.list_tools()
    assert tools, "FastMCP tool registry is empty — server import broke"

    all_violations: list[str] = []
    for tool in tools:
        all_violations.extend(_walk_tool_for_violations(tool))

    if all_violations:
        details = "\n  - ".join(all_violations)
        pytest.fail(
            "MCP tool surface exposes free-form path fields. CLAUDE.md "
            "Ground-truth-isolation rule 3 forbids any tool other than "
            "register_evidence from accepting raw paths; the agent must "
            "only name `evidence_id` values that the server resolves to "
            f"a path inside its sandbox.\n  - {details}"
        )


def test_register_evidence_filepath_remains_the_only_exception():
    """Sanity-check the allow-list itself.

    If we ever rename `register_evidence`'s parameter or remove the tool
    entirely, the entry in `ALLOWED_PATH_FIELDS` becomes dead weight and
    silently widens the surface for the test above. Force the conversation
    by failing here so someone has to explicitly re-evaluate."""
    tool = mcp._tool_manager.get_tool("register_evidence")
    assert tool is not None, (
        "register_evidence is not registered. ALLOWED_PATH_FIELDS in this "
        "test is now stale — re-evaluate whether any path field should "
        "still be allowed in the surface."
    )

    properties = (tool.parameters or {}).get("properties", {}) or {}
    assert "filepath" in properties, (
        "register_evidence no longer exposes a `filepath` field. The "
        "(register_evidence, filepath) entry in ALLOWED_PATH_FIELDS is "
        "now stale and must be removed or updated."
    )

    # Symmetric: prove the detector would have flagged `filepath` but
    # for the allow-list — i.e., the test is doing real work, not a no-op.
    assert _is_path_shaped_name("filepath"), (
        "token detector no longer matches `filepath`; the allow-list "
        "cannot be doing what it claims. Re-check _PATH_TOKENS."
    )
    # And that the false-positive guard holds: `direction` (contains
    # the substring `dir` but not as a token) must NOT trigger.
    assert not _is_path_shaped_name("direction"), (
        "token detector flagged `direction` as path-shaped; the "
        "regex-substring bug from the pre-week-5 version has resurfaced."
    )
