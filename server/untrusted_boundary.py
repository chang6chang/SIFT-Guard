"""Apply the `<evidence>` quarantine wrap at the MCP return boundary.

Per CLAUDE.md's prompt-injection defense, evidence-derived strings the
agent sees must be wrapped in `<evidence source=... hash=...
untrusted="true">` delimiters. The wrap happens HERE — after the tool
impl has audited the raw output — not at schema-construction time, so
audit-replay can recompute the wrap deterministically from the raw
stored values (see `server.schemas.ProcessRecord`'s docstring for the
original design note).

Two field-naming conventions in `untrusted_fields`:

  - a plain name (``image_file_name``) targets string values under
    that key inside the result's row dicts (``records`` /
    ``returned_records`` / ``nodes``);
  - a synthetic ``<attr>_keys`` name (``top_image_names_keys``,
    ``groups_keys``) targets the first element of each ``(key,
    count)`` tuple in the model attribute ``<attr>``.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

from server.schemas import UntrustedString

_ROW_LIST_FIELDS = ("records", "returned_records", "nodes")
_KEYS_SUFFIX = "_keys"

_ResultT = TypeVar("_ResultT", bound=BaseModel)


def _wrap(value: str, *, source: str, evidence_hash: str) -> str:
    return UntrustedString(
        source=source, evidence_hash=evidence_hash, content=value
    ).to_evidence_block()


def _source_extraction(result: BaseModel):
    """The ExtractionRef whose plugin/hash provenance the wrap cites.

    Single-extraction results carry ``extraction``; SetDifferenceResult
    carries a pair — the records are pulled from plugin_a for
    ``a_minus_b`` / ``symmetric`` and plugin_b for ``b_minus_a`` (same
    side-selection rule the tool uses for `untrusted_fields` itself).
    """
    extraction = getattr(result, "extraction", None)
    if extraction is not None:
        return extraction
    if getattr(result, "direction", None) == "b_minus_a":
        return getattr(result, "extraction_b", None)
    return getattr(result, "extraction_a", None)


def wrap_untrusted_result(result: _ResultT) -> _ResultT:
    """Return a copy of `result` with every untrusted string wrapped.

    Identity (same object) when there is nothing to wrap — models with
    empty `untrusted_fields`, no `untrusted_fields` at all (e.g.
    EvidenceRecord, DraftFinding), or no resolvable extraction ref.
    Never mutates the input.
    """
    untrusted = getattr(result, "untrusted_fields", None)
    if not untrusted:
        return result
    extraction = _source_extraction(result)
    if extraction is None:
        return result
    plugin = str(extraction.plugin_name)
    evidence_hash = extraction.extraction_sha256

    plain = [f for f in untrusted if not f.endswith(_KEYS_SUFFIX)]
    update: dict = {}

    if plain:
        for row_field in _ROW_LIST_FIELDS:
            rows = getattr(result, row_field, None)
            if rows is None:
                continue
            update[row_field] = [
                {
                    k: _wrap(v, source=f"{plugin}.{k}", evidence_hash=evidence_hash)
                    if k in plain and isinstance(v, str)
                    else v
                    for k, v in row.items()
                }
                for row in rows
            ]

    for name in untrusted:
        if not name.endswith(_KEYS_SUFFIX):
            continue
        attr = name[: -len(_KEYS_SUFFIX)]
        tuples = getattr(result, attr, None)
        if tuples is None:
            continue
        update[attr] = [
            (
                _wrap(key, source=f"{plugin}.{attr}", evidence_hash=evidence_hash)
                if isinstance(key, str)
                else key,
                count,
            )
            for key, count in tuples
        ]

    if not update:
        return result
    return result.model_copy(update=update)


__all__ = ["wrap_untrusted_result"]
