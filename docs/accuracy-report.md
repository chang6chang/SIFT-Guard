# SIFT-Guard accuracy report

This document is one of the eight required hackathon submission
deliverables ("Accuracy report with documented failure modes"). It is
seeded ahead of the week-7 measurement work so failure-mode entries
can accumulate as they surface during development.

The week-7 entry will add: the full N-runs-per-config accuracy table
on Rocba (and any second config), median + range numbers, and
per-finding correctness against ground truth.

This document describes failure modes that the *architecture itself*
exhibits — issues caught during development that any future build or
operator should know about, regardless of whether the underlying
analytical correctness is right or wrong.

## Documented failure modes

### #1 — Probe-finding pattern: tier-1/tier-2 returns do not surface their own audit-chain line number

**Surfaced:** 2026-05-06, process_analyst v2 experiment on Rocba (see
`docs/process-analyst-v2-results.md`).

**Symptom:** When an analyst calls `record_finding`, every
`EvidenceRef` it provides must carry an `audit_line` whose value
matches a real line in `case-data/audit/sift-guard-mcp.jsonl` AND
whose `source_tool` matches that line's `tool_name`. The MCP server
audits and rejects mismatches. But tier-1 (`vol_*`) and tier-2
(`query_records`, `group_by`, `set_difference`, `subtree`) tool
returns do not include the audit-chain line number that was written
by their own invocation. The analyst therefore has no programmatic
way to know which `audit_line` value to reference.

**Failure mode in v2:** the analyst spent ~16 of its 80 turns
brute-forcing valid `(audit_line, source_tool)` pairs by submitting
placeholder findings and watching which ones the server accepted vs
audited as `record_finding:rejected_invalid_audit_ref`. Once it found
working pairs, it used them in real findings. This contaminated
`findings.jsonl` with 7 placeholder records (titled `"probe …"`) and
burned roughly $0.30 of the run's $2.61 cost on probing turns.

**Why this matters for accuracy:** every probe finding is a
schema-conformant record committed to the case's findings chain. A
downstream consumer (the week-6 validator, the accuracy benchmark
harness, a human reviewer) sees them as findings unless it filters on
`title` not starting with `"probe"`. They are forensically void —
descriptions are placeholder text — so they will look like
false-positives at validation time.

**Severity:** medium. The architecture's rejection paths held (no
fabrication, no silent contamination of the case), but it shifted the
contamination into the audit-conformant findings chain. The audit
chain itself records the rejections cleanly, so an operator
reconstructing the run can identify the probe-finding pattern by
correlating finding lines with the surrounding rejection lines.

**Fix:** add `audit_line: int` to `ExtractionRef` (returned inside
every tier-1 summary and every tier-2 result) and to the tier-2
result models directly (`QueryRecordsResult`, `GroupByResult`,
`SetDifferenceResult`, `SubtreeResult`). Each tier-1/tier-2 tool
already calls `append_audit_entry` and receives back an `AuditLogEntry`
that carries `line_number`; the value just needs to flow into the
returned model. Mechanical change, ~20 lines per tool.

**Status:** scheduled for the next commit, before `network_analyst`
lands. Logged here so that, if the fix is merged before week-7
accuracy measurements, the accuracy report can later note that this
class of failure was caught early and remediated rather than
appearing in the live numbers. If the fix is not merged before the
next analyst run, the same pattern will recur and accuracy numbers
will reflect it.

**Related architectural failure:** v1's oversized-return deadlock
(see `docs/process-analyst-v1-results.md`). Both #1 and v1's deadlock
are the same class of problem: the analyst needs metadata that the
architecture withholds. The pattern to watch for in future tool
designs is "the agent must produce X but cannot observe Y, where Y
is needed to construct a valid X."

---

(More failure modes will be appended below as they surface during
weeks 6-8.)
