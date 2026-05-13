"""Post-run report generator.

Reads the case chains (findings.jsonl, correlations.jsonl,
iterations.jsonl, audit/sift-guard-mcp.jsonl) and emits two
artifacts:

  - ``<case_dir>/report.md``   — human-readable summary
  - ``<case_dir>/report.json`` — programmatic-consumption summary

The chains themselves stay authoritative; the report is a
rendering. Re-running this module against the same case directory
is idempotent and read-only against the chains.

Sections of report.md:
  1. Executive summary — total findings, counts by confidence,
     iteration count, termination reason.
  2. Per-host findings — one block per host, table sorted by
     confidence (HIGH first), then severity.
  3. Cross-host correlations — only present when at least one
     ``cross_host`` correlation exists in the chain.
  4. MITRE ATT&CK techniques observed — derived from rag_query
     audit entries (``technique_id`` field on RagQueryResult).
  5. Timeline of key events — finding ``created_at`` timestamps
     bucketed by iteration.
  6. Iteration summary — one row per iteration with new findings,
     correlations, promotions, termination flags.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from server.schemas import (
    CorrelationChainEntry,
    CrossHostCorrelation,
    DraftFinding,
    FindingChainEntry,
    FindingUpdate,
)


# ATT&CK technique IDs look like ``T1234`` or ``T1234.001``. Captured
# from rag_query audit lines; the validator's hypothesis text often
# references these inline.
_ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class FindingSummary:
    finding_id: str
    host_id: str | None
    analyst: str
    title: str
    category: str
    severity: str
    confidence: str
    state: str
    created_at: str
    description: str
    hypothesis: str | None
    evidence_ref_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "host_id": self.host_id,
            "analyst": self.analyst,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "state": self.state,
            "created_at": self.created_at,
            "evidence_ref_count": self.evidence_ref_count,
        }


@dataclass
class CrossHostSummary:
    correlation_id: str
    target_finding_ids: list[str]
    host_ids: list[str]
    indicator_kind: str
    indicator_value: str
    strength: str
    hypothesis: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class IterationSummary:
    iteration_number: int
    analysts_dispatched: list[str]
    new_findings: int
    new_correlations: int
    promotions_applied: int
    promotions_total: int
    tokens_uncached: int
    termination_decision: str
    termination_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class AttackTechniqueSummary:
    technique_id: str
    occurrences: int

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ReportSummary:
    case_id: str
    case_dir: str
    confidence_counts: dict[str, int]
    state_counts: dict[str, int]
    findings_by_host: dict[str, list[FindingSummary]]
    cross_host_correlations: list[CrossHostSummary]
    attack_techniques: list[AttackTechniqueSummary]
    iterations: list[IterationSummary]
    termination_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_dir": self.case_dir,
            "confidence_counts": self.confidence_counts,
            "state_counts": self.state_counts,
            "findings_by_host": {
                host_id: [f.to_dict() for f in findings]
                for host_id, findings in self.findings_by_host.items()
            },
            "cross_host_correlations": [c.to_dict() for c in self.cross_host_correlations],
            "attack_techniques": [t.to_dict() for t in self.attack_techniques],
            "iterations": [it.to_dict() for it in self.iterations],
            "termination_reason": self.termination_reason,
        }


# Confidence ranking for sort-by-importance. DISPUTED is surfaced
# alongside the operational confidence levels so the report does not
# bury the unresolved findings at the bottom.
_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "DISPUTED": 3}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                out.append(json.loads(stripped))
            except json.JSONDecodeError:
                continue
    return out


def _read_findings_chain(case_dir: Path) -> list[FindingChainEntry]:
    entries: list[FindingChainEntry] = []
    for raw in _read_jsonl(case_dir / "findings.jsonl"):
        try:
            entries.append(FindingChainEntry.model_validate(raw))
        except Exception:
            continue
    return entries


def _read_correlations_chain(case_dir: Path) -> list[CorrelationChainEntry]:
    entries: list[CorrelationChainEntry] = []
    for raw in _read_jsonl(case_dir / "correlations.jsonl"):
        try:
            entries.append(CorrelationChainEntry.model_validate(raw))
        except Exception:
            continue
    return entries


def _latest_state_per_finding(
    chain: Iterable[FindingChainEntry],
) -> dict[str, tuple[str, str]]:
    """Last-write-wins per finding_id, returning (state, confidence)."""
    out: dict[str, tuple[str, str]] = {}
    for entry in chain:
        f = entry.finding
        if isinstance(f, DraftFinding):
            out[f.finding_id] = (f.state, f.confidence)
        elif isinstance(f, FindingUpdate):
            out[f.finding_id] = (f.new_state, f.new_confidence)
    return out


def _draft_records(chain: Iterable[FindingChainEntry]) -> dict[str, DraftFinding]:
    drafts: dict[str, DraftFinding] = {}
    for entry in chain:
        f = entry.finding
        if isinstance(f, DraftFinding) and f.finding_id not in drafts:
            drafts[f.finding_id] = f
    return drafts


def _build_finding_summaries(
    case_dir: Path,
) -> dict[str, list[FindingSummary]]:
    """Per-host bucketed findings, sorted within each bucket."""
    chain = _read_findings_chain(case_dir)
    drafts = _draft_records(chain)
    latest = _latest_state_per_finding(chain)

    by_host: dict[str, list[FindingSummary]] = {}
    for fid, draft in drafts.items():
        state, confidence = latest.get(fid, (draft.state, draft.confidence))
        host_key = draft.host_id or "_unattributed"
        summary = FindingSummary(
            finding_id=fid,
            host_id=draft.host_id,
            analyst=draft.analyst,
            title=draft.title,
            category=draft.category,
            severity=draft.severity,
            confidence=confidence,
            state=state,
            created_at=draft.created_at.isoformat(),
            description=draft.description,
            hypothesis=draft.hypothesis,
            evidence_ref_count=len(draft.evidence_refs),
        )
        by_host.setdefault(host_key, []).append(summary)

    for host_key, findings in by_host.items():
        findings.sort(
            key=lambda f: (
                _CONFIDENCE_RANK.get(f.confidence, 99),
                _SEVERITY_RANK.get(f.severity, 99),
                f.created_at,
            )
        )
    return by_host


def _build_cross_host_correlations(case_dir: Path) -> list[CrossHostSummary]:
    out: list[CrossHostSummary] = []
    for entry in _read_correlations_chain(case_dir):
        c = entry.correlation
        if not isinstance(c, CrossHostCorrelation):
            continue
        # `shared_indicator` is a free dict on the schema. Common
        # validator outputs use {"kind": "ipv4", "value": "1.2.3.4"}
        # or analogues for hash / timestamp / ttp. Best-effort
        # extraction with safe fallbacks; the JSON report carries
        # the full dict for callers that need richer detail.
        kind = (
            c.shared_indicator.get("kind")
            or c.shared_indicator.get("type")
            or "indicator"
        )
        value = c.shared_indicator.get("value") or c.shared_indicator.get("ip") or ""
        if not value and c.shared_indicator:
            # Fall back to a compact dict rendering when neither
            # canonical key is present.
            value = json.dumps(c.shared_indicator, sort_keys=True)
        out.append(
            CrossHostSummary(
                correlation_id=c.correlation_id,
                target_finding_ids=list(c.target_finding_ids),
                host_ids=list(c.host_ids),
                indicator_kind=str(kind),
                indicator_value=str(value),
                strength=str(c.strength),
                hypothesis=c.hypothesis,
            )
        )
    return out


def _build_attack_techniques(case_dir: Path) -> list[AttackTechniqueSummary]:
    """Extract MITRE ATT&CK technique IDs cited via rag_query.

    Looks at every audit line for ``rag_query`` (or its sibling
    suffixes, e.g. ``rag_query:cached``) and counts the
    ``technique_id`` field on the structured output. Falls back to
    regex extraction over the input query string when the structured
    output is missing — handles the legacy audit shape and the
    semantic-query case where the matching technique IDs only appear
    in the hits list.
    """
    counts: dict[str, int] = {}
    audit_path = case_dir / "audit" / "sift-guard-mcp.jsonl"
    for raw in _read_jsonl(audit_path):
        tool_name = raw.get("tool_name", "")
        if not tool_name.startswith("rag_query"):
            continue
        # 1) Structured output may carry the matching hits.
        output = raw.get("output")
        if isinstance(output, dict):
            for hit in output.get("hits", []) or []:
                if isinstance(hit, dict):
                    tid = hit.get("technique_id")
                    if isinstance(tid, str):
                        counts[tid] = counts.get(tid, 0) + 1
            qv = output.get("query_value")
            if isinstance(qv, str):
                for m in _ATTACK_ID_RE.findall(qv):
                    counts[m] = counts.get(m, 0) + 1
        # 2) Audit logs only persist hashes for output by default;
        # input_args still has the query text.
        input_args = raw.get("input_args")
        if isinstance(input_args, dict):
            for v in input_args.values():
                if isinstance(v, str):
                    for m in _ATTACK_ID_RE.findall(v):
                        counts[m] = counts.get(m, 0) + 1

    return [
        AttackTechniqueSummary(technique_id=tid, occurrences=count)
        for tid, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _build_iterations(case_dir: Path) -> tuple[list[IterationSummary], str | None]:
    rows: list[IterationSummary] = []
    last_termination_reason: str | None = None
    for raw in _read_jsonl(case_dir / "iterations.jsonl"):
        # Iteration entries carry the IterationPayload under the
        # ``iteration`` key; the rest is chain bookkeeping. Fail-soft
        # on shape drift — treat unparseable entries as already-warned.
        payload = raw.get("iteration") or raw
        check = payload.get("termination_check") or {}
        promotions = payload.get("promotions_made") or []
        applied = sum(1 for p in promotions if p.get("applied"))
        reasons = [
            name
            for name in (
                "R_a_zero_unresolved",
                "R_b_disputed_set_unchanged",
                "R_c_token_budget_exceeded",
                "max_iterations_reached",
            )
            if check.get(name)
        ]
        rows.append(
            IterationSummary(
                iteration_number=int(payload.get("iteration_number", 0)),
                analysts_dispatched=list(payload.get("analysts_dispatched") or []),
                new_findings=len(payload.get("analyst_findings_added") or []),
                new_correlations=len(payload.get("validator_correlations_added") or []),
                promotions_applied=applied,
                promotions_total=len(promotions),
                tokens_uncached=int(payload.get("tokens_used_uncached") or 0),
                termination_decision=str(check.get("decision", "")),
                termination_reasons=reasons,
            )
        )
        if reasons:
            last_termination_reason = reasons[0]
    return rows, last_termination_reason


def build_summary(case_dir: Path) -> ReportSummary:
    """Read the case chains and assemble a `ReportSummary`."""
    case_dir = Path(case_dir).resolve()
    findings_by_host = _build_finding_summaries(case_dir)
    confidence_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for findings in findings_by_host.values():
        for f in findings:
            confidence_counts[f.confidence] = confidence_counts.get(f.confidence, 0) + 1
            state_counts[f.state] = state_counts.get(f.state, 0) + 1
    cross_host = _build_cross_host_correlations(case_dir)
    techniques = _build_attack_techniques(case_dir)
    iterations, termination_reason = _build_iterations(case_dir)

    case_id = case_dir.name
    case_yaml = case_dir / "CASE.yaml"
    if case_yaml.exists():
        try:
            import yaml as _yaml  # noqa: WPS433 — local optional import

            doc = _yaml.safe_load(case_yaml.read_text()) or {}
            case_id = str(doc.get("case_id") or case_id)
        except Exception:
            pass

    return ReportSummary(
        case_id=case_id,
        case_dir=str(case_dir),
        confidence_counts=confidence_counts,
        state_counts=state_counts,
        findings_by_host=findings_by_host,
        cross_host_correlations=cross_host,
        attack_techniques=techniques,
        iterations=iterations,
        termination_reason=termination_reason,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _render_executive_summary(summary: ReportSummary) -> list[str]:
    total = sum(summary.confidence_counts.values())
    host_count = len(summary.findings_by_host)
    high = summary.confidence_counts.get("HIGH", 0)
    medium = summary.confidence_counts.get("MEDIUM", 0)
    low = summary.confidence_counts.get("LOW", 0)
    disputed = summary.confidence_counts.get("DISPUTED", 0)
    confirmed = summary.state_counts.get("CONFIRMED", 0)
    out = [
        "## Executive summary",
        "",
        f"- Case: `{summary.case_id}`",
        f"- Hosts analyzed: {host_count}",
        f"- Findings: {total} total — {high} HIGH, {medium} MEDIUM, {low} LOW, {disputed} DISPUTED",
        f"- Confirmed (post-promotion): {confirmed}",
        f"- Iterations run: {len(summary.iterations)}",
    ]
    if summary.termination_reason:
        out.append(f"- Termination reason: `{summary.termination_reason}`")
    out.append("")
    return out


def _render_findings_section(summary: ReportSummary) -> list[str]:
    if not summary.findings_by_host:
        return ["## Findings", "", "_No findings recorded._", ""]
    lines = ["## Findings"]
    for host_key in sorted(summary.findings_by_host):
        findings = summary.findings_by_host[host_key]
        label = host_key if host_key != "_unattributed" else "(no host_id)"
        lines.append("")
        lines.append(f"### Host: {label}")
        lines.append("")
        lines.append("| Confidence | Severity | Category | Title | Analyst | State |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            title = f.title.replace("|", "\\|")
            category = f.category.replace("|", "\\|")
            lines.append(
                f"| {f.confidence} | {f.severity} | {category} | {title} | "
                f"{f.analyst} | {f.state} |"
            )
        lines.append("")
        for f in findings:
            lines.append(f"#### `{f.finding_id[:8]}` — {f.title}")
            lines.append("")
            lines.append(f"_{f.confidence} · {f.severity} · {f.category} · {f.analyst}_")
            lines.append("")
            lines.append(f.description)
            lines.append("")
            if f.hypothesis:
                lines.append("**Hypothesis:** " + f.hypothesis)
                lines.append("")
    return lines


def _render_cross_host(summary: ReportSummary) -> list[str]:
    if not summary.cross_host_correlations:
        return []
    lines = ["## Cross-host correlations", ""]
    lines.append("| Indicator | Hosts | Findings | Strength |")
    lines.append("|---|---|---|---|")
    for c in summary.cross_host_correlations:
        value = c.indicator_value.replace("|", "\\|")
        hosts = ", ".join(c.host_ids).replace("|", "\\|")
        findings = ", ".join(f"`{fid[:8]}`" for fid in c.target_finding_ids)
        lines.append(
            f"| {c.indicator_kind} `{value}` | {hosts} | {findings} | {c.strength} |"
        )
    lines.append("")
    return lines


def _render_attack(summary: ReportSummary) -> list[str]:
    if not summary.attack_techniques:
        return []
    lines = ["## MITRE ATT&CK techniques observed", ""]
    lines.append("| Technique | Citations |")
    lines.append("|---|---|")
    for t in summary.attack_techniques:
        lines.append(f"| `{t.technique_id}` | {t.occurrences} |")
    lines.append("")
    return lines


def _render_timeline(summary: ReportSummary) -> list[str]:
    timeline: list[tuple[str, str, str]] = []
    for findings in summary.findings_by_host.values():
        for f in findings:
            timeline.append((f.created_at, f.host_id or "_unattributed", f.title))
    if not timeline:
        return []
    timeline.sort(key=lambda row: row[0])
    lines = ["## Timeline of key events", ""]
    lines.append("| Timestamp (UTC) | Host | Finding |")
    lines.append("|---|---|---|")
    for ts, host, title in timeline:
        title_safe = title.replace("|", "\\|")
        lines.append(f"| {ts} | {host} | {title_safe} |")
    lines.append("")
    return lines


def _render_iterations(summary: ReportSummary) -> list[str]:
    if not summary.iterations:
        return []
    lines = ["## Iteration summary", ""]
    lines.append(
        "| # | Analysts | New findings | New correlations | Promotions | Tokens | Termination |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for it in summary.iterations:
        analysts = ", ".join(it.analysts_dispatched) if it.analysts_dispatched else "—"
        promo = f"{it.promotions_applied}/{it.promotions_total}"
        flags = ", ".join(it.termination_reasons) or it.termination_decision
        lines.append(
            f"| {it.iteration_number} | {analysts} | {it.new_findings} | "
            f"{it.new_correlations} | {promo} | {it.tokens_uncached:,} | {flags} |"
        )
    lines.append("")
    return lines


def render_markdown(summary: ReportSummary) -> str:
    lines: list[str] = [
        f"# SIFT-Guard report — `{summary.case_id}`",
        "",
    ]
    lines.extend(_render_executive_summary(summary))
    lines.extend(_render_findings_section(summary))
    lines.extend(_render_cross_host(summary))
    lines.extend(_render_attack(summary))
    lines.extend(_render_timeline(summary))
    lines.extend(_render_iterations(summary))
    return "\n".join(lines).rstrip() + "\n"


def render_json(summary: ReportSummary) -> str:
    return json.dumps(summary.to_dict(), indent=2, sort_keys=False) + "\n"


@dataclass
class WrittenReports:
    markdown_path: Path | None = None
    json_path: Path | None = None
    skipped: list[str] = field(default_factory=list)


def write_reports(
    case_dir: Path,
    *,
    output_dir: Path | None = None,
    formats: Iterable[str] = ("markdown", "json"),
) -> WrittenReports:
    """Build the summary and write the requested formats.

    `output_dir` defaults to ``case_dir`` so reports land next to the
    chains. Pass a different directory (e.g. ``./results``) to keep
    the case directory pristine.
    """
    case_dir = Path(case_dir).resolve()
    if output_dir is None:
        output_dir = case_dir
    else:
        output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = build_summary(case_dir)
    written = WrittenReports()
    fmts = {f.lower() for f in formats}

    if "markdown" in fmts or "md" in fmts:
        md_path = output_dir / "report.md"
        md_path.write_text(render_markdown(summary), encoding="utf-8")
        written.markdown_path = md_path

    if "json" in fmts:
        json_path = output_dir / "report.json"
        json_path.write_text(render_json(summary), encoding="utf-8")
        written.json_path = json_path

    for fmt in fmts:
        if fmt not in {"markdown", "md", "json"}:
            written.skipped.append(fmt)

    return written


__all__ = [
    "AttackTechniqueSummary",
    "CrossHostSummary",
    "FindingSummary",
    "IterationSummary",
    "ReportSummary",
    "WrittenReports",
    "build_summary",
    "render_json",
    "render_markdown",
    "write_reports",
]
