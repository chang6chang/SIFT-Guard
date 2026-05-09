"""Subagent dispatch wrapper for the orchestrator loop.

Spawns `claude -p --agent <name>` as a subprocess and parses the
stream-json output to capture session id, token usage, duration,
stop reason. The CLI's frontmatter-restricted tool surface is what
enforces analyst/validator architectural boundaries — the wrapper
simply hands the agent a structured user prompt and waits for the
final result event.

# Focus-context delivery

The Claude Code CLI does not expose a parameter for arbitrary
subagent context. The fallback per the substrate prompt is a
structured user message:

  evidence_id={uuid}
  case_id={case-string}
  iteration_number={int}
  focus_context={"pids": [7900], "image_names": ["svchost.exe"]}

This is what the orchestrator passes via the prompt positional
argument. The analyst subagent's prompt has a `# Focus context
(optional)` section explaining the V5c-1 semantics: focus biases
attention but does not constrain scope.

# Sequential dispatch (not parallel)

`server/audit.py` and the other chain writers explicitly state
"single-process server: no file lock". Two subagents dispatched
in parallel would each spawn their own MCP-server subprocess and
both would race on the same audit/findings/correlations files,
breaking the hash chain.

Until per-process file locking lands (out of scope for week 6),
this wrapper runs subagents one at a time. The loop's ANALYZE step
dispatches process_analyst, waits, then dispatches network_analyst.
Wall-clock cost: ~16 min process + ~16 min network sequentially
on Rocba's first iteration. The architecture supports parallel
dispatch the moment the substrate gains locking.

# Token accounting

The "result" stream-json event includes a usage block with
input_tokens, cache_creation_input_tokens, cache_read_input_tokens,
output_tokens. We define `tokens_uncached` as input + cache_creation
+ output — everything that wasn't served from cache. The orchestrator
sums these across iterations and triggers R_c termination if the
sum exceeds `TOKEN_BUDGET_UNCACHED`.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    agent: str
    session_id: str | None
    stop_reason: str | None
    num_turns: int
    duration_ms: int
    duration_api_ms: int
    total_cost_usd: float
    input_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int
    output_tokens: int
    tokens_uncached: int
    final_text: str
    raw_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.stop_reason in ("end_turn", "tool_use", "stop_sequence")


def _build_prompt(
    *,
    agent: str,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    focus_context: dict[str, Any] | None = None,
    findings_summary: list[dict[str, Any]] | None = None,
    host_id: str | None = None,
    host_label: str | None = None,
    host_grouped_findings: list[dict[str, Any]] | None = None,
) -> str:
    """Construct the structured user message for the subagent.

    The shape varies by agent role:
      - process_analyst / network_analyst / disk_analyst: evidence_id
        (+ optional focus_context, + optional host context). They
        discover findings independently.
      - validator: evidence_id, case_id, iteration_number,
        findings_summary OR host_grouped_findings. The findings input
        is the list of DRAFT findings to correlate (filtered to
        exclude CONFIRMED). When `host_grouped_findings` is provided
        (run-case mode), the prompt presents one ``=== Findings from
        host: ===`` block per host so the validator can read shared
        indicators across hosts at a glance.

    `host_id` / `host_label` are populated by the multi-evidence
    orchestrator and produce a "You are analyzing evidence from
    host: <label> (<id>)" line at the top of the analyst prompt.
    Single-evidence runs leave them None and emit no host line.
    """
    lines = [
        f"evidence_id: {evidence_id}",
        f"case_id: {case_id}",
        f"iteration_number: {iteration_number}",
    ]
    if host_id is not None:
        lines.append(f"host_id: {host_id}")
    if host_label is not None and host_label != host_id:
        lines.append(f"host_label: {host_label}")
    if focus_context is not None:
        lines.append(f"focus_context: {json.dumps(focus_context)}")
    if host_grouped_findings is not None:
        # Host-grouped block. Each entry is
        # {host_id, host_label, findings: [...]} — formatted for
        # readability rather than re-JSON'd, so the validator's
        # in-prompt scan sees host blocks the way the user spec'd.
        lines.append("findings_by_host:")
        for block in host_grouped_findings:
            host_text = (
                f"  === Findings from host: "
                f"{block.get('host_label', block['host_id'])} "
                f"({block['host_id']}) ==="
            )
            lines.append(host_text)
            lines.append(json.dumps(block.get("findings", []), indent=2))
    elif findings_summary is not None:
        lines.append("findings_summary:")
        lines.append(json.dumps(findings_summary, indent=2))

    role_intros = {
        "process_analyst": ("Analyze the registered Windows memory image for process anomalies."),
        "network_analyst": ("Analyze the registered Windows memory image for network anomalies."),
        "disk_analyst": (
            "Analyze the registered Windows disk image for filesystem, "
            "execution, event-log, and registry anomalies."
        ),
        "validator": (
            "Validate the DRAFT findings below by emitting correlations. "
            "You see only DRAFT-state findings; CONFIRMED findings are out "
            "of scope for this iteration.\n"
            "Before emitting a corroborates or contradicts correlation for "
            "any finding, call rag_query to check for matching ATT&CK "
            "techniques or Sigma detection rules. Cite the audit_line from "
            "the rag_query result in your correlation."
        ),
    }
    intro = role_intros.get(agent, f"Run as {agent}.")
    if host_id is not None and agent != "validator":
        # Multi-evidence (run-case) analyst dispatch surfaces the host
        # context at the top of the prompt — separate from the
        # structured key/value lines the agent parses for tool calls.
        host_text = host_label or host_id
        intro = f"You are analyzing evidence from host: {host_text} ({host_id}).\n" + intro
    if agent == "validator" and host_grouped_findings is not None:
        # The cross-host extension is communicated to the validator
        # at run-time (in-prompt) rather than pinned in
        # validator.md, so the same agent file works for both
        # single-evidence and run-case modes.
        intro = (
            intro + "\n\n"
            "Multi-host case: findings span multiple hosts (see "
            "`findings_by_host` below). When you see two findings "
            "on different hosts that share a load-bearing indicator "
            "(an IP address, a binary hash, a synchronized timestamp, "
            "a named MITRE ATT&CK technique), emit a correlation with "
            '`correlation_type="cross_host"`, list every involved '
            "host_id in `host_ids`, and capture the shared indicator "
            "in `shared_indicator` (e.g. "
            '`{"type": "ip", "value": "10.3.58.42"}`). '
            "Cross-host correlations are independent-source corroborations "
            "and feed the same R3 strong-corroboration promotion path."
        )
    return intro + "\n" + "\n".join(lines)


def _parse_stream_json(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse the subprocess stdout into (events, final_result).

    final_result is the {"type":"result"} event; if absent, returns
    an empty dict and the caller treats the dispatch as failed.
    """
    events: list[dict[str, Any]] = []
    final: dict[str, Any] = {}
    for raw in stdout.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except (ValueError, TypeError):
            logger.debug("non-JSON line in stream-json: %r", stripped[:200])
            continue
        events.append(event)
        if isinstance(event, dict) and event.get("type") == "result":
            final = event
    return events, final


def _extract_final_text(events: list[dict[str, Any]]) -> str:
    """The last assistant message's text content, if any. Best-effort
    — the audit chain + findings.jsonl are the authoritative outputs.
    """
    for event in reversed(events):
        if event.get("type") == "assistant":
            msg = event.get("message", {})
            content = msg.get("content", [])
            if isinstance(content, list):
                texts = [
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                if texts:
                    return "\n".join(texts).strip()
    return ""


def dispatch_subagent(
    agent: str,
    prompt: str,
    *,
    cwd: Path,
    max_budget_usd: float = 5.0,
    timeout_seconds: int = 1800,
) -> DispatchResult:
    """Spawn `claude -p --agent <name>` and capture the run.

    The subagent's frontmatter restricts its tool surface; the parent
    process role here is purely transport — start it, wait for the
    result event, return token + timing metadata.

    Failure modes:
      - Subprocess timeout → DispatchResult with stop_reason=None.
        Loop should treat as a structural failure and STOP.
      - Non-zero exit → same.
      - Missing result event (truncated stream) → same.

    All three propagate as DispatchResult.succeeded == False; the
    caller decides how to react.
    """
    cmd = [
        "claude",
        "-p",
        "--agent",
        agent,
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-mode",
        "bypassPermissions",
        "--max-budget-usd",
        str(max_budget_usd),
        prompt,
    ]
    logger.info("dispatching subagent %s (cwd=%s)", agent, cwd)

    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("subagent %s timed out after %ds", agent, timeout_seconds)
        return DispatchResult(
            agent=agent,
            session_id=None,
            stop_reason=None,
            num_turns=0,
            duration_ms=timeout_seconds * 1000,
            duration_api_ms=0,
            total_cost_usd=0.0,
            input_tokens=0,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
            output_tokens=0,
            tokens_uncached=0,
            final_text="",
            raw_events=[],
        )

    events, final = _parse_stream_json(proc.stdout)
    if not final:
        logger.error(
            "subagent %s emitted no result event (returncode=%s)",
            agent,
            proc.returncode,
        )

    usage = final.get("usage", {}) if final else {}
    input_tok = int(usage.get("input_tokens", 0))
    cc_tok = int(usage.get("cache_creation_input_tokens", 0))
    cr_tok = int(usage.get("cache_read_input_tokens", 0))
    out_tok = int(usage.get("output_tokens", 0))

    return DispatchResult(
        agent=agent,
        session_id=final.get("session_id"),
        stop_reason=final.get("stop_reason"),
        num_turns=int(final.get("num_turns", 0)),
        duration_ms=int(final.get("duration_ms", 0)),
        duration_api_ms=int(final.get("duration_api_ms", 0)),
        total_cost_usd=float(final.get("total_cost_usd", 0.0)),
        input_tokens=input_tok,
        cache_creation_input_tokens=cc_tok,
        cache_read_input_tokens=cr_tok,
        output_tokens=out_tok,
        tokens_uncached=input_tok + cc_tok + out_tok,
        final_text=_extract_final_text(events),
        raw_events=events,
    )


def dispatch_analyst(
    agent: str,
    *,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    cwd: Path,
    focus_context: dict[str, Any] | None = None,
    host_id: str | None = None,
    host_label: str | None = None,
    max_budget_usd: float = 5.0,
    timeout_seconds: int = 1800,
) -> DispatchResult:
    """High-level dispatch for an analyst subagent.

    `host_id` / `host_label` populated by run-case orchestration —
    surface as a "You are analyzing evidence from host:" line at the
    top of the analyst's prompt. Single-evidence runs leave them
    None and the prompt is unchanged.
    """
    prompt = _build_prompt(
        agent=agent,
        evidence_id=evidence_id,
        case_id=case_id,
        iteration_number=iteration_number,
        focus_context=focus_context,
        host_id=host_id,
        host_label=host_label,
    )
    return dispatch_subagent(
        agent,
        prompt,
        cwd=cwd,
        max_budget_usd=max_budget_usd,
        timeout_seconds=timeout_seconds,
    )


def dispatch_validator(
    *,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    findings_summary: list[dict[str, Any]] | None = None,
    host_grouped_findings: list[dict[str, Any]] | None = None,
    cwd: Path,
    max_budget_usd: float = 5.0,
    timeout_seconds: int = 1800,
) -> DispatchResult:
    """High-level dispatch for the validator subagent.

    Either `findings_summary` (single-evidence) OR
    `host_grouped_findings` (run-case) must be set. When the
    host-grouped form is provided, the validator's prompt frames the
    findings as per-host blocks and gains the cross-host correlation
    instructions inline.
    """
    prompt = _build_prompt(
        agent="validator",
        evidence_id=evidence_id,
        case_id=case_id,
        iteration_number=iteration_number,
        findings_summary=findings_summary,
        host_grouped_findings=host_grouped_findings,
    )
    return dispatch_subagent(
        "validator",
        prompt,
        cwd=cwd,
        max_budget_usd=max_budget_usd,
        timeout_seconds=timeout_seconds,
    )


__all__ = [
    "DispatchResult",
    "dispatch_analyst",
    "dispatch_subagent",
    "dispatch_validator",
]
