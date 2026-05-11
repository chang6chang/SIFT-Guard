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

# Parallel dispatch (fcntl-protected chain writers)

The five hash-chained writers (audit, findings, correlations,
extractions, iterations) all serialize their read-modify-write
phase via ``server._chain_lock.chain_write_lock``, an
``fcntl.flock``-backed sidecar mutex. This lets the orchestrator's
ANALYZE step submit every analyst job to a ``ThreadPoolExecutor``;
each thread spawns its own ``claude -p --agent <name>`` subprocess
with its own MCP-server child, and those concurrent MCP servers
contend for the chain locks rather than corrupting the chain.

Expected ANALYZE wall-clock for the SRL-2015 4-host case
(12 jobs at ~5-15 min each):

  - Sequential:        12 jobs × ~10 min = ~120 min
  - Parallel (this):   max single-job wall-clock ≈ 15-20 min

CORRELATE / PROMOTE / PLAN / WRITE stay sequential — the validator
needs the full DRAFT set before correlating, promotion is a single
DAG pass, and the iteration record is one entry per loop turn.

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
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# MCP-config path resolution. Claude Code subagents discover MCP
# servers from ``.mcp.json`` in the launch cwd. The orchestrator's
# default cwd is ``case_dir.parent`` (e.g. ``~/results/``), which
# never contains the SIFT-Guard config — so without an explicit
# ``--mcp-config`` flag the subagent has no MCP tools and silently
# falls back to the default Bash/Read/Write surface, improvising
# instead of calling ``record_finding``. We resolve the config
# location explicitly:
#
#   1. ``SIFT_GUARD_MCP_CONFIG`` env var (operator override).
#   2. ``$REPO_ROOT/.mcp.json`` (works when running from a checkout).
#   3. ``/opt/sift-guard/.mcp.json`` (the installed location written
#      by setup-sift-guard.sh).
#
# ``resolve_mcp_config_path`` returns the first hit or None;
# ``dispatch_subagent`` includes the flag iff a path is found.
_DEFAULT_INSTALL_MCP_CONFIG = Path("/opt/sift-guard/.mcp.json")
_REPO_ROOT_MCP_CONFIG = Path(__file__).resolve().parent.parent / ".mcp.json"


def resolve_mcp_config_path() -> Path | None:
    """Return the path to the MCP-server config, or None when no
    candidate exists. See module-level comment for resolution order."""
    env = os.environ.get("SIFT_GUARD_MCP_CONFIG")
    if env:
        candidate = Path(env)
        if candidate.exists():
            return candidate
        logger.warning(
            "SIFT_GUARD_MCP_CONFIG=%s does not exist; falling through to defaults",
            env,
        )
    if _REPO_ROOT_MCP_CONFIG.exists():
        return _REPO_ROOT_MCP_CONFIG
    if _DEFAULT_INSTALL_MCP_CONFIG.exists():
        return _DEFAULT_INSTALL_MCP_CONFIG
    return None


class MCPServerNotAttachedError(RuntimeError):
    """Raised when a subagent's stream-json shows the sift-guard MCP
    server did NOT attach. The agent would still run — with the
    default Bash/Read/Write surface — but it would never see
    ``record_finding`` / ``vol_pslist`` / etc. Failing the dispatch
    is the architectural guardrail (failure-closed, per CLAUDE.md
    "Architectural guardrails > prompt guardrails")."""


def _extract_mcp_server_status(events: list[dict[str, Any]]) -> dict[str, str]:
    """Walk the stream-json events and return ``{server_name: status}``.

    Claude Code emits a ``system`` / ``init`` event near the top of
    every session with an ``mcp_servers`` field listing each
    configured server's connection status. We tolerate a few
    historical shapes (``mcpServers`` camelCase, top-level
    ``servers`` list with ``{name, status}`` dicts) so a Claude
    Code version bump doesn't silently break the check.
    """
    for event in events:
        if event.get("type") not in ("system", "init", "system_init"):
            continue
        # Shape 1: {"type": "system", "mcp_servers": [{"name": "...", "status": "connected"}]}
        for key in ("mcp_servers", "mcpServers"):
            servers = event.get(key)
            if isinstance(servers, list):
                return {
                    s["name"]: s.get("status", "unknown")
                    for s in servers
                    if isinstance(s, dict) and "name" in s
                }
            if isinstance(servers, dict):
                return {
                    name: (info.get("status", "unknown") if isinstance(info, dict) else "unknown")
                    for name, info in servers.items()
                }
        # Shape 2: nested under "subtype" payload (rarer).
        nested = event.get("subtype")
        if isinstance(nested, dict):
            for key in ("mcp_servers", "mcpServers"):
                servers = nested.get(key)
                if isinstance(servers, list):
                    return {
                        s["name"]: s.get("status", "unknown")
                        for s in servers
                        if isinstance(s, dict) and "name" in s
                    }
    return {}


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
    # MCP-server attach status as reported by the subagent's
    # stream-json ``system`` init event. Empty dict means the event
    # was missing or unparseable (treated as not-attached).
    mcp_server_status: dict[str, str] = field(default_factory=dict)
    raw_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def sift_guard_mcp_attached(self) -> bool:
        """True iff the subagent reported the sift-guard MCP server as
        connected. False when the init event is missing the entry or
        when its status is anything other than ``connected``."""
        return self.mcp_server_status.get("sift-guard") == "connected"

    @property
    def succeeded(self) -> bool:
        # Fail-closed on MCP-attach: a run with no sift-guard MCP is
        # not a successful analyst dispatch even when stop_reason
        # says end_turn. The 2026-05-12 SRL-2015 incident burned a
        # full multi-hour run on eight subagents whose MCP attach
        # was missing; surfacing the failure here is the architectural
        # guardrail that prevents a repeat.
        if not self.sift_guard_mcp_attached:
            return False
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
    cmd: list[str] = [
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
    ]
    # Pass --mcp-config explicitly so the subagent loads the sift-guard
    # MCP server regardless of cwd. Without this, the subagent's
    # frontmatter ``tools:`` allow-list refers to names that don't
    # exist (the MCP server isn't loaded), the allow-list silently
    # fails open, and the agent improvises with Bash/Write — writing
    # findings to .md files instead of calling record_finding.
    mcp_config = resolve_mcp_config_path()
    if mcp_config is not None:
        cmd.extend(["--mcp-config", str(mcp_config)])
    else:
        logger.warning(
            "no .mcp.json located; subagent %s will start without sift-guard MCP "
            "tools and will be flagged as not-attached after dispatch",
            agent,
        )
    cmd.append(prompt)
    logger.info(
        "dispatching subagent %s (cwd=%s, mcp_config=%s)",
        agent,
        cwd,
        mcp_config,
    )

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

    # Architectural guardrail: confirm the sift-guard MCP server
    # actually attached. Without it the subagent has no
    # `record_finding`/`vol_*`/`disk_*` tools and the run silently
    # produces zero findings (the 2026-05-12 SRL-2015 incident).
    # We fail-closed: the dispatch is marked unsucceeded so the
    # orchestrator can warn and stop rather than burn tokens on
    # eight subagents that won't write anything.
    server_status = _extract_mcp_server_status(events)
    sift_status = server_status.get("sift-guard")
    if sift_status != "connected":
        logger.error(
            "subagent %s started without sift-guard MCP attached "
            "(mcp_servers=%s); marking dispatch unsucceeded so "
            "findings-less runs surface immediately",
            agent,
            server_status or "<no init event>",
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
        mcp_server_status=server_status,
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
